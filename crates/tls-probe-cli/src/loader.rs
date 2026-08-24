use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use aya::maps::RingBuf;
use aya::programs::{tc, KProbe, SchedClassifier, TcAttachType};
use aya::Ebpf;
use tls_probe_common::{RawTlsCapture, RAW_CAPTURE_HEADER_SIZE};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::error::ProbeError;

// --- Filesystem paths (Linux procfs/sysfs) ---

const SYSFS_NET_DIR: &str = "/sys/class/net";
const PROC_ROUTE: &str = "/proc/net/route";
const PROC_IF_INET6: &str = "/proc/net/if_inet6";

// --- Interface detection constants ---

const LOOPBACK_IFACE: &str = "lo";
const DEFAULT_ROUTE_DEST: &str = "00000000";

/// Operstate values considered "active" for TC attach.
/// Bridge interfaces report "unknown" when up; physical NICs report "up".
const ACTIVE_OPERSTATES: &[&str] = &["up", "unknown"];

// --- IPv4/IPv6 link-local detection ---

/// 169.254.0.0/16 in little-endian hex (as it appears in /proc/net/route).
const IPV4_LINK_LOCAL_PREFIX: u32 = 0x0000_FEA9;
const IPV4_LINK_LOCAL_MASK: u32 = 0x0000_FFFF;

/// IPv6 scope value for link-local addresses in /proc/net/if_inet6.
const IPV6_SCOPE_LINK_LOCAL: u32 = 0x20;

// --- eBPF program/map identifiers (must match names in the eBPF object) ---

#[derive(Debug, Clone, Copy)]
enum EbpfProgram {
    Ingress,
    Egress,
}

impl EbpfProgram {
    const fn name(self) -> &'static str {
        match self {
            Self::Ingress => "tls_ingress",
            Self::Egress => "tls_egress",
        }
    }
}

const TLS_EVENTS_MAP_NAME: &str = "TLS_EVENTS";
const RINGBUF_DROPS_MAP_NAME: &str = "RINGBUF_DROPS";
const CONN_MAP_NAME: &str = "CONN_MAP";

/// Connect-side kprobe entry points (stash sock pointer + process info).
const CONNECT_KPROBES: [&str; 2] = ["tcp_v4_connect", "tcp_v6_connect"];

/// Connect-side kretprobe names in the eBPF object. Each reads the now-populated
/// 4-tuple and moves the stash into CONN_MAP. The second element is the kernel
/// function to attach to.
const CONNECT_KRETPROBES: [(&str, &str); 2] = [
    ("tcp_v4_connect_ret", "tcp_v4_connect"),
    ("tcp_v6_connect_ret", "tcp_v6_connect"),
];

/// Name of the process-attribution kretprobe for inbound (accept-side) attribution.
const ACCEPT_KRETPROBE: &str = "inet_csk_accept";

const EVENT_LOOP_POLL_MS: u64 = 100;

/// Resolve the `--interface` argument into a list of concrete interface names.
///
/// Modes:
///   - `"auto"` — single interface carrying the default IPv4 route
///   - `"all"`  — all interfaces with a routable (non-link-local) IP that are operationally up
///   - anything else — comma-separated explicit names
pub fn detect_interfaces(mode: &str) -> Result<Vec<String>, ProbeError> {
    match mode {
        "auto" => detect_default_interface().map(|iface| vec![iface]),
        "all" => detect_routable_interfaces(),
        explicit => Ok(explicit.split(',').map(|s| s.trim().to_string()).collect()),
    }
}

/// Returns the interface carrying the IPv4 default route (destination 0.0.0.0).
fn detect_default_interface() -> Result<String, ProbeError> {
    let route = fs::read_to_string(PROC_ROUTE)
        .map_err(|e| ProbeError::LoadError(format!("Failed to read route table: {}", e)))?;

    for line in route.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 2 && fields[1] == DEFAULT_ROUTE_DEST {
            return Ok(fields[0].to_string());
        }
    }

    Err(ProbeError::LoadError(
        "No default route found. Use --interface to specify explicitly.".to_string(),
    ))
}

/// Discovers interfaces suitable for TLS capture by checking two properties:
///   1. Operationally UP (operstate is "up" or "unknown" — bridge interfaces report "unknown" when active)
///   2. Has at least one routable IP address (IPv4 or IPv6, excluding link-local)
///
/// This approach is platform-agnostic: works on bridge interfaces, bare metal (eth0),
/// cloud VMs (ens5), containers (eth0), without hardcoding any interface names.
fn detect_routable_interfaces() -> Result<Vec<String>, ProbeError> {
    let entries = fs::read_dir(SYSFS_NET_DIR)
        .map_err(|e| ProbeError::LoadError(format!("Failed to read {}: {}", SYSFS_NET_DIR, e)))?;

    let candidates: Vec<String> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|name| name != LOOPBACK_IFACE)
        .filter(|name| is_operationally_up(name))
        .filter(|name| has_routable_address(name))
        .collect();

    if candidates.is_empty() {
        return Err(ProbeError::LoadError(
            "No routable interfaces found. Use --interface to specify explicitly.".to_string(),
        ));
    }

    for iface in &candidates {
        debug!("Detected routable interface: {}", iface);
    }

    Ok(candidates)
}

/// Checks /sys/class/net/<iface>/operstate against ACTIVE_OPERSTATES.
fn is_operationally_up(iface: &str) -> bool {
    let path = format!("{}/{}/operstate", SYSFS_NET_DIR, iface);
    fs::read_to_string(&path)
        .map(|s| ACTIVE_OPERSTATES.contains(&s.trim()))
        .unwrap_or(false)
}

/// Checks whether an interface has at least one routable (non-link-local) IP address.
/// Parses /proc/net/if_inet6 for IPv6 and /sys/class/net/<iface>/address existence
/// combined with ip-address assignment from /proc/net/fib_trie for IPv4.
fn has_routable_address(iface: &str) -> bool {
    has_routable_ipv4(iface) || has_routable_ipv6(iface)
}

/// Checks /proc/net/route for non-link-local routing entries belonging to this interface.
/// An interface with at least one non-169.254.x.x route is considered routable for IPv4.
fn has_routable_ipv4(iface: &str) -> bool {
    if let Ok(route) = fs::read_to_string(PROC_ROUTE) {
        return route.lines().skip(1).any(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.is_empty() {
                return false;
            }
            if fields[0] != iface {
                return false;
            }
            if fields.len() < 3 {
                return false;
            }
            if let Ok(dest) = u32::from_str_radix(fields[1], 16) {
                // A link-local dest still counts when it has a real gateway —
                // preserves the original defensive check for odd route tables.
                let gateway = u32::from_str_radix(fields[2], 16).unwrap_or(0);
                (dest & IPV4_LINK_LOCAL_MASK) != IPV4_LINK_LOCAL_PREFIX || gateway != 0
            } else {
                false
            }
        });
    }
    false
}

/// Checks /proc/net/if_inet6 for routable IPv6 addresses on this interface.
fn has_routable_ipv6(iface: &str) -> bool {
    if let Ok(content) = fs::read_to_string(PROC_IF_INET6) {
        return content.lines().any(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 6 {
                return false;
            }
            if fields[5] != iface {
                return false;
            }
            if let Ok(scope) = u32::from_str_radix(fields[3], 16) {
                scope != IPV6_SCOPE_LINK_LOCAL
            } else {
                false
            }
        });
    }
    false
}

/// Manages eBPF program lifecycle: load once, attach to multiple interfaces.
pub struct TlsProbeLoader {
    ebpf: Ebpf,
    programs_loaded: bool,
    attached_interfaces: Vec<String>,
}

impl TlsProbeLoader {
    /// Loads the eBPF object file into kernel memory.
    /// Does NOT yet load individual programs — that happens on first attach.
    pub fn new(ebpf_path: &Path) -> Result<Self, ProbeError> {
        let data = fs::read(ebpf_path)
            .map_err(|e| ProbeError::LoadError(format!("Failed to read eBPF program: {}", e)))?;

        let ebpf = Ebpf::load(&data)
            .map_err(|e| ProbeError::LoadError(format!("Failed to load eBPF program: {}", e)))?;

        Ok(Self {
            ebpf,
            programs_loaded: false,
            attached_interfaces: Vec::new(),
        })
    }

    /// Attaches TC ingress/egress classifiers to each interface.
    /// Programs are loaded into the kernel on the first call; subsequent interfaces
    /// reuse the already-loaded programs (avoiding AlreadyLoaded errors).
    pub fn attach(&mut self, interfaces: &[String]) -> Result<Vec<String>, ProbeError> {
        if !self.programs_loaded {
            self.load_programs()?;
        }

        let mut attached = Vec::new();

        for iface in interfaces {
            match self.attach_interface(iface) {
                Ok(()) => {
                    attached.push(format!("tc:{}:ingress", iface));
                    attached.push(format!("tc:{}:egress", iface));
                    self.attached_interfaces.push(iface.clone());
                }
                Err(e) => {
                    warn!("Skipping {}: {}", iface, e);
                    continue;
                }
            }
        }

        if attached.is_empty() {
            return Err(ProbeError::AttachError(
                "No probes were attached. Use --interface to specify a valid interface."
                    .to_string(),
            ));
        }

        Ok(attached)
    }

    /// Loads ingress and egress TC programs, plus the process-attribution
    /// kprobes and kretprobes, into the kernel exactly once.
    fn load_programs(&mut self) -> Result<(), ProbeError> {
        for prog in [EbpfProgram::Ingress, EbpfProgram::Egress] {
            let classifier: &mut SchedClassifier = self
                .ebpf
                .program_mut(prog.name())
                .ok_or_else(|| {
                    ProbeError::AttachError(format!("{} program not found", prog.name()))
                })?
                .try_into()
                .map_err(|e| {
                    ProbeError::AttachError(format!("Invalid program type for {:?}: {:?}", prog, e))
                })?;

            classifier.load().map_err(|e| {
                ProbeError::LoadError(format!("Failed to load {:?} program: {:?}", prog, e))
            })?;
        }

        match self.load_and_attach_attribution_probes() {
            Ok(()) => {}
            Err(e) => {
                warn!("Process attribution disabled: {e}");
                warn!("TLS capture will work but events won't have PID/process names");
            }
        }

        self.programs_loaded = true;
        info!("eBPF TC programs loaded into kernel");
        Ok(())
    }

    /// Loads and attaches connect kprobe/kretprobe pairs and the accept
    /// kretprobe used for process attribution. Attached globally (not
    /// per-interface): they fire on system calls in the calling process's
    /// context.
    fn load_and_attach_attribution_probes(&mut self) -> Result<(), ProbeError> {
        // Attach outbound (connect-side) kprobe entries — stash sock ptr + info
        for name in CONNECT_KPROBES {
            let probe: &mut KProbe = self
                .ebpf
                .program_mut(name)
                .ok_or_else(|| ProbeError::AttachError(format!("{name} not found")))?
                .try_into()
                .map_err(|e| {
                    ProbeError::AttachError(format!("Invalid kprobe type for {name}: {e:?}"))
                })?;

            probe
                .load()
                .map_err(|e| ProbeError::LoadError(format!("Failed to load {name}: {e:?}")))?;
            probe
                .attach(name, 0)
                .map_err(|e| ProbeError::AttachError(format!("Failed to attach {name}: {e:?}")))?;

            info!("Attached kprobe: {}", name);
        }

        // Attach outbound (connect-side) kretprobes — read 4-tuple, insert CONN_MAP
        for (prog_name, fn_name) in CONNECT_KRETPROBES {
            let probe: &mut KProbe = self
                .ebpf
                .program_mut(prog_name)
                .ok_or_else(|| ProbeError::AttachError(format!("{prog_name} not found")))?
                .try_into()
                .map_err(|e| {
                    ProbeError::AttachError(format!(
                        "Invalid kretprobe type for {prog_name}: {e:?}"
                    ))
                })?;

            probe
                .load()
                .map_err(|e| ProbeError::LoadError(format!("Failed to load {prog_name}: {e:?}")))?;
            probe.attach(fn_name, 0).map_err(|e| {
                ProbeError::AttachError(format!("Failed to attach {prog_name}: {e:?}"))
            })?;

            info!("Attached kretprobe: {} -> {}", prog_name, fn_name);
        }

        // Attach inbound (accept-side) kretprobe. aya has no separate
        // KRetProbe userspace type: the #[kretprobe] section in the eBPF
        // object makes this KProbe attach as a return probe.
        let kretprobe: &mut KProbe = self
            .ebpf
            .program_mut(ACCEPT_KRETPROBE)
            .ok_or_else(|| ProbeError::AttachError(format!("{} not found", ACCEPT_KRETPROBE)))?
            .try_into()
            .map_err(|e| {
                ProbeError::AttachError(format!(
                    "Invalid kretprobe type for {}: {e:?}",
                    ACCEPT_KRETPROBE
                ))
            })?;

        kretprobe.load().map_err(|e| {
            ProbeError::LoadError(format!("Failed to load {}: {e:?}", ACCEPT_KRETPROBE))
        })?;
        kretprobe.attach(ACCEPT_KRETPROBE, 0).map_err(|e| {
            ProbeError::AttachError(format!("Failed to attach {}: {e:?}", ACCEPT_KRETPROBE))
        })?;

        info!("Attached kretprobe: {}", ACCEPT_KRETPROBE);

        Ok(())
    }

    /// Attaches already-loaded programs to a single interface.
    /// Assumes load_programs() has been called.
    fn attach_interface(&mut self, iface: &str) -> Result<(), ProbeError> {
        let _ = tc::qdisc_add_clsact(iface);

        let attach_pairs = [
            (EbpfProgram::Ingress, TcAttachType::Ingress),
            (EbpfProgram::Egress, TcAttachType::Egress),
        ];

        for (prog, direction) in attach_pairs {
            let classifier: &mut SchedClassifier = self
                .ebpf
                .program_mut(prog.name())
                .ok_or_else(|| {
                    ProbeError::AttachError(format!("{} program not found", prog.name()))
                })?
                .try_into()
                .map_err(|e| {
                    ProbeError::AttachError(format!("Invalid program type for {:?}: {:?}", prog, e))
                })?;

            classifier.attach(iface, direction).map_err(|e| {
                ProbeError::AttachError(format!(
                    "Failed to attach {:?} to {}: {:?}",
                    prog, iface, e
                ))
            })?;

            info!("Attached {} to {} {:?}", prog.name(), iface, direction);
        }

        Ok(())
    }

    /// Takes the kernel-side ringbuf drop counter map for periodic userspace reads.
    pub fn take_kernel_drops_map(
        &mut self,
    ) -> Option<aya::maps::PerCpuArray<aya::maps::MapData, u64>> {
        self.ebpf
            .take_map(RINGBUF_DROPS_MAP_NAME)
            .and_then(|m| aya::maps::PerCpuArray::try_from(m).ok())
    }

    /// Takes the CONN_MAP for attribution verification (e.g., self-test).
    pub fn take_conn_map(
        &mut self,
    ) -> Option<
        aya::maps::HashMap<
            aya::maps::MapData,
            tls_probe_common::ConnKey,
            tls_probe_common::ConnInfo,
        >,
    > {
        self.ebpf
            .take_map(CONN_MAP_NAME)
            .and_then(|m| aya::maps::HashMap::try_from(m).ok())
    }

    /// Starts reading TLS capture events from the ring buffer, forwarding to the channel.
    /// Runs until `running` is set to false.
    pub async fn run(
        &mut self,
        event_tx: mpsc::Sender<RawTlsCapture>,
        events_dropped: Arc<AtomicU64>,
        running: Arc<AtomicBool>,
    ) -> Result<(), ProbeError> {
        let map = self
            .ebpf
            .take_map(TLS_EVENTS_MAP_NAME)
            .ok_or_else(|| ProbeError::MapNotFound(TLS_EVENTS_MAP_NAME.to_string()))?;

        let ring_buf = RingBuf::try_from(map).map_err(|e| {
            ProbeError::MapNotFound(format!("Failed to convert TLS_EVENTS map: {:?}", e))
        })?;

        let mut async_fd = AsyncFd::new(ring_buf).map_err(|e| {
            ProbeError::LoadError(format!("Failed to create async ringbuf fd: {e}"))
        })?;

        let running_drain = running.clone();
        let drain = tokio::spawn(async move {
            loop {
                if !running_drain.load(Ordering::Relaxed) {
                    break;
                }

                let mut guard = match async_fd.readable_mut().await {
                    Ok(guard) => guard,
                    Err(e) => {
                        error!("Error polling ringbuf: {e}");
                        continue;
                    }
                };

                loop {
                    let ring_buf = guard.get_inner_mut();
                    match ring_buf.next() {
                        Some(item) => {
                            let bytes = &*item;
                            if bytes.len() < RAW_CAPTURE_HEADER_SIZE {
                                continue;
                            }

                            let mut capture = RawTlsCapture::default();
                            let copy_len = bytes.len().min(std::mem::size_of::<RawTlsCapture>());
                            unsafe {
                                std::ptr::copy_nonoverlapping(
                                    bytes.as_ptr(),
                                    &mut capture as *mut _ as *mut u8,
                                    copy_len,
                                );
                            }

                            match event_tx.try_send(capture) {
                                Ok(()) => {}
                                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                                    events_dropped.fetch_add(1, Ordering::Relaxed);
                                }
                                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                                    return;
                                }
                            }
                        }
                        None => break,
                    }
                }

                guard.clear_ready();
            }
        });

        while running.load(Ordering::Relaxed) {
            tokio::time::sleep(tokio::time::Duration::from_millis(EVENT_LOOP_POLL_MS)).await;
        }

        // The drain task only re-checks `running` after a readiness wakeup; on
        // a quiet ringbuf it parks in readable_mut().await indefinitely. Give
        // it a short grace to flush stragglers, then abort — post-shutdown
        // events are not worth hanging SIGTERM for.
        let mut drain = drain;
        if tokio::time::timeout(tokio::time::Duration::from_secs(2), &mut drain)
            .await
            .is_err()
        {
            drain.abort();
            let _ = drain.await;
        }
        Ok(())
    }
}
