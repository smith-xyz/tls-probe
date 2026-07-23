use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use aya::maps::AsyncPerfEventArray;
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::util::online_cpus;
use aya::Ebpf;
use bytes::BytesMut;
use tls_probe_common::RawTlsCapture;
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
/// Bridges (br-ex) report "unknown" when up; physical NICs report "up".
const ACTIVE_OPERSTATES: &[&str] = &["up", "unknown"];

// --- IPv4/IPv6 link-local detection ---

/// 169.254.0.0/16 in little-endian hex (as it appears in /proc/net/route).
const IPV4_LINK_LOCAL_PREFIX: u32 = 0x0000_FEA9;
const IPV4_LINK_LOCAL_MASK: u32 = 0x0000_FFFF;

/// IPv6 scope value for link-local addresses in /proc/net/if_inet6.
const IPV6_SCOPE_LINK_LOCAL: u32 = 0x20;

/// fe80::/10 prefix mask and value for IPv6 link-local detection.
const IPV6_LINK_LOCAL_PREFIX: u16 = 0xfe80;
const IPV6_LINK_LOCAL_MASK: u16 = 0xffc0;

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

const PERF_MAP_NAME: &str = "TLS_EVENTS";

// --- Perf buffer tuning ---

const PERF_BUFFER_COUNT: usize = 10;
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
///   1. Operationally UP (operstate is "up" or "unknown" — bridges report "unknown" when active)
///   2. Has at least one routable IP address (IPv4 or IPv6, excluding link-local)
///
/// This approach is platform-agnostic: works on OCP (br-ex), bare metal (eth0),
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
    let Ok(route) = fs::read_to_string(PROC_ROUTE) else {
        return false;
    };

    for line in route.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 8 && fields[0] == iface {
            let dest = u32::from_str_radix(fields[1], 16).unwrap_or(0);
            let gateway = u32::from_str_radix(fields[2], 16).unwrap_or(0);
            let is_link_local = (dest & IPV4_LINK_LOCAL_MASK) == IPV4_LINK_LOCAL_PREFIX;
            if !is_link_local || gateway != 0 {
                return true;
            }
        }
    }

    false
}

/// Parses /proc/net/if_inet6 to find non-link-local IPv6 addresses on the interface.
/// Format: address_hex ifindex prefix_len scope flags iface_name
fn has_routable_ipv6(iface: &str) -> bool {
    let Ok(content) = fs::read_to_string(PROC_IF_INET6) else {
        return false;
    };

    for line in content.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 6 && fields[5] == iface {
            let scope = u32::from_str_radix(fields[3], 16).unwrap_or(IPV6_SCOPE_LINK_LOCAL);
            if scope != IPV6_SCOPE_LINK_LOCAL {
                if let Some(addr) = parse_hex_ipv6(fields[0]) {
                    if !addr.is_loopback() && !is_link_local_v6(&addr) {
                        return true;
                    }
                }
            }
        }
    }

    false
}

/// Parses a 32-char hex string from /proc/net/if_inet6 into an IpAddr.
fn parse_hex_ipv6(hex: &str) -> Option<IpAddr> {
    if hex.len() != 32 {
        return None;
    }
    let mut octets = [0u8; 16];
    for (i, octet) in octets.iter_mut().enumerate() {
        *octet = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(IpAddr::V6(octets.into()))
}

fn is_link_local_v6(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V6(v6) => (v6.segments()[0] & IPV6_LINK_LOCAL_MASK) == IPV6_LINK_LOCAL_PREFIX,
        _ => false,
    }
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
                "No probes were attached. Use --interface to specify a valid interface.".to_string(),
            ));
        }

        Ok(attached)
    }

    /// Loads ingress and egress TC programs into the kernel exactly once.
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

        self.programs_loaded = true;
        info!("eBPF TC programs loaded into kernel");
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

    /// Starts reading TLS capture events from the perf buffer, forwarding to the channel.
    /// Runs until `running` is set to false.
    pub async fn run(
        &mut self,
        event_tx: mpsc::Sender<RawTlsCapture>,
        running: Arc<AtomicBool>,
    ) -> Result<(), ProbeError> {
        let mut perf_array: AsyncPerfEventArray<_> = self
            .ebpf
            .take_map(PERF_MAP_NAME)
            .ok_or_else(|| ProbeError::MapNotFound(PERF_MAP_NAME.to_string()))?
            .try_into()
            .map_err(|e| ProbeError::MapNotFound(format!("Failed to convert map: {:?}", e)))?;

        let cpus = online_cpus()
            .map_err(|e| ProbeError::LoadError(format!("Failed to get online CPUs: {:?}", e)))?;

        for cpu_id in cpus {
            let mut buf = perf_array
                .open(cpu_id, None)
                .map_err(|e| ProbeError::LoadError(format!("Failed to open perf buffer: {}", e)))?;

            let tx = event_tx.clone();
            let running = running.clone();

            tokio::spawn(async move {
                let mut buffers = (0..PERF_BUFFER_COUNT)
                    .map(|_| BytesMut::with_capacity(std::mem::size_of::<RawTlsCapture>()))
                    .collect::<Vec<_>>();

                while running.load(Ordering::Relaxed) {
                    let events = match buf.read_events(&mut buffers).await {
                        Ok(events) => events,
                        Err(e) => {
                            error!("Error reading perf events: {}", e);
                            continue;
                        }
                    };

                    for i in 0..events.read {
                        let buf = &buffers[i];
                        if buf.len() >= std::mem::size_of::<RawTlsCapture>() {
                            let capture: RawTlsCapture =
                                unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const _) };
                            if tx.send(capture).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }

        while running.load(Ordering::Relaxed) {
            tokio::time::sleep(tokio::time::Duration::from_millis(EVENT_LOOP_POLL_MS)).await;
        }

        Ok(())
    }

    pub fn detach(&mut self) {
        for iface in &self.attached_interfaces {
            let _ = tc::qdisc_detach_program(
                iface,
                TcAttachType::Ingress,
                EbpfProgram::Ingress.name(),
            );
            let _ = tc::qdisc_detach_program(
                iface,
                TcAttachType::Egress,
                EbpfProgram::Egress.name(),
            );
            info!("Detached TC programs from {}", iface);
        }
        self.attached_interfaces.clear();
    }
}

impl Drop for TlsProbeLoader {
    fn drop(&mut self) {
        self.detach();
    }
}
