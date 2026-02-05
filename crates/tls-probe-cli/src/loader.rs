use std::fs;
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
use tracing::{error, info};

use crate::error::ProbeError;

pub fn detect_interfaces(mode: &str) -> Result<Vec<String>, ProbeError> {
    match mode {
        "auto" => detect_default_interface().map(|iface| vec![iface]),
        "all" => detect_all_interfaces(),
        explicit => Ok(explicit.split(',').map(|s| s.trim().to_string()).collect()),
    }
}

fn detect_default_interface() -> Result<String, ProbeError> {
    let route = fs::read_to_string("/proc/net/route")
        .map_err(|e| ProbeError::LoadError(format!("Failed to read route table: {}", e)))?;

    for line in route.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 2 && fields[1] == "00000000" {
            return Ok(fields[0].to_string());
        }
    }

    Err(ProbeError::LoadError(
        "No default route found. Use --interface to specify explicitly.".to_string(),
    ))
}

fn detect_all_interfaces() -> Result<Vec<String>, ProbeError> {
    let entries = fs::read_dir("/sys/class/net")
        .map_err(|e| ProbeError::LoadError(format!("Failed to read network interfaces: {}", e)))?;

    let interfaces: Vec<String> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|name| name != "lo")
        .collect();

    if interfaces.is_empty() {
        return Err(ProbeError::LoadError(
            "No network interfaces found".to_string(),
        ));
    }

    Ok(interfaces)
}

pub struct TlsProbeLoader {
    ebpf: Ebpf,
    attached_interfaces: Vec<String>,
}

impl TlsProbeLoader {
    pub fn new(ebpf_path: &Path) -> Result<Self, ProbeError> {
        let data = std::fs::read(ebpf_path)
            .map_err(|e| ProbeError::LoadError(format!("Failed to read eBPF program: {}", e)))?;

        let ebpf = Ebpf::load(&data)
            .map_err(|e| ProbeError::LoadError(format!("Failed to load eBPF program: {}", e)))?;

        Ok(Self {
            ebpf,
            attached_interfaces: Vec::new(),
        })
    }

    pub fn attach(&mut self, interfaces: &[String]) -> Result<Vec<String>, ProbeError> {
        let mut attached = Vec::new();

        for iface in interfaces {
            if let Err(e) = self.attach_interface(iface) {
                error!("Failed to attach to {}: {}", iface, e);
                continue;
            }
            attached.push(format!("tc:{}:ingress", iface));
            attached.push(format!("tc:{}:egress", iface));
            self.attached_interfaces.push(iface.clone());
        }

        if attached.is_empty() {
            return Err(ProbeError::AttachError(
                "No probes were attached. Check interface names.".to_string(),
            ));
        }

        Ok(attached)
    }

    fn attach_interface(&mut self, iface: &str) -> Result<(), ProbeError> {
        let _ = tc::qdisc_add_clsact(iface);

        let ingress: &mut SchedClassifier = self
            .ebpf
            .program_mut("tls_ingress")
            .ok_or_else(|| ProbeError::AttachError("tls_ingress program not found".to_string()))?
            .try_into()
            .map_err(|e| ProbeError::AttachError(format!("Invalid program type: {:?}", e)))?;

        ingress.load().map_err(|e| {
            ProbeError::AttachError(format!("Failed to load ingress program: {:?}", e))
        })?;

        ingress
            .attach(iface, TcAttachType::Ingress)
            .map_err(|e| ProbeError::AttachError(format!("Failed to attach ingress: {:?}", e)))?;

        info!("Attached tls_ingress to {} ingress", iface);

        let egress: &mut SchedClassifier = self
            .ebpf
            .program_mut("tls_egress")
            .ok_or_else(|| ProbeError::AttachError("tls_egress program not found".to_string()))?
            .try_into()
            .map_err(|e| ProbeError::AttachError(format!("Invalid program type: {:?}", e)))?;

        egress.load().map_err(|e| {
            ProbeError::AttachError(format!("Failed to load egress program: {:?}", e))
        })?;

        egress
            .attach(iface, TcAttachType::Egress)
            .map_err(|e| ProbeError::AttachError(format!("Failed to attach egress: {:?}", e)))?;

        info!("Attached tls_egress to {} egress", iface);

        Ok(())
    }

    pub async fn run(
        &mut self,
        event_tx: mpsc::Sender<RawTlsCapture>,
        running: Arc<AtomicBool>,
    ) -> Result<(), ProbeError> {
        let mut perf_array: AsyncPerfEventArray<_> = self
            .ebpf
            .take_map("TLS_EVENTS")
            .ok_or_else(|| ProbeError::MapNotFound("TLS_EVENTS".to_string()))?
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
                let mut buffers = (0..10)
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
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }

        Ok(())
    }

    pub fn detach(&mut self) {
        for iface in &self.attached_interfaces {
            let _ = tc::qdisc_detach_program(iface, TcAttachType::Ingress, "tls_ingress");
            let _ = tc::qdisc_detach_program(iface, TcAttachType::Egress, "tls_egress");
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
