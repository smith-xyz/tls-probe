use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

#[cfg(target_os = "linux")]
use anyhow::Context;
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::{BufWriter, Write};
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "linux")]
use std::sync::Arc;
#[cfg(target_os = "linux")]
use tracing::info;

#[cfg(target_os = "linux")]
const DEFAULT_EBPF_PATH: &str = "target/bpfel-unknown-none/release/tls-probe-ebpf";
#[cfg(target_os = "linux")]
const EVENT_CHANNEL_CAPACITY: usize = 1000;
#[cfg(target_os = "linux")]
const POLL_INTERVAL_MS: u64 = 100;

#[derive(Args, Default)]
pub struct CaptureArgs {
    #[arg(
        short,
        long,
        help = "Capture duration in seconds (0 or omit for continuous)"
    )]
    pub duration: Option<u64>,

    #[arg(
        short,
        long,
        help = "Output file path for streamed events (JSONL, one event per line)"
    )]
    pub output: Option<PathBuf>,

    #[arg(
        long,
        help = "Append Unix timestamp to output filename (e.g. capture.json -> capture-1719500000.json)"
    )]
    pub output_timestamped: bool,

    #[arg(long, help = "Path to compiled eBPF program")]
    pub ebpf: Option<PathBuf>,

    #[arg(
        short,
        long,
        default_value = "auto",
        help = "Network interface: 'auto' (default route), 'all', or comma-separated list"
    )]
    pub interface: String,
}

/// Captures TLS handshake events via eBPF and streams them as JSONL.
///
/// Takes ownership of `args` (consumed during setup). Events are written
/// as one JSON object per line to the `--output` file and/or stdout.
/// Returns when the capture duration elapses or a signal is received.
pub async fn run(args: CaptureArgs) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use crate::capabilities::{check_capabilities, ensure_memlock_rlimit};
        use crate::loader::{detect_interfaces, TlsProbeLoader};
        use crate::tls::analyze_capture;
        use tls_probe_common::RawTlsCapture;
        use tokio::sync::mpsc;
        use tokio::time::{sleep, Duration};

        check_capabilities().with_context(|| "Capability check failed")?;
        ensure_memlock_rlimit().with_context(|| "Failed to configure memory limits")?;

        let ebpf_path = args
            .ebpf
            .unwrap_or_else(|| PathBuf::from(DEFAULT_EBPF_PATH));

        info!("Loading eBPF program from: {:?}", ebpf_path);

        let mut loader = TlsProbeLoader::new(&ebpf_path)
            .with_context(|| format!("Failed to load eBPF program from {:?}", ebpf_path))?;

        info!("eBPF program loaded successfully");

        let interfaces = detect_interfaces(&args.interface)
            .with_context(|| "Failed to detect network interfaces")?;

        info!("Attaching TC probes to interfaces: {:?}", interfaces);
        let attached = loader
            .attach(&interfaces)
            .with_context(|| "Failed to attach TC probes")?;
        info!("Attached {} probes", attached.len());
        info!("Probes attached: {:?}", attached);

        let (tx, mut rx) = mpsc::channel::<RawTlsCapture>(EVENT_CHANNEL_CAPACITY);
        let running = Arc::new(AtomicBool::new(true));

        let running_for_loop = running.clone();
        let tx_clone = tx.clone();
        tokio::spawn(async move {
            if let Err(e) = loader.run(tx_clone, running_for_loop).await {
                tracing::error!("Event loop error: {}", e);
            }
        });

        let continuous = args.duration.is_none() || args.duration == Some(0);
        let duration_secs = args.duration.unwrap_or(0);

        if continuous {
            info!("Capturing TLS handshakes continuously...");
        } else {
            info!("Capturing TLS handshakes for {} seconds...", duration_secs);
        }
        info!("Press Ctrl+C to stop");

        let mut writer: Option<BufWriter<File>> = match &args.output {
            Some(output_path) => {
                let final_path = if args.output_timestamped {
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let stem = output_path
                        .file_stem()
                        .unwrap_or_default()
                        .to_string_lossy();
                    let ext = output_path
                        .extension()
                        .map(|e| e.to_string_lossy().to_string());
                    let new_name = match ext {
                        Some(e) => format!("{}-{}.{}", stem, ts, e),
                        None => format!("{}-{}", stem, ts),
                    };
                    output_path.with_file_name(new_name)
                } else {
                    output_path.clone()
                };
                info!("Streaming events (JSONL) to: {:?}", final_path);
                let file = File::create(&final_path)
                    .with_context(|| format!("Failed to create output file {:?}", final_path))?;
                Some(BufWriter::new(file))
            }
            None => None,
        };

        let emit_to_stdout = args.output.is_none();
        let start = std::time::Instant::now();

        let running_clone = running.clone();
        tokio::spawn(async move {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut sigterm) => {
                    tokio::select! {
                        _ = tokio::signal::ctrl_c() => {},
                        _ = sigterm.recv() => {},
                    }
                }
                Err(_) => {
                    tokio::signal::ctrl_c().await.ok();
                }
            }
            running_clone.store(false, Ordering::Relaxed);
        });

        loop {
            tokio::select! {
                Some(capture) = rx.recv() => {
                    let analysis = analyze_capture(&capture);

                    if let Some(w) = writer.as_mut() {
                        serde_json::to_writer(&mut *w, &analysis)
                            .with_context(|| "Failed to serialize event")?;
                        w.write_all(b"\n")
                            .with_context(|| "Failed to write newline")?;
                        w.flush()
                            .with_context(|| "Failed to flush event to disk")?;
                    }

                    if emit_to_stdout {
                        let json = serde_json::to_string(&analysis)
                            .with_context(|| "Failed to serialize event for stdout")?;
                        println!("{}", json);
                    } else {
                        info!(
                            "{}: {} -> {}, {}, {} ciphers{}{}",
                            analysis.handshake_type,
                            analysis.src,
                            analysis.dst,
                            analysis.tls_version,
                            analysis.cipher_suites.len(),
                            if analysis.pqc_ready { " [PQC]" } else { "" },
                            analysis.sni.as_ref().map(|s| format!(" ({})", s)).unwrap_or_default()
                        );

                        if analysis.pqc_ready {
                            info!("  PQC groups: {:?}", analysis.pqc_groups);
                        }
                    }
                }
                _ = sleep(Duration::from_millis(POLL_INTERVAL_MS)) => {
                    if !continuous && start.elapsed().as_secs() >= duration_secs {
                        info!("Capture duration reached");
                        break;
                    }
                    if !running.load(Ordering::Relaxed) {
                        info!("Capture interrupted");
                        break;
                    }
                }
            }
        }

        running.store(false, Ordering::Relaxed);

        if let Some(mut w) = writer.take() {
            w.flush()
                .with_context(|| "Failed final flush to output file")?;
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        eprintln!("Error: eBPF capture requires Linux");
        eprintln!();
        eprintln!("This tool uses eBPF probes that only work on Linux.");
        eprintln!("Build and run on a Linux system with:");
        eprintln!("  cargo xtask build-ebpf");
        eprintln!("  cargo build --release");
        eprintln!("  sudo ./target/release/tls-probe capture -i eth0");
    }

    Ok(())
}
