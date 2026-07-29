use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

#[cfg(target_os = "linux")]
use anyhow::Context;
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(target_os = "linux")]
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::time::Instant;
#[cfg(target_os = "linux")]
use tracing::{debug, info, Level};

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

    #[arg(
        long,
        help = "Maximum bytes per output chunk before rotation (required for file output)"
    )]
    pub max_output_bytes: Option<u64>,

    #[arg(
        long,
        help = "Maximum total spool size; evict oldest complete chunks when exceeded"
    )]
    pub max_total_bytes: Option<u64>,

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

#[cfg(target_os = "linux")]
const DEFAULT_EBPF_PATH: &str = "target/bpfel-unknown-none/release/tls-probe-ebpf";
#[cfg(target_os = "linux")]
const EVENT_CHANNEL_CAPACITY: usize = 1000;
#[cfg(target_os = "linux")]
const POLL_INTERVAL_MS: u64 = 100;

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
        use crate::pipeline::{
            run_writer_thread, sum_kernel_drops, BufferedLineWriter, RotatingSpoolWriter,
            WriterBackend, COUNTER_LOG_INTERVAL, WRITE_CHANNEL_CAPACITY,
        };
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

        let kernel_drops_map = loader.take_kernel_drops_map();

        let events_dropped = Arc::new(AtomicU64::new(0));
        let events_emitted = Arc::new(AtomicU64::new(0));
        let chunks_evicted = Arc::new(AtomicU64::new(0));
        let running = Arc::new(AtomicBool::new(true));

        let (capture_tx, mut capture_rx) = mpsc::channel::<RawTlsCapture>(EVENT_CHANNEL_CAPACITY);
        let (writer_tx, writer_rx) = mpsc::channel::<Vec<u8>>(WRITE_CHANNEL_CAPACITY);

        let emit_to_stdout = args.output.is_none();
        let verbose_events = tracing::enabled!(Level::DEBUG);

        let file_backend = match &args.output {
            Some(output_path) => {
                if let Some(max_chunk_bytes) = args.max_output_bytes {
                    info!(
                        "Streaming events (JSONL) to spool dir {:?} (max chunk {} bytes)",
                        output_path, max_chunk_bytes
                    );
                    let spool = RotatingSpoolWriter::new(
                        output_path.clone(),
                        max_chunk_bytes,
                        args.max_total_bytes,
                        chunks_evicted.clone(),
                    )
                    .with_context(|| format!("Failed to open spool directory {:?}", output_path))?;
                    Some(WriterBackend::Spool(spool))
                } else {
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
                    let file = File::create(&final_path).with_context(|| {
                        format!("Failed to create output file {:?}", final_path)
                    })?;
                    Some(WriterBackend::Plain(BufferedLineWriter::new(file)))
                }
            }
            None => None,
        };

        let events_emitted_writer = events_emitted.clone();
        let writer_handle = std::thread::spawn(move || {
            run_writer_thread(
                writer_rx,
                file_backend,
                emit_to_stdout,
                events_emitted_writer,
            );
        });

        let writer_tx_worker = writer_tx.clone();
        let worker_handle = tokio::spawn(async move {
            while let Some(capture) = capture_rx.recv().await {
                let analysis = analyze_capture(&capture);

                if verbose_events {
                    debug!(
                        "{}: {} -> {}, {}, {} ciphers{}",
                        analysis.handshake_type,
                        analysis.src,
                        analysis.dst,
                        analysis.tls_version,
                        analysis.cipher_suites.len(),
                        analysis
                            .sni
                            .as_ref()
                            .map(|s| format!(" ({s})"))
                            .unwrap_or_default()
                    );
                }

                let mut line = serde_json::to_vec(&analysis).unwrap_or_default();
                line.push(b'\n');
                if writer_tx_worker.send(line).await.is_err() {
                    break;
                }
            }
        });

        let running_for_loader = running.clone();
        let events_dropped_loader = events_dropped.clone();
        let loader_handle = tokio::spawn(async move {
            if let Err(e) = loader
                .run(capture_tx, events_dropped_loader, running_for_loader)
                .await
            {
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

        let start = Instant::now();
        let mut last_counter_log = Instant::now();

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
            sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;

            if last_counter_log.elapsed() >= COUNTER_LOG_INTERVAL {
                let kernel_lost = sum_kernel_drops(kernel_drops_map.as_ref());
                info!(
                    "counters: emitted={} dropped={} kernel_lost={} chunks_evicted={}",
                    events_emitted.load(Ordering::Relaxed),
                    events_dropped.load(Ordering::Relaxed),
                    kernel_lost,
                    chunks_evicted.load(Ordering::Relaxed)
                );
                last_counter_log = Instant::now();
            }

            if !continuous && start.elapsed().as_secs() >= duration_secs {
                info!("Capture duration reached");
                break;
            }
            if !running.load(Ordering::Relaxed) {
                info!("Capture interrupted");
                break;
            }
        }

        running.store(false, Ordering::Relaxed);

        let _ = loader_handle.await;
        drop(writer_tx);
        let _ = worker_handle.await;
        writer_handle
            .join()
            .map_err(|e| anyhow::anyhow!("writer thread panicked: {e:?}"))?;

        let kernel_lost = sum_kernel_drops(kernel_drops_map.as_ref());
        info!(
            "counters: emitted={} dropped={} kernel_lost={} chunks_evicted={}",
            events_emitted.load(Ordering::Relaxed),
            events_dropped.load(Ordering::Relaxed),
            kernel_lost,
            chunks_evicted.load(Ordering::Relaxed)
        );
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
