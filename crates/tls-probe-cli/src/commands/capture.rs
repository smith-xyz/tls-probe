use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

#[cfg(target_os = "linux")]
const DEFAULT_EBPF_PATH: &str = "target/bpfel-unknown-none/release/tls-probe-ebpf";
#[cfg(target_os = "linux")]
use anyhow::Context;
#[cfg(target_os = "linux")]
use std::collections::HashSet;
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::Write;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "linux")]
use std::sync::Arc;
#[cfg(target_os = "linux")]
use tracing::info;

#[derive(Args, Default)]
pub struct CaptureArgs {
    #[arg(
        short,
        long,
        help = "Capture duration in seconds (0 or omit for continuous)"
    )]
    pub duration: Option<u64>,

    #[arg(short, long, help = "Output file path for captured events (JSON)")]
    pub output: Option<PathBuf>,

    #[arg(long, help = "Path to compiled eBPF program")]
    pub ebpf: Option<PathBuf>,

    #[arg(long, help = "Output detailed analysis instead of raw events")]
    pub analyze: bool,

    #[arg(long, help = "Print summary statistics at end of capture")]
    pub summary: bool,

    #[arg(
        short,
        long,
        default_value = "auto",
        help = "Network interface: 'auto' (default route), 'all', or comma-separated list"
    )]
    pub interface: String,
}

pub async fn run(args: CaptureArgs) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use crate::capabilities::{check_capabilities, ensure_memlock_rlimit};
        use crate::loader::{detect_interfaces, TlsProbeLoader};
        use crate::tls::{analyze_capture, TlsAnalysis};
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
        let attached = loader.attach(&interfaces)?;
        info!("Attached {} probes", attached.len());
        info!("Probes attached: {:?}", attached);

        let (tx, mut rx) = mpsc::channel::<RawTlsCapture>(1000);
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

        let streaming = args.output.is_none() && !args.summary;
        let mut captures: Vec<RawTlsCapture> = Vec::new();
        let mut analyses: Vec<TlsAnalysis> = Vec::new();
        let start = std::time::Instant::now();

        let running_clone = running.clone();
        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.ok();
            running_clone.store(false, Ordering::Relaxed);
        });

        loop {
            tokio::select! {
                Some(capture) = rx.recv() => {
                    let analysis = analyze_capture(&capture);

                    if streaming {
                        let json = if args.analyze {
                            serde_json::to_string(&analysis)?
                        } else {
                            format!(
                                r#"{{"timestamp":"{}","src":"{}","dst":"{}","handshake_type":"{}","tls_version":"{}"}}"#,
                                analysis.timestamp,
                                analysis.src,
                                analysis.dst,
                                analysis.handshake_type,
                                analysis.tls_version
                            )
                        };
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

                    captures.push(capture);
                    analyses.push(analysis);
                }
                _ = sleep(Duration::from_millis(100)) => {
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

        if args.summary {
            print_summary(&analyses);
        }

        if let Some(output_path) = args.output {
            let json = serde_json::to_string_pretty(&analyses)?;
            let mut file = File::create(&output_path)?;
            file.write_all(json.as_bytes())?;
            info!("Events written to: {:?}", output_path);
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

#[cfg(target_os = "linux")]
fn print_summary(analyses: &[crate::tls::TlsAnalysis]) {
    use std::collections::HashMap;

    if analyses.is_empty() {
        println!("\n=== Capture Summary ===");
        println!("No TLS handshake events captured");
        return;
    }

    let client_hellos = analyses
        .iter()
        .filter(|a| a.handshake_type == "ClientHello")
        .count();
    let server_hellos = analyses
        .iter()
        .filter(|a| a.handshake_type == "ServerHello")
        .count();
    let pqc_count = analyses.iter().filter(|a| a.pqc_ready).count();

    let unique_dests: HashSet<&str> = analyses.iter().map(|a| a.dst.as_str()).collect();

    let mut version_counts: HashMap<&str, usize> = HashMap::new();
    for a in analyses {
        *version_counts.entry(&a.tls_version).or_insert(0) += 1;
    }

    println!("\n=== Capture Summary ===");
    println!("Total events:      {}", analyses.len());
    println!("  ClientHello:     {}", client_hellos);
    println!("  ServerHello:     {}", server_hellos);
    println!();
    println!("PQC Status:");
    if analyses.is_empty() {
        println!("  No events captured");
    } else {
        let pqc_pct = (pqc_count as f64 / analyses.len() as f64) * 100.0;
        println!("  PQC-ready:       {} ({:.1}%)", pqc_count, pqc_pct);
        println!(
            "  Classical-only:  {} ({:.1}%)",
            analyses.len() - pqc_count,
            100.0 - pqc_pct
        );
    }
    println!();
    println!("TLS Versions:");
    let mut versions: Vec<_> = version_counts.iter().collect();
    versions.sort_by(|a, b| b.1.cmp(a.1));
    for (version, count) in versions {
        println!("  {}: {}", version, count);
    }
    println!();
    println!("Unique destinations: {}", unique_dests.len());
}
