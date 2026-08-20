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

    #[arg(
        long,
        help = "Root path to cgroup v2 filesystem (e.g. /host/sys/fs/cgroup)"
    )]
    pub cgroup_root: Option<PathBuf>,

    #[arg(long, help = "Skip the attribution self-test canary at startup")]
    pub no_self_test: bool,
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
        use tls_probe_common::{RawTlsCapture, FLAG_ALERT};
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

        // Run attribution self-test unless disabled.
        if !args.no_self_test {
            let conn_map = loader.take_conn_map();
            let _ = crate::self_test::run_self_test(conn_map.as_ref());
        }

        let kernel_drops_map = loader.take_kernel_drops_map();

        let events_dropped = Arc::new(AtomicU64::new(0));
        let events_emitted = Arc::new(AtomicU64::new(0));
        let chunks_evicted = Arc::new(AtomicU64::new(0));
        let correlator_sh_without_ch = Arc::new(AtomicU64::new(0));
        let alerts_dropped = Arc::new(AtomicU64::new(0));
        let certs_dropped_13 = Arc::new(AtomicU64::new(0));
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
        let correlator_sh_without_ch_worker = correlator_sh_without_ch.clone();
        let alerts_dropped_worker = alerts_dropped.clone();
        let certs_dropped_13_worker = certs_dropped_13.clone();
        let worker_handle = tokio::spawn(async move {
            use crate::containers::DefaultResolver;
            use crate::correlate::Correlator;
            use crate::reasm::Reassembler;
            use crate::record_walk;
            use crate::tls::analyze_capture_with_payload;

            let mut reassembler = Reassembler::new();
            let mut correlator = Correlator::new();
            let mut timeout_counter = 0u32;

            // Initialize cgroup resolver with optional custom root.
            let cgroup_root = args
                .cgroup_root
                .as_deref()
                .unwrap_or_else(|| std::path::Path::new("/sys/fs/cgroup"));
            let resolver = std::sync::Arc::new(DefaultResolver::new(cgroup_root));

            while let Some(capture) = capture_rx.recv().await {
                // Try to reassemble multi-packet records.
                let mut maybe_assembled = None;

                // Check if this is a fragment or continuation.
                // FLAG_INGRESS is a direction marker, not a reassembly indicator.
                if capture.flags
                    & (tls_probe_common::FLAG_FRAGMENT | tls_probe_common::FLAG_CONTINUATION)
                    != 0
                {
                    maybe_assembled = reassembler.insert(&capture);
                }

                // Process the capture or reassembled record.
                if let Some(assembled) = maybe_assembled {
                    // We have a completed reassembly: parse the assembled buffer with head_capture metadata.
                    let mut event =
                        analyze_capture_with_payload(&assembled.head_capture, &assembled.buffer);
                    event.reassembled = Some(true);
                    event.truncated = Some(assembled.truncated);

                    // Correlate ClientHello and ServerHello for negotiation insight.
                    let conn_key = tls_probe_common::ConnKey {
                        src_addr: assembled.head_capture.src_addr,
                        dst_addr: assembled.head_capture.dst_addr,
                        src_port: assembled.head_capture.src_port,
                        dst_port: assembled.head_capture.dst_port,
                    };

                    if assembled.head_capture.is_client_hello() {
                        if let Ok(analysis) =
                            tls_probe_parser::parse_tls_payload(&assembled.buffer, true)
                        {
                            correlator.on_client_hello(conn_key, &analysis);
                        }
                    } else if assembled.head_capture.is_server_hello() {
                        if let Ok(analysis) =
                            tls_probe_parser::parse_tls_payload(&assembled.buffer, false)
                        {
                            if let Some(negotiation) =
                                correlator.on_server_hello(conn_key, &analysis)
                            {
                                event.negotiation = Some(negotiation);
                            } else {
                                correlator_sh_without_ch_worker.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    } else if (assembled.head_capture.flags & FLAG_ALERT) != 0 {
                        // Alert record: try to join with a pending ClientHello.
                        if let Some((level, description)) =
                            crate::tls::parse_alert(&assembled.buffer)
                        {
                            if let Some(negotiation) =
                                correlator.on_alert(conn_key, level, description)
                            {
                                event.negotiation = Some(negotiation);
                            } else {
                                // Alert without matching CH: drop it and count.
                                alerts_dropped_worker.fetch_add(1, Ordering::Relaxed);
                            }
                        } else {
                            // Malformed alert: drop and count.
                            alerts_dropped_worker.fetch_add(1, Ordering::Relaxed);
                        }
                    } else if assembled.head_capture.handshake_type == 0x0B {
                        // Certificate message: parse and track mTLS state.
                        // Determine if client-sent (ingress, FLAG_INGRESS) or server-sent (egress, no FLAG_INGRESS).
                        let is_client =
                            (assembled.head_capture.flags & tls_probe_common::FLAG_INGRESS) != 0;

                        // Try to parse the leaf certificate.
                        // Skip handshake header (1 byte type + 3 byte length) in assembled buffer.
                        if assembled.buffer.len() > 4 {
                            let cert_payload = &assembled.buffer[4..];
                            if let Some(cert) = crate::certificate::parse_certificate(cert_payload)
                            {
                                event.certificate = Some(cert);
                            }
                        }

                        // Track mTLS: client-sent Certificate implies mTLS. The
                        // completed-mTLS negotiation rides this event (the SH
                        // was already emitted before the client cert existed).
                        if is_client {
                            if let Some(neg) = correlator.on_client_certificate(conn_key) {
                                event.negotiation = Some(neg);
                            }
                        }

                        // TLS 1.3: drop Certificate handshake (kernel already captures everything).
                        if let Ok(analysis) =
                            tls_probe_parser::parse_tls_payload(&assembled.buffer, is_client)
                        {
                            let version = analysis.effective_version();
                            if version == 0x0304 {
                                certs_dropped_13_worker.fetch_add(1, Ordering::Relaxed);
                                // Skip emitting this event.
                                continue;
                            }
                        }
                    } else if assembled.head_capture.handshake_type == 0x0D {
                        // CertificateRequest message: track mTLS state.
                        correlator.on_certificate_request(conn_key);

                        // TLS 1.3: drop CertificateRequest (kernel already captures everything).
                        if let Ok(analysis) =
                            tls_probe_parser::parse_tls_payload(&assembled.buffer, false)
                        {
                            let version = analysis.effective_version();
                            if version == 0x0304 {
                                certs_dropped_13_worker.fetch_add(1, Ordering::Relaxed);
                                // Skip emitting this event.
                                continue;
                            }
                        }
                    }

                    // Enrich with cgroup and container attribution.
                    event = crate::tls::enrich_with_cgroup(
                        event,
                        &assembled.head_capture,
                        resolver.as_ref(),
                    );

                    if verbose_events {
                        debug!(
                            "{}: {} -> {}, {}, {} ciphers{} [reassembled: {}]",
                            event.handshake_type,
                            event.src,
                            event.dst,
                            event.tls_version,
                            event.cipher_suites.len(),
                            event
                                .sni
                                .as_ref()
                                .map(|s| format!(" ({s})"))
                                .unwrap_or_default(),
                            event.reassembled.unwrap_or(false)
                        );
                    }

                    let mut line = serde_json::to_vec(&event).unwrap_or_default();
                    line.push(b'\n');
                    if writer_tx_worker.send(line).await.is_err() {
                        break;
                    }
                } else if capture.flags
                    & (tls_probe_common::FLAG_FRAGMENT | tls_probe_common::FLAG_CONTINUATION)
                    == 0
                {
                    // Non-fragmented: process normally (fast path).
                    let mut analysis = analyze_capture(&capture);

                    // Correlate ClientHello and ServerHello for negotiation insight.
                    let conn_key = tls_probe_common::ConnKey {
                        src_addr: capture.src_addr,
                        dst_addr: capture.dst_addr,
                        src_port: capture.src_port,
                        dst_port: capture.dst_port,
                    };

                    if capture.is_client_hello() {
                        if let Ok(analysis_parsed) =
                            tls_probe_parser::parse_tls_payload(capture.payload_slice(), true)
                        {
                            correlator.on_client_hello(conn_key, &analysis_parsed);
                        }
                    } else if capture.is_server_hello() {
                        if let Ok(analysis_parsed) =
                            tls_probe_parser::parse_tls_payload(capture.payload_slice(), false)
                        {
                            // Userspace multi-record extraction for TLS 1.2 server certificate flights.
                            // Process CertificateRequest BEFORE ServerHello negotiation so mtls_requested
                            // is set in the correlator before we join with the ClientHello.
                            let record_version = analysis_parsed.effective_version();
                            if record_version <= 0x0303 {
                                let walked = record_walk::walk_records(capture.payload_slice());
                                for walked_record in &walked.records {
                                    let handshake_type = if walked_record.body.is_empty() {
                                        0x00
                                    } else {
                                        walked_record.body[0]
                                    };
                                    // Track CertificateRequest BEFORE ServerHello negotiation.
                                    if handshake_type == 0x0D {
                                        correlator.on_certificate_request(conn_key);
                                    }
                                }
                            }

                            if let Some(negotiation) =
                                correlator.on_server_hello(conn_key, &analysis_parsed)
                            {
                                analysis.negotiation = Some(negotiation);
                            } else {
                                correlator_sh_without_ch_worker.fetch_add(1, Ordering::Relaxed);
                            }

                            // Emit synthesized events for walked Certificate and CertificateRequest records.
                            if record_version <= 0x0303 {
                                let walked = record_walk::walk_records(capture.payload_slice());
                                for walked_record in walked.records {
                                    let (mut synth_event, handshake_type) =
                                        record_walk::synthesize_event_from_walked_record(
                                            &capture,
                                            &walked_record,
                                        );

                                    // Parse certificate if Certificate record (0x0B).
                                    if handshake_type == 0x0B {
                                        // Skip handshake header (1 byte type + 3 byte length).
                                        if walked_record.body.len() > 4 {
                                            let cert_payload = &walked_record.body[4..];
                                            if let Some(cert) =
                                                crate::certificate::parse_certificate(cert_payload)
                                            {
                                                synth_event.certificate = Some(cert);
                                            }
                                        }
                                    }

                                    // Enrich with cgroup and container attribution.
                                    synth_event = crate::tls::enrich_with_cgroup(
                                        synth_event,
                                        &capture,
                                        resolver.as_ref(),
                                    );

                                    if verbose_events {
                                        debug!(
                                            "walked {}: {} -> {}, {}",
                                            synth_event.handshake_type,
                                            synth_event.src,
                                            synth_event.dst,
                                            synth_event.tls_version
                                        );
                                    }

                                    let mut line =
                                        serde_json::to_vec(&synth_event).unwrap_or_default();
                                    line.push(b'\n');
                                    if writer_tx_worker.send(line).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    } else if (capture.flags & FLAG_ALERT) != 0 {
                        // Alert record: try to join with a pending ClientHello.
                        if let Some((level, description)) =
                            crate::tls::parse_alert(capture.payload_slice())
                        {
                            if let Some(negotiation) =
                                correlator.on_alert(conn_key, level, description)
                            {
                                analysis.negotiation = Some(negotiation);
                            } else {
                                // Alert without matching CH: drop it and count.
                                alerts_dropped_worker.fetch_add(1, Ordering::Relaxed);
                            }
                        } else {
                            // Malformed alert: drop and count.
                            alerts_dropped_worker.fetch_add(1, Ordering::Relaxed);
                        }
                    } else if capture.handshake_type == 0x0B {
                        // Certificate message: parse and track mTLS state.
                        // Determine if client-sent (ingress, FLAG_INGRESS) or server-sent (egress, no FLAG_INGRESS).
                        let is_client = (capture.flags & tls_probe_common::FLAG_INGRESS) != 0;

                        // Try to parse the leaf certificate.
                        // Skip handshake header (1 byte type + 3 byte length) in payload.
                        let payload = capture.payload_slice();
                        if payload.len() > 4 {
                            let cert_payload = &payload[4..];
                            if let Some(cert) = crate::certificate::parse_certificate(cert_payload)
                            {
                                analysis.certificate = Some(cert);
                            }
                        }

                        // Track mTLS: client-sent Certificate implies mTLS. The
                        // completed-mTLS negotiation rides this event (the SH
                        // was already emitted before the client cert existed).
                        if is_client {
                            if let Some(neg) = correlator.on_client_certificate(conn_key) {
                                analysis.negotiation = Some(neg);
                            }
                        }

                        // TLS 1.3: drop Certificate handshake (kernel already captures everything).
                        if let Ok(analysis_parsed) =
                            tls_probe_parser::parse_tls_payload(capture.payload_slice(), is_client)
                        {
                            let version = analysis_parsed.effective_version();
                            if version == 0x0304 {
                                certs_dropped_13_worker.fetch_add(1, Ordering::Relaxed);
                                // Skip emitting this event and jump to sweep logic.
                                continue;
                            }
                        }
                    } else if capture.handshake_type == 0x0D {
                        // CertificateRequest message: track mTLS state.
                        correlator.on_certificate_request(conn_key);

                        // TLS 1.3: drop CertificateRequest (kernel already captures everything).
                        if let Ok(analysis_parsed) =
                            tls_probe_parser::parse_tls_payload(capture.payload_slice(), false)
                        {
                            let version = analysis_parsed.effective_version();
                            if version == 0x0304 {
                                certs_dropped_13_worker.fetch_add(1, Ordering::Relaxed);
                                // Skip emitting this event and jump to sweep logic.
                                continue;
                            }
                        }
                    }

                    // Enrich with cgroup and container attribution.
                    analysis =
                        crate::tls::enrich_with_cgroup(analysis, &capture, resolver.as_ref());

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
                // Else: fragment or continuation waiting for more — do nothing, loop continues.

                // Sweep expired reassemblies and correlator state periodically (every 500 captures = ~50ms @ 10K Hz).
                timeout_counter = timeout_counter.wrapping_add(1);
                if timeout_counter.is_multiple_of(500) {
                    let _ = correlator.sweep_expired();
                    let expired = reassembler.sweep_expired();
                    for expired_rec in expired {
                        // Parse the expired (truncated) record from the head_capture and assembled buffer.
                        let mut event = analyze_capture_with_payload(
                            &expired_rec.head_capture,
                            &expired_rec.buffer,
                        );
                        event.reassembled = Some(true);
                        event.truncated = Some(expired_rec.truncated);

                        // Enrich with cgroup and container attribution.
                        event = crate::tls::enrich_with_cgroup(
                            event,
                            &expired_rec.head_capture,
                            resolver.as_ref(),
                        );

                        if verbose_events {
                            debug!(
                                "{}: {} -> {}, {}, {} ciphers{} [reassembled: {}, truncated: {}]",
                                event.handshake_type,
                                event.src,
                                event.dst,
                                event.tls_version,
                                event.cipher_suites.len(),
                                event
                                    .sni
                                    .as_ref()
                                    .map(|s| format!(" ({s})"))
                                    .unwrap_or_default(),
                                event.reassembled.unwrap_or(false),
                                event.truncated.unwrap_or(false)
                            );
                        }

                        let mut line = serde_json::to_vec(&event).unwrap_or_default();
                        line.push(b'\n');
                        if writer_tx_worker.send(line).await.is_err() {
                            break;
                        }
                    }
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
                    "counters: emitted={} dropped={} kernel_lost={} chunks_evicted={} correlator_sh_without_ch={} alerts_dropped={} certs_dropped_13={}",
                    events_emitted.load(Ordering::Relaxed),
                    events_dropped.load(Ordering::Relaxed),
                    kernel_lost,
                    chunks_evicted.load(Ordering::Relaxed),
                    correlator_sh_without_ch.load(Ordering::Relaxed),
                    alerts_dropped.load(Ordering::Relaxed),
                    certs_dropped_13.load(Ordering::Relaxed)
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
            "counters: emitted={} dropped={} kernel_lost={} chunks_evicted={} correlator_sh_without_ch={} alerts_dropped={} certs_dropped_13={}",
            events_emitted.load(Ordering::Relaxed),
            events_dropped.load(Ordering::Relaxed),
            kernel_lost,
            chunks_evicted.load(Ordering::Relaxed),
            correlator_sh_without_ch.load(Ordering::Relaxed),
            alerts_dropped.load(Ordering::Relaxed),
            certs_dropped_13.load(Ordering::Relaxed)
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
