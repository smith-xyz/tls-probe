use anyhow::Result;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

/// Initializes the global tracing subscriber with the specified log level.
/// Diagnostics are written to stderr, while the main output is expected to be captured separately.
pub(crate) fn init(level: Level) -> Result<()> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .with_writer(std::io::stderr)
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::pipeline::run_writer_thread;

    const CHILD_ENV: &str = "TLS_PROBE_STDOUT_LOGGING_TEST_CHILD";
    const TEST_NAME: &str = "logging::tests::stdout_capture_keeps_diagnostics_on_stderr";
    const TIMEOUT: Duration = Duration::from_secs(5);
    const POLL_INTERVAL: Duration = Duration::from_millis(10);
    const EVENT: &str = "{\"probe_event\":1}\n";
    const DIAGNOSTIC: &str = "capture task status";
    const READY: &str = "writer processed event; calling info!";

    // Kill and reap even if polling or an assertion unexpectedly panics.
    struct ChildGuard(Option<Child>);

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if let Some(child) = self.0.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    fn run_child() -> ! {
        // Use exactly the initialization called by main, not a test-only subscriber.
        init(Level::INFO).expect("initialize production logging");
        let emitted = Arc::new(AtomicU64::new(0));
        let writer_emitted = Arc::clone(&emitted);
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let writer = thread::spawn(move || run_writer_thread(rx, None, true, writer_emitted));
        tx.blocking_send(EVENT.as_bytes().to_vec())
            .expect("send event");

        // An emitted event proves the writer has acquired and still holds stdout's lock.
        let start = Instant::now();
        while emitted.load(Ordering::Relaxed) == 0 {
            assert!(start.elapsed() < TIMEOUT, "writer never processed event");
            thread::sleep(POLL_INTERVAL);
        }
        eprintln!("{READY}");
        tracing::info!("{DIAGNOSTIC}");
        drop(tx);
        writer.join().expect("writer shuts down after logging");

        // Avoid libtest's trailing status text so stdout contains only its banner and JSONL.
        std::process::exit(0);
    }

    #[test]
    fn stdout_capture_keeps_diagnostics_on_stderr() {
        if std::env::var_os(CHILD_ENV).is_some() {
            run_child();
        }

        let mut guard = ChildGuard(Some(
            Command::new(std::env::current_exe().expect("test executable"))
                .args(["--exact", TEST_NAME, "--nocapture", "--quiet"])
                .env(CHILD_ENV, "1")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn isolated regression child"),
        ));
        let child = guard.0.as_mut().expect("child exists");
        let start = Instant::now();
        let timed_out = loop {
            if child.try_wait().expect("poll child").is_some() {
                break false;
            }
            if start.elapsed() >= TIMEOUT {
                child.kill().expect("kill deadlocked child");
                break true;
            }
            thread::sleep(POLL_INTERVAL);
        };
        // Output is deliberately tiny (one event and diagnostic), so pipes cannot fill.
        let output = guard
            .0
            .take()
            .expect("child exists")
            .wait_with_output()
            .expect("reap child");
        let stdout = String::from_utf8(output.stdout).expect("UTF-8 stdout");
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
        assert!(
            !timed_out,
            "child timed out after {TIMEOUT:?}; stdout: {stdout:?}; stderr: {stderr:?}"
        );
        assert!(
            output.status.success(),
            "child failed: {:?}; stderr: {stderr}",
            output.status
        );
        assert!(
            stderr.contains(READY),
            "child did not exercise the writer: {stderr}"
        );
        assert!(
            stderr.contains(DIAGNOSTIC),
            "diagnostic missing from stderr: {stderr}"
        );
        // Ignore only libtest's known preamble; all application stdout must be JSONL.
        let jsonl = stdout
            .trim_start()
            .strip_prefix("running 1 test\n")
            .expect("libtest banner");
        assert_eq!(jsonl, EVENT, "stdout must contain only the capture event");
        assert!(
            !stderr.contains(EVENT.trim()),
            "capture event leaked to stderr"
        );
    }
}
