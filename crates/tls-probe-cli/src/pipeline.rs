//! Emit pipeline helpers: buffered writer flush policy and drop accounting.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tracing::warn;

pub const FLUSH_THRESHOLD: usize = 64 * 1024;
pub const FLUSH_INTERVAL: Duration = Duration::from_millis(250);
pub const WRITE_CHANNEL_CAPACITY: usize = 256;
pub const COUNTER_LOG_INTERVAL: Duration = Duration::from_secs(5);
pub const WRITER_POLL_SLEEP: Duration = Duration::from_millis(1);

const CHUNK_PREFIX: &str = "capture-";
const CHUNK_SUFFIX: &str = ".jsonl";
const CHUNK_PART_SUFFIX: &str = ".jsonl.part";

/// Tracks pending output bytes and decides when to flush a [`BufWriter`].
pub struct BufferedLineWriter<W: Write> {
    inner: BufWriter<W>,
    pending_bytes: usize,
    last_flush: Instant,
}

impl<W: Write> BufferedLineWriter<W> {
    pub fn new(writer: W) -> Self {
        Self {
            inner: BufWriter::new(writer),
            pending_bytes: 0,
            last_flush: Instant::now(),
        }
    }

    pub fn write_line(&mut self, line: &[u8]) -> io::Result<()> {
        self.inner.write_all(line)?;
        self.pending_bytes += line.len();
        Ok(())
    }

    pub fn should_flush(&self) -> bool {
        self.pending_bytes > 0
            && (self.pending_bytes >= FLUSH_THRESHOLD
                || self.last_flush.elapsed() >= FLUSH_INTERVAL)
    }

    pub fn flush_if_needed(&mut self) -> io::Result<bool> {
        if self.should_flush() {
            self.inner.flush()?;
            self.pending_bytes = 0;
            self.last_flush = Instant::now();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn force_flush(&mut self) -> io::Result<()> {
        if self.pending_bytes > 0 {
            self.inner.flush()?;
            self.pending_bytes = 0;
            self.last_flush = Instant::now();
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn pending_bytes(&self) -> usize {
        self.pending_bytes
    }

    #[cfg(test)]
    pub(crate) fn set_last_flush_for_test(&mut self, instant: Instant) {
        self.last_flush = instant;
    }
}

fn current_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn chunk_paths(output_dir: &Path, ts: u64) -> (PathBuf, PathBuf) {
    let complete_path = output_dir.join(format!("{CHUNK_PREFIX}{ts}{CHUNK_SUFFIX}"));
    let part_path = output_dir.join(format!("{CHUNK_PREFIX}{ts}{CHUNK_PART_SUFFIX}"));
    (part_path, complete_path)
}

fn parse_complete_chunk_timestamp(path: &Path) -> Option<u64> {
    let name = path.file_name()?.to_str()?;
    let stem = name.strip_suffix(CHUNK_SUFFIX)?;
    stem.strip_prefix(CHUNK_PREFIX)?.parse().ok()
}

/// Bounded spool writer: rotates chunks at a byte threshold and evicts oldest complete chunks.
pub struct RotatingSpoolWriter {
    output_dir: PathBuf,
    max_chunk_bytes: u64,
    max_total_bytes: Option<u64>,
    current_writer: BufferedLineWriter<File>,
    current_part_path: PathBuf,
    current_complete_path: PathBuf,
    current_bytes: u64,
    chunks_evicted: Arc<AtomicU64>,
}

impl RotatingSpoolWriter {
    /// Opens the first `.part` chunk in `output_dir`, creating the directory if needed.
    pub fn new(
        output_dir: PathBuf,
        max_chunk_bytes: u64,
        max_total_bytes: Option<u64>,
        chunks_evicted: Arc<AtomicU64>,
    ) -> io::Result<Self> {
        fs::create_dir_all(&output_dir)?;
        let ts = current_timestamp_secs();
        let (part_path, complete_path) = chunk_paths(&output_dir, ts);
        let file = File::create(&part_path)?;
        Ok(Self {
            output_dir,
            max_chunk_bytes,
            max_total_bytes,
            current_writer: BufferedLineWriter::new(file),
            current_part_path: part_path,
            current_complete_path: complete_path,
            current_bytes: 0,
            chunks_evicted,
        })
    }

    pub fn write_line(&mut self, line: &[u8]) -> io::Result<()> {
        self.current_writer.write_line(line)?;
        self.current_bytes += line.len() as u64;
        if self.current_bytes >= self.max_chunk_bytes {
            self.rotate()?;
        }
        Ok(())
    }

    pub fn flush_if_needed(&mut self) -> io::Result<bool> {
        self.current_writer.flush_if_needed()
    }

    fn rotate(&mut self) -> io::Result<()> {
        self.current_writer.force_flush()?;
        fs::rename(&self.current_part_path, &self.current_complete_path)?;
        self.current_bytes = 0;

        if let Some(max_total) = self.max_total_bytes {
            self.enforce_cap(max_total)?;
        }

        let ts = current_timestamp_secs();
        let (part_path, complete_path) = chunk_paths(&self.output_dir, ts);
        let file = File::create(&part_path)?;
        self.current_writer = BufferedLineWriter::new(file);
        self.current_part_path = part_path;
        self.current_complete_path = complete_path;
        Ok(())
    }

    fn list_complete_chunks(&self) -> io::Result<Vec<(u64, u64, PathBuf)>> {
        let mut chunks = Vec::new();
        for entry in fs::read_dir(&self.output_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
                continue;
            }
            let Some(ts) = parse_complete_chunk_timestamp(&path) else {
                continue;
            };
            let size = entry.metadata()?.len();
            chunks.push((ts, size, path));
        }
        Ok(chunks)
    }

    fn enforce_cap(&mut self, max_total: u64) -> io::Result<()> {
        let mut chunks = self.list_complete_chunks()?;
        chunks.sort_by_key(|c| c.0);

        let total: u64 = chunks.iter().map(|c| c.1).sum();
        if total <= max_total {
            return Ok(());
        }

        let mut excess = total - max_total;
        for (_, size, path) in &chunks {
            if excess == 0 {
                break;
            }
            warn!(
                "spool cap exceeded: evicting oldest chunk {:?} ({} bytes)",
                path, size
            );
            fs::remove_file(path)?;
            self.chunks_evicted.fetch_add(1, Ordering::Relaxed);
            excess = excess.saturating_sub(*size);
        }
        Ok(())
    }

    /// Flushes the active chunk and atomically renames `.part` to complete.
    pub fn finalize(mut self) -> io::Result<()> {
        self.current_writer.force_flush()?;
        if self.current_part_path.exists() {
            fs::rename(&self.current_part_path, &self.current_complete_path)?;
        }
        Ok(())
    }
}

/// File output backend: plain single file or rotating spool.
pub enum WriterBackend {
    Plain(BufferedLineWriter<File>),
    Spool(RotatingSpoolWriter),
}

impl WriterBackend {
    fn write_line(&mut self, line: &[u8]) -> io::Result<()> {
        match self {
            Self::Plain(w) => w.write_line(line),
            Self::Spool(w) => w.write_line(line),
        }
    }

    fn flush_if_needed(&mut self) -> io::Result<bool> {
        match self {
            Self::Plain(w) => w.flush_if_needed(),
            Self::Spool(w) => w.flush_if_needed(),
        }
    }

    fn finalize(self) -> io::Result<()> {
        match self {
            Self::Plain(mut w) => w.force_flush(),
            Self::Spool(w) => w.finalize(),
        }
    }
}

/// Runs the dedicated writer thread loop: receives JSONL lines and writes with batched flush.
pub fn run_writer_thread(
    mut writer_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    file_backend: Option<WriterBackend>,
    emit_to_stdout: bool,
    events_emitted: Arc<AtomicU64>,
) {
    let stdout = std::io::stdout();
    let mut file_writer = file_backend;
    let mut stdout_writer = if emit_to_stdout {
        Some(BufferedLineWriter::new(stdout.lock()))
    } else {
        None
    };

    loop {
        match writer_rx.try_recv() {
            Ok(line) => {
                if let Some(w) = file_writer.as_mut() {
                    let _ = w.write_line(&line);
                    let _ = w.flush_if_needed();
                }
                if let Some(w) = stdout_writer.as_mut() {
                    let _ = w.write_line(&line);
                    let _ = w.flush_if_needed();
                }
                events_emitted.fetch_add(1, Ordering::Relaxed);
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                if let Some(w) = file_writer.as_mut() {
                    let _ = w.flush_if_needed();
                }
                if let Some(w) = stdout_writer.as_mut() {
                    let _ = w.flush_if_needed();
                }
                std::thread::sleep(WRITER_POLL_SLEEP);
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                break;
            }
        }
    }

    if let Some(w) = file_writer {
        let _ = w.finalize();
    }
    if let Some(mut w) = stdout_writer {
        let _ = w.force_flush();
    }
}

/// Sums per-CPU ringbuf drop counters from the eBPF map.
#[cfg(target_os = "linux")]
pub fn sum_kernel_drops(map: Option<&aya::maps::PerCpuArray<aya::maps::MapData, u64>>) -> u64 {
    map.and_then(|m| m.get(&0, 0).ok())
        .map(|values| values.iter().sum())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use tls_probe_common::RawTlsCapture;
    use tokio::sync::mpsc;
    use tokio::sync::mpsc::error::TrySendError;

    fn temp_spool_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("tls-probe-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn complete_chunks(dir: &Path) -> Vec<PathBuf> {
        fs::read_dir(dir)
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("jsonl"))
            .collect()
    }

    fn part_chunks(dir: &Path) -> Vec<PathBuf> {
        fs::read_dir(dir)
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("part"))
            .collect()
    }

    #[tokio::test]
    async fn saturated_channel_increments_drop_counter() {
        let (tx, _rx) = mpsc::channel::<RawTlsCapture>(1);
        let drops = Arc::new(AtomicU64::new(0));

        tx.try_send(RawTlsCapture::default())
            .expect("first send fits");

        for _ in 0..2 {
            match tx.try_send(RawTlsCapture::default()) {
                Ok(()) => panic!("expected channel full"),
                Err(TrySendError::Full(_)) => {
                    drops.fetch_add(1, Ordering::Relaxed);
                }
                Err(TrySendError::Closed(_)) => panic!("unexpected closed channel"),
            }
        }

        assert_eq!(drops.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn flush_on_threshold() {
        let mut writer = BufferedLineWriter::new(Cursor::new(Vec::new()));
        let line = vec![b'x'; FLUSH_THRESHOLD];
        writer.write_line(&line).expect("write");
        assert!(writer.should_flush());
        assert!(writer.flush_if_needed().expect("flush"));
        assert_eq!(writer.pending_bytes(), 0);
    }

    #[test]
    fn flush_on_tick() {
        let mut writer = BufferedLineWriter::new(Cursor::new(Vec::new()));
        writer.write_line(b"small\n").expect("write");
        assert!(!writer.should_flush());

        writer.set_last_flush_for_test(Instant::now() - FLUSH_INTERVAL - Duration::from_millis(1));
        assert!(writer.should_flush());
        assert!(writer.flush_if_needed().expect("flush"));
        assert_eq!(writer.pending_bytes(), 0);
    }

    #[test]
    fn writer_thread_emits_and_flushes() {
        let (tx, rx) = mpsc::channel(4);
        let emitted = Arc::new(AtomicU64::new(0));
        let emitted_join = emitted.clone();

        let handle = std::thread::spawn(move || {
            run_writer_thread(rx, None, false, emitted_join);
        });

        tx.blocking_send(b"{\"a\":1}\n".to_vec()).expect("send");
        drop(tx);
        handle.join().expect("writer join");

        assert_eq!(emitted.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn rotation_triggers_chunk_rename() {
        let dir = temp_spool_dir("rotation");
        let evicted = Arc::new(AtomicU64::new(0));
        let mut writer =
            RotatingSpoolWriter::new(dir.clone(), 10, None, evicted).expect("new spool");

        writer.write_line(b"0123456789\n").expect("first line");
        writer.write_line(b"more\n").expect("rotate line");

        assert_eq!(complete_chunks(&dir).len(), 1);
        assert_eq!(part_chunks(&dir).len(), 1);
        assert!(complete_chunks(&dir)[0]
            .to_string_lossy()
            .ends_with(".jsonl"));
        assert!(!complete_chunks(&dir)[0].to_string_lossy().contains(".part"));

        writer.finalize().expect("finalize");
        assert_eq!(part_chunks(&dir).len(), 0);
        assert!(!complete_chunks(&dir).is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cap_enforcement_evicts_oldest_chunks() {
        let dir = temp_spool_dir("cap");
        let evicted = Arc::new(AtomicU64::new(0));

        for ts in [100_u64, 200, 300] {
            let path = dir.join(format!("capture-{ts}.jsonl"));
            fs::create_dir_all(&dir).expect("mkdir");
            fs::write(&path, vec![b'x'; 100]).expect("seed chunk");
        }

        let mut writer = RotatingSpoolWriter::new(dir.clone(), 1000, Some(250), evicted.clone())
            .expect("new spool");
        writer.enforce_cap(250).expect("enforce");

        let remaining: Vec<u64> = complete_chunks(&dir)
            .iter()
            .filter_map(|p| parse_complete_chunk_timestamp(p))
            .collect();
        assert!(!remaining.contains(&100));
        assert!(remaining.contains(&200) || remaining.contains(&300));
        assert!(evicted.load(Ordering::Relaxed) >= 1);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn finalize_renames_part_to_complete() {
        let dir = temp_spool_dir("finalize");
        let evicted = Arc::new(AtomicU64::new(0));
        let mut writer =
            RotatingSpoolWriter::new(dir.clone(), 1000, None, evicted).expect("new spool");

        let part_before = part_chunks(&dir);
        assert_eq!(part_before.len(), 1);

        writer.write_line(b"data\n").expect("write");
        writer.finalize().expect("finalize");

        assert_eq!(part_chunks(&dir).len(), 0);
        assert_eq!(complete_chunks(&dir).len(), 1);

        let _ = fs::remove_dir_all(&dir);
    }
}
