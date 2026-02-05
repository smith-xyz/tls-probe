use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProbeError {
    #[error("failed to load eBPF program: {0}")]
    LoadError(String),

    #[error("failed to attach probe: {0}")]
    AttachError(String),

    #[error("map not found: {0}")]
    MapNotFound(String),

    #[allow(dead_code)] // this is fine for now
    #[error("event processing error: {0}")]
    EventError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[cfg(target_os = "linux")]
    #[error("aya error: {0}")]
    Aya(#[from] aya::EbpfError),
}
