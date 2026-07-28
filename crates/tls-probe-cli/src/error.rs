use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProbeError {
    #[error("failed to load eBPF program: {0}")]
    LoadError(String),

    #[error("failed to attach probe: {0}")]
    AttachError(String),

    #[error("map not found: {0}")]
    MapNotFound(String),
}
