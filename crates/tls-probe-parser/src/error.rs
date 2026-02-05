use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("payload too short")]
    TooShort,

    #[error("invalid TLS record")]
    InvalidRecord,

    #[error("invalid handshake type")]
    InvalidHandshakeType,

    #[error("unexpected end of data at offset {0}")]
    UnexpectedEnd(usize),

    #[error("invalid extension data")]
    InvalidExtension,
}
