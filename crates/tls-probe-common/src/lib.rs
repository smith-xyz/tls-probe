#![cfg_attr(not(feature = "user"), no_std)]

#[cfg(feature = "user")]
extern crate std;

pub mod codes;
pub mod domains;

pub use domains::process::{ConnInfo, ConnKey, COMM_SIZE};
pub use domains::tls::{
    RawTlsCapture, ReasmKey, ReasmState, FLAG_ALERT, FLAG_CONTINUATION, FLAG_FRAGMENT,
    FLAG_INGRESS, MAX_REASM_SEGMENTS, RAW_CAPTURE_HEADER_SIZE, RAW_PAYLOAD_SIZE,
    TLS_HANDSHAKE_CERTIFICATE, TLS_HANDSHAKE_CERTIFICATE_REQUEST, TLS_HANDSHAKE_CLIENT_HELLO,
    TLS_HANDSHAKE_SERVER_HELLO,
};

// Re-export frequently-used codes and predicates
pub use codes::{
    is_client_hello, is_grease, is_pqc_group, is_pqc_sig_alg, is_server_hello, CONTENT_TYPE_ALERT,
    CONTENT_TYPE_HANDSHAKE, HANDSHAKE_CLIENT_HELLO as CODES_HANDSHAKE_CLIENT_HELLO,
    HANDSHAKE_SERVER_HELLO as CODES_HANDSHAKE_SERVER_HELLO,
};
