mod client_hello;
mod error;
mod extensions;
mod server_hello;
mod types;

pub use client_hello::parse_client_hello;
pub use error::ParseError;
pub use extensions::{Extension, ExtensionType};
pub use server_hello::parse_server_hello;
pub use types::{ParsedClientHello, ParsedServerHello, TlsVersion};

const TLS_RECORD_HDR_LEN: usize = 5;
const TLS_HANDSHAKE_HDR_LEN: usize = 4;
const TLS_RANDOM_LEN: usize = 32;

pub fn parse_tls_payload(payload: &[u8], is_client_hello: bool) -> Result<TlsAnalysis, ParseError> {
    if payload.len() < TLS_RECORD_HDR_LEN + TLS_HANDSHAKE_HDR_LEN {
        return Err(ParseError::TooShort);
    }

    let record_version = u16::from_be_bytes([payload[1], payload[2]]);

    if is_client_hello {
        let hello = parse_client_hello(payload)?;
        Ok(TlsAnalysis::ClientHello {
            record_version,
            hello,
        })
    } else {
        let hello = parse_server_hello(payload)?;
        Ok(TlsAnalysis::ServerHello {
            record_version,
            hello,
        })
    }
}

#[derive(Debug, Clone)]
pub enum TlsAnalysis {
    ClientHello {
        record_version: u16,
        hello: ParsedClientHello,
    },
    ServerHello {
        record_version: u16,
        hello: ParsedServerHello,
    },
}

impl TlsAnalysis {
    pub fn effective_version(&self) -> u16 {
        match self {
            TlsAnalysis::ClientHello {
                hello,
                record_version,
            } => hello
                .supported_versions
                .first()
                .copied()
                .unwrap_or(*record_version),
            TlsAnalysis::ServerHello { hello, .. } => {
                hello.negotiated_version.unwrap_or(hello.legacy_version)
            }
        }
    }

    pub fn cipher_suites(&self) -> &[u16] {
        match self {
            TlsAnalysis::ClientHello { hello, .. } => &hello.cipher_suites,
            TlsAnalysis::ServerHello { hello, .. } => std::slice::from_ref(&hello.cipher_suite),
        }
    }

    pub fn key_exchange_groups(&self) -> &[u16] {
        match self {
            TlsAnalysis::ClientHello { hello, .. } => &hello.supported_groups,
            TlsAnalysis::ServerHello { hello, .. } => hello.key_share_group.as_slice(),
        }
    }

    pub fn signature_algorithms(&self) -> &[u16] {
        match self {
            TlsAnalysis::ClientHello { hello, .. } => &hello.signature_algorithms,
            TlsAnalysis::ServerHello { .. } => &[],
        }
    }

    pub fn sni(&self) -> Option<&str> {
        match self {
            TlsAnalysis::ClientHello { hello, .. } => hello.sni.as_deref(),
            TlsAnalysis::ServerHello { .. } => None,
        }
    }

    pub fn is_client_hello(&self) -> bool {
        matches!(self, TlsAnalysis::ClientHello { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_client_hello() -> Vec<u8> {
        let mut payload = Vec::new();

        payload.extend_from_slice(&[0x16, 0x03, 0x01]);
        let length_pos = payload.len();
        payload.extend_from_slice(&[0x00, 0x00]);

        payload.push(0x01);
        let hs_length_pos = payload.len();
        payload.extend_from_slice(&[0x00, 0x00, 0x00]);

        let hello_start = payload.len();
        payload.extend_from_slice(&[0x03, 0x03]);
        payload.extend_from_slice(&[0u8; 32]);
        payload.push(0x00);
        payload.extend_from_slice(&[0x00, 0x06]);
        payload.extend_from_slice(&[0x13, 0x01, 0x13, 0x02, 0x13, 0x03]);
        payload.extend_from_slice(&[0x01, 0x00]);

        let ext_start = payload.len();
        payload.extend_from_slice(&[0x00, 0x00]);

        payload.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
        payload.extend_from_slice(&[0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d]);

        let ext_len = (payload.len() - ext_start - 2) as u16;
        payload[ext_start] = (ext_len >> 8) as u8;
        payload[ext_start + 1] = ext_len as u8;

        let hs_len = (payload.len() - hello_start) as u32;
        payload[hs_length_pos] = ((hs_len >> 16) & 0xFF) as u8;
        payload[hs_length_pos + 1] = ((hs_len >> 8) & 0xFF) as u8;
        payload[hs_length_pos + 2] = (hs_len & 0xFF) as u8;

        let record_len = (payload.len() - 5) as u16;
        payload[length_pos] = (record_len >> 8) as u8;
        payload[length_pos + 1] = record_len as u8;

        payload
    }

    fn build_server_hello() -> Vec<u8> {
        let mut payload = Vec::new();

        payload.extend_from_slice(&[0x16, 0x03, 0x03]);
        let length_pos = payload.len();
        payload.extend_from_slice(&[0x00, 0x00]);

        payload.push(0x02);
        let hs_length_pos = payload.len();
        payload.extend_from_slice(&[0x00, 0x00, 0x00]);

        let hello_start = payload.len();
        payload.extend_from_slice(&[0x03, 0x03]);
        payload.extend_from_slice(&[0u8; 32]);
        payload.push(0x00);
        payload.extend_from_slice(&[0x13, 0x01]);
        payload.push(0x00);

        let ext_start = payload.len();
        payload.extend_from_slice(&[0x00, 0x00]);

        payload.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
        payload.extend_from_slice(&[0x00, 0x33, 0x00, 0x02, 0x00, 0x1d]);

        let ext_len = (payload.len() - ext_start - 2) as u16;
        payload[ext_start] = (ext_len >> 8) as u8;
        payload[ext_start + 1] = ext_len as u8;

        let hs_len = (payload.len() - hello_start) as u32;
        payload[hs_length_pos] = ((hs_len >> 16) & 0xFF) as u8;
        payload[hs_length_pos + 1] = ((hs_len >> 8) & 0xFF) as u8;
        payload[hs_length_pos + 2] = (hs_len & 0xFF) as u8;

        let record_len = (payload.len() - 5) as u16;
        payload[length_pos] = (record_len >> 8) as u8;
        payload[length_pos + 1] = record_len as u8;

        payload
    }

    #[test]
    fn parse_client_hello_basic() {
        let payload = build_client_hello();
        let result = parse_tls_payload(&payload, true);
        assert!(result.is_ok(), "Parse failed: {:?}", result.err());

        let analysis = result.unwrap();
        assert!(analysis.is_client_hello());
        assert_eq!(analysis.effective_version(), 0x0304);
        assert_eq!(analysis.cipher_suites(), &[0x1301, 0x1302, 0x1303]);
        assert_eq!(analysis.key_exchange_groups(), &[0x001d]);
    }

    #[test]
    fn parse_server_hello_basic() {
        let payload = build_server_hello();
        let result = parse_tls_payload(&payload, false);
        assert!(result.is_ok(), "Parse failed: {:?}", result.err());

        let analysis = result.unwrap();
        assert!(!analysis.is_client_hello());
        assert_eq!(analysis.effective_version(), 0x0304);
        assert_eq!(analysis.cipher_suites(), &[0x1301]);
        assert_eq!(analysis.key_exchange_groups(), &[0x001d]);
    }

    #[test]
    fn parse_too_short() {
        let payload = vec![0x16, 0x03, 0x01, 0x00];
        let result = parse_tls_payload(&payload, true);
        assert!(result.is_err());
    }

    #[test]
    fn client_hello_extracts_versions() {
        let payload = build_client_hello();
        let result = parse_client_hello(&payload).unwrap();
        assert_eq!(result.supported_versions, vec![0x0304]);
    }

    #[test]
    fn client_hello_extracts_groups() {
        let payload = build_client_hello();
        let result = parse_client_hello(&payload).unwrap();
        assert_eq!(result.supported_groups, vec![0x001d]);
    }

    #[test]
    fn server_hello_extracts_cipher() {
        let payload = build_server_hello();
        let result = parse_server_hello(&payload).unwrap();
        assert_eq!(result.cipher_suite, 0x1301);
    }

    #[test]
    fn server_hello_extracts_key_share() {
        let payload = build_server_hello();
        let result = parse_server_hello(&payload).unwrap();
        assert_eq!(result.key_share_group, Some(0x001d));
    }

    #[test]
    fn server_hello_extracts_negotiated_version() {
        let payload = build_server_hello();
        let result = parse_server_hello(&payload).unwrap();
        assert_eq!(result.negotiated_version, Some(0x0304));
    }

    #[test]
    fn client_hello_legacy_version() {
        let payload = build_client_hello();
        let result = parse_client_hello(&payload).unwrap();
        assert_eq!(result.legacy_version, 0x0303);
    }

    #[test]
    fn server_hello_legacy_version() {
        let payload = build_server_hello();
        let result = parse_server_hello(&payload).unwrap();
        assert_eq!(result.legacy_version, 0x0303);
    }
}
