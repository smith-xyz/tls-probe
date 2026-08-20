mod client_hello;
mod error;
mod extensions;
mod server_hello;
mod types;

pub use client_hello::parse_client_hello;
pub use error::ParseError;
pub use extensions::{extract_alpn, Extension, ExtensionType};
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
            hello: Box::new(hello),
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
        hello: Box<ParsedClientHello>,
    },
    ServerHello {
        record_version: u16,
        hello: ParsedServerHello,
    },
}

impl TlsAnalysis {
    pub fn effective_version(&self) -> u16 {
        match self {
            TlsAnalysis::ClientHello { hello, .. } => hello
                .supported_versions
                .first()
                .copied()
                .unwrap_or(hello.legacy_version),
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

    #[test]
    fn client_hello_without_supported_versions_falls_back_to_legacy() {
        let mut payload = Vec::new();

        // Record header: content_type=handshake, version=0x0301 (TLS 1.0 compat)
        payload.extend_from_slice(&[0x16, 0x03, 0x01]);
        let length_pos = payload.len();
        payload.extend_from_slice(&[0x00, 0x00]);

        // Handshake header: type=ClientHello
        payload.push(0x01);
        let hs_length_pos = payload.len();
        payload.extend_from_slice(&[0x00, 0x00, 0x00]);

        let hello_start = payload.len();
        // legacy_version = 0x0303 (TLS 1.2)
        payload.extend_from_slice(&[0x03, 0x03]);
        payload.extend_from_slice(&[0u8; 32]); // random
        payload.push(0x00); // session_id length = 0
        payload.extend_from_slice(&[0x00, 0x06]); // cipher suites length
        payload.extend_from_slice(&[0x13, 0x01, 0x13, 0x02, 0x13, 0x03]);
        payload.extend_from_slice(&[0x01, 0x00]); // compression

        // Extensions: only supported_groups, NO supported_versions
        let ext_start = payload.len();
        payload.extend_from_slice(&[0x00, 0x00]);
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

        let result = parse_tls_payload(&payload, true).unwrap();
        // Should fall back to legacy_version (0x0303 = TLS 1.2),
        // NOT record_version (0x0301 = TLS 1.0)
        assert_eq!(result.effective_version(), 0x0303);
    }

    #[test]
    fn parse_large_client_hello_with_ml_kem() {
        // Test parsing of an oversized ClientHello (~1700 bytes with ML-KEM key_share).
        let mut payload = Vec::new();

        payload.extend_from_slice(&[0x16, 0x03, 0x03]);
        let length_pos = payload.len();
        payload.extend_from_slice(&[0x00, 0x00]); // Placeholder for record length

        payload.push(0x01); // Handshake type: ClientHello
        let hs_length_pos = payload.len();
        payload.extend_from_slice(&[0x00, 0x00, 0x00]); // Placeholder for HS length

        let hello_start = payload.len();
        payload.extend_from_slice(&[0x03, 0x03]); // legacy_version = TLS 1.2
        payload.extend_from_slice(&[0u8; 32]); // random
        payload.push(0x00); // session_id length = 0

        // Cipher suites: include modern ones
        payload.extend_from_slice(&[0x00, 0x06]); // 3 suites
        payload.extend_from_slice(&[0x13, 0x01, 0x13, 0x02, 0x13, 0x03]); // TLS_AES_128_GCM_SHA256, etc.

        payload.extend_from_slice(&[0x01, 0x00]); // Compression (none)

        // Extensions
        let ext_start = payload.len();
        payload.extend_from_slice(&[0x00, 0x00]); // Placeholder for ext length

        // supported_versions extension
        payload.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);

        // supported_groups extension (basic)
        payload.extend_from_slice(&[0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d]);

        // key_share extension with large ML-KEM key (~1216 bytes)
        payload.extend_from_slice(&[0x00, 0x33]); // key_share extension type
        let ks_len_pos = payload.len();
        payload.extend_from_slice(&[0x00, 0x00]); // Placeholder for key_share length

        let ks_data_start = payload.len();
        payload.extend_from_slice(&[0x04, 0xc1]); // ML-KEM-768 (0x04c1)
        let ks_payload_len_pos = payload.len();
        payload.extend_from_slice(&[0x04, 0xb0]); // 1200 bytes (placeholder)

        // Fill with synthetic key material (simulating the large PQC key)
        payload.resize(payload.len() + 1200, 0x42);

        // Fix up the lengths
        let ks_payload_len = payload.len() - ks_data_start - 4;
        payload[ks_payload_len_pos] = ((ks_payload_len >> 8) & 0xFF) as u8;
        payload[ks_payload_len_pos + 1] = (ks_payload_len & 0xFF) as u8;

        let ks_total_len = payload.len() - ks_data_start;
        payload[ks_len_pos] = ((ks_total_len >> 8) & 0xFF) as u8;
        payload[ks_len_pos + 1] = (ks_total_len & 0xFF) as u8;

        // Extensions length
        let ext_len = payload.len() - ext_start - 2;
        payload[ext_start] = ((ext_len >> 8) & 0xFF) as u8;
        payload[ext_start + 1] = (ext_len & 0xFF) as u8;

        // Handshake length
        let hs_len = payload.len() - hello_start;
        payload[hs_length_pos] = ((hs_len >> 16) & 0xFF) as u8;
        payload[hs_length_pos + 1] = ((hs_len >> 8) & 0xFF) as u8;
        payload[hs_length_pos + 2] = (hs_len & 0xFF) as u8;

        // Record length
        let record_len = payload.len() - 5;
        payload[length_pos] = ((record_len >> 8) & 0xFF) as u8;
        payload[length_pos + 1] = (record_len & 0xFF) as u8;

        // Parse should succeed for the full buffer
        let result = parse_tls_payload(&payload, true);
        assert!(
            result.is_ok(),
            "Failed to parse large ClientHello: {:?}",
            result.err()
        );

        let analysis = result.unwrap();
        assert!(analysis.is_client_hello());
        assert_eq!(analysis.cipher_suites(), &[0x1301, 0x1302, 0x1303]);
    }

    #[test]
    fn parse_truncated_large_hello_gracefully_fails() {
        // Simulate a truncated large hello that would fail to parse.
        let mut payload = Vec::new();

        payload.extend_from_slice(&[0x16, 0x03, 0x03]);
        let length_pos = payload.len();
        payload.extend_from_slice(&[0x00, 0x00]);

        payload.push(0x01);
        let hs_length_pos = payload.len();
        payload.extend_from_slice(&[0x00, 0x05, 0x00]); // Claim 1280 bytes but only provide a bit

        let hello_start = payload.len();
        payload.extend_from_slice(&[0x03, 0x03]);
        payload.extend_from_slice(&[0u8; 32]);
        // Truncate before providing full payload

        let hs_len = payload.len() - hello_start;
        payload[hs_length_pos] = ((hs_len >> 16) & 0xFF) as u8;
        payload[hs_length_pos + 1] = ((hs_len >> 8) & 0xFF) as u8;
        payload[hs_length_pos + 2] = (hs_len & 0xFF) as u8;

        let record_len = payload.len() - 5;
        payload[length_pos] = ((record_len >> 8) & 0xFF) as u8;
        payload[length_pos + 1] = (record_len & 0xFF) as u8;

        // Parsing should fail gracefully (not panic)
        let result = parse_tls_payload(&payload, true);
        assert!(result.is_err(), "Should fail to parse truncated hello");
    }
}
