#![cfg_attr(all(test, not(target_os = "linux")), allow(dead_code))]

use serde::Serialize;
use tls_probe_common::{RawTlsCapture, TLS_HANDSHAKE_CLIENT_HELLO, TLS_HANDSHAKE_SERVER_HELLO};
use tls_probe_parser::{parse_tls_payload, TlsAnalysis as ParsedAnalysis};

#[derive(Debug, Clone, Serialize)]
pub struct TlsAnalysis {
    pub timestamp: String,
    pub src: String,
    pub dst: String,
    pub tls_version: String,
    pub handshake_type: &'static str,
    pub cipher_suites: Vec<CipherSuiteInfo>,
    pub key_exchange_groups: Vec<KeyExchangeInfo>,
    pub signature_algorithms: Vec<SignatureAlgorithmInfo>,
    pub key_share_group: Option<KeyExchangeInfo>,
    pub sni: Option<String>,
    pub pqc_ready: bool,
    pub pqc_groups: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CipherSuiteInfo {
    pub id: u16,
    pub name: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct KeyExchangeInfo {
    pub id: u16,
    pub name: &'static str,
    pub is_pqc: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SignatureAlgorithmInfo {
    pub id: u16,
    pub name: &'static str,
}

pub fn analyze_capture(capture: &RawTlsCapture) -> TlsAnalysis {
    let payload = capture.payload_slice();
    let is_client = capture.is_client_hello();

    let parsed = parse_tls_payload(payload, is_client);

    match parsed {
        Ok(analysis) => build_analysis(capture, &analysis),
        Err(_) => build_fallback_analysis(capture),
    }
}

fn build_analysis(capture: &RawTlsCapture, parsed: &ParsedAnalysis) -> TlsAnalysis {
    let cipher_suites: Vec<CipherSuiteInfo> = parsed
        .cipher_suites()
        .iter()
        .map(|&id| CipherSuiteInfo {
            id,
            name: cipher_suite_name(id),
        })
        .collect();

    let key_exchange_groups: Vec<KeyExchangeInfo> = parsed
        .key_exchange_groups()
        .iter()
        .map(|&id| KeyExchangeInfo {
            id,
            name: key_exchange_name(id),
            is_pqc: is_pqc_key_exchange(id),
        })
        .collect();

    let signature_algorithms: Vec<SignatureAlgorithmInfo> = parsed
        .signature_algorithms()
        .iter()
        .map(|&id| SignatureAlgorithmInfo {
            id,
            name: signature_algorithm_name(id),
        })
        .collect();

    let key_share_group = match parsed {
        ParsedAnalysis::ClientHello { hello, .. } => {
            hello.key_share_groups.first().map(|&id| KeyExchangeInfo {
                id,
                name: key_exchange_name(id),
                is_pqc: is_pqc_key_exchange(id),
            })
        }
        ParsedAnalysis::ServerHello { hello, .. } => {
            hello.key_share_group.map(|id| KeyExchangeInfo {
                id,
                name: key_exchange_name(id),
                is_pqc: is_pqc_key_exchange(id),
            })
        }
    };

    let pqc_groups: Vec<&'static str> = key_exchange_groups
        .iter()
        .filter(|g| g.is_pqc)
        .map(|g| g.name)
        .collect();

    let pqc_ready = !pqc_groups.is_empty() || key_share_group.as_ref().is_some_and(|g| g.is_pqc);

    let version = parsed.effective_version();
    let tls_version = tls_version_str(version);

    TlsAnalysis {
        timestamp: chrono::Utc::now().to_rfc3339(),
        src: format!("{}:{}", capture.src_addr_str(), capture.src_port),
        dst: format!("{}:{}", capture.dst_addr_str(), capture.dst_port),
        tls_version: tls_version.to_string(),
        handshake_type: handshake_type_name(capture.handshake_type),
        cipher_suites,
        key_exchange_groups,
        signature_algorithms,
        key_share_group,
        sni: parsed.sni().map(String::from),
        pqc_ready,
        pqc_groups,
    }
}

fn build_fallback_analysis(capture: &RawTlsCapture) -> TlsAnalysis {
    TlsAnalysis {
        timestamp: chrono::Utc::now().to_rfc3339(),
        src: format!("{}:{}", capture.src_addr_str(), capture.src_port),
        dst: format!("{}:{}", capture.dst_addr_str(), capture.dst_port),
        tls_version: tls_version_str(capture.record_version).to_string(),
        handshake_type: handshake_type_name(capture.handshake_type),
        cipher_suites: Vec::new(),
        key_exchange_groups: Vec::new(),
        signature_algorithms: Vec::new(),
        key_share_group: None,
        sni: None,
        pqc_ready: false,
        pqc_groups: Vec::new(),
    }
}

fn tls_version_str(version: u16) -> &'static str {
    match version {
        0x0304 => "TLS 1.3",
        0x0303 => "TLS 1.2",
        0x0302 => "TLS 1.1",
        0x0301 => "TLS 1.0",
        0x0300 => "SSL 3.0",
        _ => "Unknown",
    }
}

fn is_grease(value: u16) -> bool {
    let hi = (value >> 8) as u8;
    let lo = (value & 0xFF) as u8;
    hi == lo && (hi & 0x0F) == 0x0A
}

fn is_pqc_key_exchange(id: u16) -> bool {
    matches!(
        id,
        0x0200    // ML-KEM-512
        | 0x0201  // ML-KEM-768
        | 0x0202  // ML-KEM-1024
        | 0x2F00  // X25519MLKEM768
        | 0x2F01  // SecP256r1MLKEM768
        | 0x6399  // X25519Kyber768Draft00
        | 0x639A  // SecP256r1Kyber768Draft00
        | 0x4588 // X25519Kyber512Draft00
    )
}

fn key_exchange_name(id: u16) -> &'static str {
    if is_grease(id) {
        return "GREASE";
    }
    match id {
        0x0017 => "secp256r1",
        0x0018 => "secp384r1",
        0x0019 => "secp521r1",
        0x001D => "x25519",
        0x001E => "x448",
        0x0100 => "ffdhe2048",
        0x0101 => "ffdhe3072",
        0x0102 => "ffdhe4096",
        0x0103 => "ffdhe6144",
        0x0104 => "ffdhe8192",
        0x0200 => "ML-KEM-512",
        0x0201 => "ML-KEM-768",
        0x0202 => "ML-KEM-1024",
        0x2F00 => "X25519MLKEM768",
        0x2F01 => "SecP256r1MLKEM768",
        0x6399 => "X25519Kyber768Draft00",
        0x639A => "SecP256r1Kyber768Draft00",
        0x4588 => "X25519Kyber512Draft00",
        _ => "unknown",
    }
}

fn cipher_suite_name(id: u16) -> &'static str {
    if is_grease(id) {
        return "GREASE";
    }
    match id {
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        0x1304 => "TLS_AES_128_CCM_SHA256",
        0x1305 => "TLS_AES_128_CCM_8_SHA256",
        0xC02B => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xC02C => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xC02F => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xC030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xC023 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        0xC024 => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        0xC027 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        0xC028 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        0xC009 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        0xC00A => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        0xC013 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        0xC014 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        0xCCA8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        0xCCA9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        0x009C => "TLS_RSA_WITH_AES_128_GCM_SHA256",
        0x009D => "TLS_RSA_WITH_AES_256_GCM_SHA384",
        0x002F => "TLS_RSA_WITH_AES_128_CBC_SHA",
        0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA",
        0x003C => "TLS_RSA_WITH_AES_128_CBC_SHA256",
        0x003D => "TLS_RSA_WITH_AES_256_CBC_SHA256",
        _ => "unknown",
    }
}

fn signature_algorithm_name(id: u16) -> &'static str {
    if is_grease(id) {
        return "GREASE";
    }
    match id {
        0x0201 => "rsa_pkcs1_sha1",
        0x0203 => "ecdsa_sha1",
        0x0401 => "rsa_pkcs1_sha256",
        0x0403 => "ecdsa_secp256r1_sha256",
        0x0501 => "rsa_pkcs1_sha384",
        0x0503 => "ecdsa_secp384r1_sha384",
        0x0601 => "rsa_pkcs1_sha512",
        0x0603 => "ecdsa_secp521r1_sha512",
        0x0804 => "rsa_pss_rsae_sha256",
        0x0805 => "rsa_pss_rsae_sha384",
        0x0806 => "rsa_pss_rsae_sha512",
        0x0807 => "ed25519",
        0x0808 => "ed448",
        0x0809 => "rsa_pss_pss_sha256",
        0x080A => "rsa_pss_pss_sha384",
        0x080B => "rsa_pss_pss_sha512",
        _ => "unknown",
    }
}

fn handshake_type_name(ht: u8) -> &'static str {
    match ht {
        TLS_HANDSHAKE_CLIENT_HELLO => "ClientHello",
        TLS_HANDSHAKE_SERVER_HELLO => "ServerHello",
        0x04 => "NewSessionTicket",
        0x08 => "EncryptedExtensions",
        0x0B => "Certificate",
        0x0D => "CertificateRequest",
        0x0F => "CertificateVerify",
        0x14 => "Finished",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pqc_key_exchange_detection() {
        assert!(is_pqc_key_exchange(0x0200));
        assert!(is_pqc_key_exchange(0x0201));
        assert!(is_pqc_key_exchange(0x0202));
        assert!(is_pqc_key_exchange(0x2F00));
        assert!(is_pqc_key_exchange(0x2F01));
        assert!(is_pqc_key_exchange(0x6399));
        assert!(is_pqc_key_exchange(0x639A));
        assert!(is_pqc_key_exchange(0x4588));

        assert!(!is_pqc_key_exchange(0x001D));
        assert!(!is_pqc_key_exchange(0x0017));
        assert!(!is_pqc_key_exchange(0x0018));
        assert!(!is_pqc_key_exchange(0x0000));
        assert!(!is_pqc_key_exchange(0xFFFF));
    }

    #[test]
    fn cipher_suite_lookup_known() {
        assert_eq!(cipher_suite_name(0x1301), "TLS_AES_128_GCM_SHA256");
        assert_eq!(cipher_suite_name(0x1302), "TLS_AES_256_GCM_SHA384");
        assert_eq!(cipher_suite_name(0x1303), "TLS_CHACHA20_POLY1305_SHA256");
        assert_eq!(
            cipher_suite_name(0xC02F),
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        );
    }

    #[test]
    fn cipher_suite_lookup_unknown() {
        assert_eq!(cipher_suite_name(0x0000), "unknown");
        assert_eq!(cipher_suite_name(0xFFFF), "unknown");
    }

    #[test]
    fn key_exchange_lookup_pqc() {
        assert_eq!(key_exchange_name(0x0200), "ML-KEM-512");
        assert_eq!(key_exchange_name(0x0201), "ML-KEM-768");
        assert_eq!(key_exchange_name(0x2F00), "X25519MLKEM768");
        assert_eq!(key_exchange_name(0x6399), "X25519Kyber768Draft00");
    }

    #[test]
    fn grease_detection() {
        assert!(is_grease(0x0A0A));
        assert!(is_grease(0x1A1A));
        assert!(is_grease(0xFAFA));

        assert!(!is_grease(0x0000));
        assert!(!is_grease(0x0A0B));
        assert!(!is_grease(0x1301));
    }

    #[test]
    fn handshake_type_lookup() {
        assert_eq!(
            handshake_type_name(TLS_HANDSHAKE_CLIENT_HELLO),
            "ClientHello"
        );
        assert_eq!(
            handshake_type_name(TLS_HANDSHAKE_SERVER_HELLO),
            "ServerHello"
        );
    }
}
