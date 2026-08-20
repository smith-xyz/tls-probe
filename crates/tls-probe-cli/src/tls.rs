#![cfg_attr(all(test, not(target_os = "linux")), allow(dead_code))]

use crate::certificate::Certificate;
use crate::correlate::Negotiation;
use crate::ja4;
use schemars::JsonSchema;
use serde::Serialize;
use tls_probe_common::{RawTlsCapture, TLS_HANDSHAKE_CLIENT_HELLO, TLS_HANDSHAKE_SERVER_HELLO};
use tls_probe_parser::{parse_tls_payload, TlsAnalysis as ParsedAnalysis};

/// Session resumption and 0-RTT signal flags.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(description = "Resumption/0-RTT signals: PSK and early_data offer/select")]
pub struct Resumption {
    pub psk_offered: bool,
    pub early_data_offered: bool,
    pub psk_selected: bool,
    pub session_ticket_offered: bool,
}

/// One JSONL event emitted by `tls-probe capture`.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(
    title = "TLS Capture Event",
    description = "One JSONL line from tls-probe capture output"
)]
pub struct CaptureEvent {
    pub schema_version: &'static str,
    pub timestamp: String,
    #[schemars(description = "Monotonic ktime from bpf_ktime_get_ns()")]
    pub timestamp_ns: u64,
    #[schemars(description = "Source address:port")]
    pub src: String,
    #[schemars(description = "Destination address:port")]
    pub dst: String,
    pub tls_version: String,
    pub handshake_type: &'static str,
    pub cipher_suites: Vec<CipherSuiteInfo>,
    pub key_exchange_groups: Vec<KeyExchangeInfo>,
    pub signature_algorithms: Vec<SignatureAlgorithmInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(
        description = "signature_algorithms_cert (0x0032) — what the client accepts in certificate chains; ML-DSA here signals PQC-cert readiness"
    )]
    pub signature_algorithms_cert: Option<Vec<SignatureAlgorithmInfo>>,
    pub key_share_group: Option<KeyExchangeInfo>,
    pub sni: Option<String>,
    pub process_name: Option<String>,
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reassembled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(
        description = "Alert level (present only for alerts): 'warning', 'fatal', 'unknown(N)'"
    )]
    pub alert_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(
        description = "Alert description (present only for alerts): named per RFC 8446, e.g. 'protocol_version(70)'"
    )]
    pub alert_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub negotiation: Option<Negotiation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(description = "Resumption/0-RTT signals; omitted if all flags are false")]
    pub resumption: Option<Resumption>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(description = "cgroup v2 inode number for container attribution")]
    pub cgroup_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(description = "Container ID (from cgroup path); null if unresolvable")]
    pub container_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(description = "Pod UID (from cgroup path, Kubernetes only); null if not in a pod")]
    pub pod_uid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(
        description = "JA4 client fingerprint (ClientHello events only); fingerprints TLS client behavior for identification and threat detection"
    )]
    pub ja4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(description = "Parsed leaf certificate (Certificate handshake events only)")]
    pub certificate: Option<Certificate>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct CipherSuiteInfo {
    pub id: u16,
    pub name: &'static str,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct KeyExchangeInfo {
    pub id: u16,
    pub name: &'static str,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct SignatureAlgorithmInfo {
    pub id: u16,
    pub name: &'static str,
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn generate_schema() -> schemars::schema::RootSchema {
    schemars::schema_for!(CaptureEvent)
}

pub fn analyze_capture(capture: &RawTlsCapture) -> CaptureEvent {
    let payload = capture.payload_slice();
    analyze_capture_with_payload(capture, payload)
}

/// Analyze a capture with a custom payload (e.g., from reassembly buffer).
/// The payload can exceed the 4096-byte packet limit from reassembly.
pub fn analyze_capture_with_payload(capture: &RawTlsCapture, payload: &[u8]) -> CaptureEvent {
    // Detect alert records (content_type = 0x15).
    if capture.content_type == 0x15 {
        if let Some((level, description)) = parse_alert(payload) {
            return build_alert_event(capture, level, description);
        }
        // Fallback if payload is too short.
        return build_fallback_analysis(capture);
    }

    let is_client = capture.is_client_hello();

    let parsed = parse_tls_payload(payload, is_client);

    match parsed {
        Ok(analysis) => build_analysis(capture, &analysis),
        Err(_) => build_fallback_analysis(capture),
    }
}

fn build_alert_event(
    capture: &RawTlsCapture,
    alert_level: u8,
    alert_description: u8,
) -> CaptureEvent {
    let (process_name, pid) = process_attribution(capture);

    CaptureEvent {
        schema_version: "1",
        timestamp: chrono::Utc::now().to_rfc3339(),
        timestamp_ns: capture.timestamp_ns,
        src: format!("{}:{}", capture.src_addr_str(), capture.src_port),
        dst: format!("{}:{}", capture.dst_addr_str(), capture.dst_port),
        tls_version: tls_version_str(capture.record_version).to_string(),
        handshake_type: "Alert",
        cipher_suites: Vec::new(),
        key_exchange_groups: Vec::new(),
        signature_algorithms: Vec::new(),
        signature_algorithms_cert: None,
        key_share_group: None,
        sni: None,
        process_name,
        pid,
        reassembled: None,
        truncated: None,
        alert_level: Some(alert_level_name(alert_level)),
        alert_description: Some(alert_description_name(alert_description)),
        negotiation: None,
        resumption: None,
        cgroup_id: None,
        container_id: None,
        pod_uid: None,
        ja4: None,
        certificate: None,
    }
}

fn build_analysis(capture: &RawTlsCapture, parsed: &ParsedAnalysis) -> CaptureEvent {
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

    let signature_algorithms_cert: Option<Vec<SignatureAlgorithmInfo>> = match parsed {
        ParsedAnalysis::ClientHello { hello, .. }
            if !hello.signature_algorithms_cert.is_empty() =>
        {
            Some(
                hello
                    .signature_algorithms_cert
                    .iter()
                    .map(|&id| SignatureAlgorithmInfo {
                        id,
                        name: signature_algorithm_name(id),
                    })
                    .collect(),
            )
        }
        _ => None,
    };

    let key_share_group = match parsed {
        ParsedAnalysis::ClientHello { hello, .. } => {
            hello.key_share_groups.first().map(|&id| KeyExchangeInfo {
                id,
                name: key_exchange_name(id),
            })
        }
        ParsedAnalysis::ServerHello { hello, .. } => {
            hello.key_share_group.map(|id| KeyExchangeInfo {
                id,
                name: key_exchange_name(id),
            })
        }
    };

    let version = parsed.effective_version();
    let tls_version = tls_version_str(version);
    let (process_name, pid) = process_attribution(capture);

    let resumption = match parsed {
        ParsedAnalysis::ClientHello { hello, .. } => {
            let any_flag = hello.psk_offered
                || hello.early_data_offered
                || hello.psk_key_exchange_modes_offered
                || hello.session_ticket_offered;
            if any_flag {
                Some(Resumption {
                    psk_offered: hello.psk_offered,
                    early_data_offered: hello.early_data_offered,
                    psk_selected: false,
                    session_ticket_offered: hello.session_ticket_offered,
                })
            } else {
                None
            }
        }
        ParsedAnalysis::ServerHello { hello, .. } => {
            if hello.psk_selected {
                Some(Resumption {
                    psk_offered: false,
                    early_data_offered: false,
                    psk_selected: hello.psk_selected,
                    session_ticket_offered: false,
                })
            } else {
                None
            }
        }
    };

    // Compute JA4 fingerprint for ClientHello events only
    let ja4_fingerprint = match parsed {
        ParsedAnalysis::ClientHello { hello, .. } => Some(ja4::ja4(hello)),
        ParsedAnalysis::ServerHello { .. } => None,
    };

    CaptureEvent {
        schema_version: "1",
        timestamp: chrono::Utc::now().to_rfc3339(),
        timestamp_ns: capture.timestamp_ns,
        src: format!("{}:{}", capture.src_addr_str(), capture.src_port),
        dst: format!("{}:{}", capture.dst_addr_str(), capture.dst_port),
        tls_version: tls_version.to_string(),
        handshake_type: handshake_type_name(capture.handshake_type),
        cipher_suites,
        key_exchange_groups,
        signature_algorithms,
        signature_algorithms_cert,
        key_share_group,
        sni: parsed.sni().map(String::from),
        process_name,
        pid,
        reassembled: None,
        truncated: None,
        alert_level: None,
        alert_description: None,
        negotiation: None,
        resumption,
        cgroup_id: None,
        container_id: None,
        pod_uid: None,
        ja4: ja4_fingerprint,
        certificate: None,
    }
}

fn build_fallback_analysis(capture: &RawTlsCapture) -> CaptureEvent {
    let (process_name, pid) = process_attribution(capture);

    CaptureEvent {
        schema_version: "1",
        timestamp: chrono::Utc::now().to_rfc3339(),
        timestamp_ns: capture.timestamp_ns,
        src: format!("{}:{}", capture.src_addr_str(), capture.src_port),
        dst: format!("{}:{}", capture.dst_addr_str(), capture.dst_port),
        tls_version: tls_version_str(capture.record_version).to_string(),
        handshake_type: handshake_type_name(capture.handshake_type),
        cipher_suites: Vec::new(),
        key_exchange_groups: Vec::new(),
        signature_algorithms: Vec::new(),
        signature_algorithms_cert: None,
        key_share_group: None,
        sni: None,
        process_name,
        pid,
        reassembled: None,
        truncated: None,
        alert_level: None,
        alert_description: None,
        negotiation: None,
        resumption: None,
        cgroup_id: None,
        container_id: None,
        pod_uid: None,
        ja4: None,
        certificate: None,
    }
}

/// Derives `(process_name, pid)` from the kprobe-attributed fields on a
/// capture. Returns `(None, None)` when no connect-time attribution was
/// found for the connection (e.g. the connecting process exited before the
/// CONN_MAP entry could be read, or attribution raced the LRU eviction).
fn process_attribution(capture: &RawTlsCapture) -> (Option<String>, Option<u32>) {
    if capture.pid == 0 {
        return (None, None);
    }

    let len = capture
        .comm
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(capture.comm.len());
    let name = String::from_utf8_lossy(&capture.comm[..len]).to_string();

    (Some(name), Some(capture.pid))
}

/// Enriches a CaptureEvent with cgroup and container attribution.
/// Takes a reference to the original capture (for cgroup_id) and the resolver trait object.
/// Ownership of the event is transferred and updated in-place.
pub fn enrich_with_cgroup(
    mut event: CaptureEvent,
    capture: &RawTlsCapture,
    resolver: &dyn crate::containers::CgroupResolver,
) -> CaptureEvent {
    if capture.cgroup_id == 0 {
        return event;
    }

    event.cgroup_id = Some(capture.cgroup_id);
    let (container_id, pod_uid) = crate::containers::resolve_cgroup_id(resolver, capture.cgroup_id);
    event.container_id = container_id;
    event.pod_uid = pod_uid;

    event
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

pub fn is_grease(value: u16) -> bool {
    let hi = (value >> 8) as u8;
    let lo = (value & 0xFF) as u8;
    hi == lo && (hi & 0x0F) == 0x0A
}

fn key_exchange_name(id: u16) -> &'static str {
    if is_grease(id) {
        return "GREASE";
    }
    match id {
        // ECDHE curves (RFC 8422)
        0x0017 => "secp256r1",
        0x0018 => "secp384r1",
        0x0019 => "secp521r1",
        0x001D => "x25519",
        0x001E => "x448",
        // FFDHE groups (RFC 7919)
        0x0100 => "ffdhe2048",
        0x0101 => "ffdhe3072",
        0x0102 => "ffdhe4096",
        0x0103 => "ffdhe6144",
        0x0104 => "ffdhe8192",
        // Standalone ML-KEM (draft-connolly-tls-mlkem-key-agreement-05)
        0x0200 => "MLKEM512",
        0x0201 => "MLKEM768",
        0x0202 => "MLKEM1024",
        // Hybrid PQ ML-KEM (RFC-ietf-tls-ecdhe-mlkem-05)
        0x11E9 => "SecP256r1MLKEM512",
        0x11EA => "MLKEM512X25519",
        0x11EB => "SecP256r1MLKEM768",
        0x11EC => "X25519MLKEM768",
        0x11ED => "SecP384r1MLKEM1024",
        // Obsoleted pre-standard Kyber (RFC-ietf-tls-ecdhe-mlkem-05 §8)
        0x6399 => "X25519Kyber768Draft00",
        0x639A => "SecP256r1Kyber768Draft00",
        _ => "unknown",
    }
}

fn cipher_suite_name(id: u16) -> &'static str {
    if is_grease(id) {
        return "GREASE";
    }
    match id {
        // TLS 1.3 AEAD suites
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        0x1304 => "TLS_AES_128_CCM_SHA256",
        0x1305 => "TLS_AES_128_CCM_8_SHA256",
        // ECDHE GCM
        0xC02B => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xC02C => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xC02F => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xC030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        // ECDHE CBC-SHA256/384
        0xC023 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        0xC024 => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        0xC027 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        0xC028 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        // ECDHE CBC-SHA (legacy)
        0xC009 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        0xC00A => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        0xC013 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        0xC014 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        // ECDHE ChaCha20
        0xCCA8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        0xCCA9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        // ECDHE 3DES (legacy)
        0xC008 => "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
        0xC012 => "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
        // ECDHE RC4 (legacy, insecure)
        0xC007 => "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
        0xC011 => "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
        // DHE RSA GCM
        0x009E => "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        0x009F => "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        // DHE RSA CBC-SHA256
        0x0067 => "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
        0x006B => "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
        // DHE RSA CBC-SHA (legacy)
        0x0033 => "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        0x0039 => "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        // DHE RSA ChaCha20
        0xCCAA => "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        // DHE DSS
        0x00A2 => "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
        0x00A3 => "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
        0x0040 => "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
        0x006A => "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
        0x0032 => "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
        0x0038 => "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
        // RSA GCM
        0x009C => "TLS_RSA_WITH_AES_128_GCM_SHA256",
        0x009D => "TLS_RSA_WITH_AES_256_GCM_SHA384",
        // RSA CBC
        0x002F => "TLS_RSA_WITH_AES_128_CBC_SHA",
        0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA",
        0x003C => "TLS_RSA_WITH_AES_128_CBC_SHA256",
        0x003D => "TLS_RSA_WITH_AES_256_CBC_SHA256",
        // RSA legacy
        0x000A => "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        0x0005 => "TLS_RSA_WITH_RC4_128_SHA",
        0x0004 => "TLS_RSA_WITH_RC4_128_MD5",
        // Signaling
        0x00FF => "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
        0x5600 => "TLS_FALLBACK_SCSV",
        _ => "unknown",
    }
}

fn signature_algorithm_name(id: u16) -> &'static str {
    if is_grease(id) {
        return "GREASE";
    }
    match id {
        // SHA-1 legacy
        0x0201 => "rsa_pkcs1_sha1",
        0x0202 => "dsa_sha1",
        0x0203 => "ecdsa_sha1",
        // SHA-224 legacy (TLS 1.2)
        0x0301 => "rsa_pkcs1_sha224",
        0x0302 => "dsa_sha224",
        0x0303 => "ecdsa_sha224",
        // SHA-256
        0x0401 => "rsa_pkcs1_sha256",
        0x0402 => "dsa_sha256",
        0x0403 => "ecdsa_secp256r1_sha256",
        // SHA-384
        0x0501 => "rsa_pkcs1_sha384",
        0x0502 => "dsa_sha384",
        0x0503 => "ecdsa_secp384r1_sha384",
        // SHA-512
        0x0601 => "rsa_pkcs1_sha512",
        0x0602 => "dsa_sha512",
        0x0603 => "ecdsa_secp521r1_sha512",
        // RSA PSS (RSAE)
        0x0804 => "rsa_pss_rsae_sha256",
        0x0805 => "rsa_pss_rsae_sha384",
        0x0806 => "rsa_pss_rsae_sha512",
        // EdDSA
        0x0807 => "ed25519",
        0x0808 => "ed448",
        // RSA PSS (PSS)
        0x0809 => "rsa_pss_pss_sha256",
        0x080A => "rsa_pss_pss_sha384",
        0x080B => "rsa_pss_pss_sha512",
        // Brainpool (RFC 8734)
        0x081A => "ecdsa_brainpoolP256r1tls13_sha256",
        0x081B => "ecdsa_brainpoolP384r1tls13_sha384",
        0x081C => "ecdsa_brainpoolP512r1tls13_sha512",
        // ML-DSA post-quantum signatures
        0x0904 => "mldsa44",
        0x0905 => "mldsa65",
        0x0906 => "mldsa87",
        _ => "unknown",
    }
}

fn alert_level_name(level: u8) -> String {
    match level {
        1 => "warning".to_string(),
        2 => "fatal".to_string(),
        _ => format!("unknown({})", level),
    }
}

fn alert_description_name(description: u8) -> String {
    match description {
        0 => "close_notify(0)".to_string(),
        10 => "unexpected_message(10)".to_string(),
        20 => "bad_record_mac(20)".to_string(),
        22 => "record_overflow(22)".to_string(),
        40 => "handshake_failure(40)".to_string(),
        42 => "bad_certificate(42)".to_string(),
        43 => "unsupported_certificate(43)".to_string(),
        44 => "certificate_revoked(44)".to_string(),
        45 => "certificate_expired(45)".to_string(),
        46 => "certificate_unknown(46)".to_string(),
        47 => "illegal_parameter(47)".to_string(),
        48 => "unknown_ca(48)".to_string(),
        49 => "access_denied(49)".to_string(),
        50 => "decode_error(50)".to_string(),
        51 => "decrypt_error(51)".to_string(),
        70 => "protocol_version(70)".to_string(),
        71 => "insufficient_security(71)".to_string(),
        80 => "internal_error(80)".to_string(),
        86 => "inappropriate_fallback(86)".to_string(),
        90 => "user_canceled(90)".to_string(),
        109 => "missing_extension(109)".to_string(),
        110 => "unsupported_extension(110)".to_string(),
        112 => "unrecognized_name(112)".to_string(),
        113 => "bad_certificate_status_response(113)".to_string(),
        115 => "unknown_psk_identity(115)".to_string(),
        116 => "certificate_required(116)".to_string(),
        120 => "no_application_protocol(120)".to_string(),
        _ => format!("unknown({})", description),
    }
}

pub fn parse_alert(payload: &[u8]) -> Option<(u8, u8)> {
    // The kernel copies from the record start: 5-byte record header
    // (content_type, version, length), then level (byte 5) and description (byte 6).
    if payload.len() >= 7 && payload[0] == 0x15 {
        Some((payload[5], payload[6]))
    } else {
        None
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
    fn parse_alert_reads_past_record_header() {
        // Full record as the kernel copies it: header + (level, description).
        let record = [0x15, 0x03, 0x03, 0x00, 0x02, 2, 70];
        assert_eq!(parse_alert(&record), Some((2, 70)));
        // Too short (header only) and wrong content type both reject.
        assert_eq!(parse_alert(&record[..6]), None);
        assert_eq!(parse_alert(&[0x16, 0x03, 0x03, 0x00, 0x02, 2, 70]), None);
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
        assert_eq!(
            cipher_suite_name(0x009E),
            "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
        );
        assert_eq!(
            cipher_suite_name(0x009F),
            "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"
        );
        assert_eq!(cipher_suite_name(0x000A), "TLS_RSA_WITH_3DES_EDE_CBC_SHA");
        assert_eq!(
            cipher_suite_name(0x00FF),
            "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"
        );
    }

    #[test]
    fn cipher_suite_lookup_unknown() {
        assert_eq!(cipher_suite_name(0x0000), "unknown");
        assert_eq!(cipher_suite_name(0xFFFF), "unknown");
    }

    #[test]
    fn key_exchange_lookup_iana_final() {
        assert_eq!(key_exchange_name(0x0200), "MLKEM512");
        assert_eq!(key_exchange_name(0x0201), "MLKEM768");
        assert_eq!(key_exchange_name(0x0202), "MLKEM1024");
        assert_eq!(key_exchange_name(0x11E9), "SecP256r1MLKEM512");
        assert_eq!(key_exchange_name(0x11EA), "MLKEM512X25519");
        assert_eq!(key_exchange_name(0x11EB), "SecP256r1MLKEM768");
        assert_eq!(key_exchange_name(0x11EC), "X25519MLKEM768");
        assert_eq!(key_exchange_name(0x11ED), "SecP384r1MLKEM1024");
    }

    #[test]
    fn key_exchange_lookup_obsoleted_kyber() {
        assert_eq!(key_exchange_name(0x6399), "X25519Kyber768Draft00");
        assert_eq!(key_exchange_name(0x639A), "SecP256r1Kyber768Draft00");
    }

    #[test]
    fn key_exchange_unassigned_returns_unknown() {
        assert_eq!(key_exchange_name(0x2F00), "unknown");
        assert_eq!(key_exchange_name(0x2F01), "unknown");
        assert_eq!(key_exchange_name(0x4588), "unknown");
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

    #[test]
    fn fixture_event_serializes_to_schema_shape() {
        let capture = RawTlsCapture::default();
        let event = analyze_capture(&capture);
        let json = serde_json::to_string(&event).expect("serialize capture event");
        let value: serde_json::Value = serde_json::from_str(&json).expect("parse serialized json");

        assert!(value.get("timestamp").is_some());
        assert!(value.get("timestamp_ns").is_some());
        assert!(value.get("src").is_some());
        assert!(value.get("dst").is_some());
        assert!(value.get("tls_version").is_some());
        assert!(value.get("handshake_type").is_some());
        assert!(value.get("cipher_suites").is_some());
    }

    #[test]
    fn schema_version_appears_in_serialized_event() {
        let capture = RawTlsCapture::default();
        let event = analyze_capture(&capture);
        let json = serde_json::to_string(&event).expect("serialize capture event");

        assert!(
            json.contains(r#""schema_version":"1""#),
            "schema_version field must appear in serialized event"
        );
    }
}

#[cfg(test)]
mod schema_tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn schema_matches_committed() {
        let generated = generate_schema();
        let generated_json = serde_json::to_string_pretty(&generated).expect("serialize schema");

        let committed = include_str!("../../../specs/capture-event.schema.json");

        assert_eq!(
            generated_json.trim(),
            committed.trim(),
            "Schema drift detected! Regenerate with: cargo test -p tls-probe -- --ignored generate_schema_file"
        );
    }

    #[test]
    #[ignore = "Run manually to regenerate: cargo test -p tls-probe -- --ignored generate_schema_file"]
    fn generate_schema_file() {
        let schema = generate_schema();
        let json = format!(
            "{}\n",
            serde_json::to_string_pretty(&schema).expect("serialize schema")
        );
        let schema_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../specs/capture-event.schema.json");
        if let Some(parent) = schema_path.parent() {
            std::fs::create_dir_all(parent).expect("create specs directory");
        }
        std::fs::write(&schema_path, json).expect("write schema file");
        eprintln!("Schema written to {}", schema_path.display());
    }

    #[test]
    #[ignore = "Run manually to regenerate: cargo test -p tls-probe -- --ignored generate_field_reference"]
    fn generate_field_reference() {
        let schema = generate_schema();
        let json_str = serde_json::to_string(&schema).expect("serialize schema");
        let schema_obj: serde_json::Value = serde_json::from_str(&json_str).expect("parse schema");

        let mut markdown = String::from(
            "# TLS Capture Event Field Reference\n\n\
             Generated from specs/capture-event.schema.json — do not edit by hand; \
             regenerate with: `cargo test -p tls-probe -- --ignored generate_field_reference`\n\n\
             ## Schema Versioning Policy\n\n\
             - **Schema version 1** is the initial stable release.\n\
             - **Additive changes** (new optional fields) do not require a version bump and remain compatible with existing consumers.\n\
             - **Breaking changes** (required field removal, type changes, required field additions) bump to schema version 2+.\n\n"
        );

        markdown.push_str("## Fields\n\n");
        markdown.push_str("|Field|Type|Required|Description|\n");
        markdown.push_str("|-----|----|--------|-------------|\n");

        if let Some(props) = schema_obj.get("properties").and_then(|p| p.as_object()) {
            let required: std::collections::HashSet<&str> = schema_obj
                .get("required")
                .and_then(|r| r.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
                .unwrap_or_default();

            let mut keys: Vec<_> = props.keys().collect();
            keys.sort();

            for key in keys {
                let prop = &props[key];
                let is_required = required.contains(key.as_str());
                let req_str = if is_required { "yes" } else { "no" };

                let type_str = if let Some(type_val) = prop.get("type") {
                    if let Some(s) = type_val.as_str() {
                        s.to_string()
                    } else if let Some(arr) = type_val.as_array() {
                        arr.iter()
                            .filter_map(|v| v.as_str())
                            .collect::<Vec<_>>()
                            .join(" or ")
                    } else {
                        "object".to_string()
                    }
                } else if prop.get("anyOf").is_some() || prop.get("oneOf").is_some() {
                    "ref/union".to_string()
                } else {
                    "object".to_string()
                };

                let desc = prop
                    .get("description")
                    .and_then(|d| d.as_str())
                    .unwrap_or("");

                markdown.push_str(&format!("`{}`|{}|{}|{}\n", key, type_str, req_str, desc));
            }
        }

        let field_ref_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/field-reference.md");
        if let Some(parent) = field_ref_path.parent() {
            std::fs::create_dir_all(parent).expect("create docs directory");
        }
        std::fs::write(&field_ref_path, markdown).expect("write field reference");
        eprintln!("Field reference written to {}", field_ref_path.display());
    }
}
