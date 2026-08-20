//! TLS record walker for multi-record extraction from single-packet ServerHello payloads.
//!
//! For TLS 1.2 server certificate flights, the kernel captures only the FIRST record
//! in a packet (ServerHello). However, the kernel copies the ENTIRE packet payload
//! into the event. This module walks subsequent records in that payload to extract
//! Certificate and CertificateRequest records that follow the ServerHello.
//!
//! **Ownership**: The walker takes a reference to a payload buffer and returns
//! a list of extracted records; the caller retains ownership of all data.

#![cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]

#[cfg(any(target_os = "linux", test))]
use tls_probe_common::RawTlsCapture;

/// Maximum number of records to walk (defensive cap).
const MAX_RECORDS_TO_WALK: usize = 4;

/// Represents an extracted TLS record from the payload walk.
/// Only Handshake records (content_type 0x16) are stored; the type is implied.
#[derive(Debug, Clone)]
pub struct ExtractedRecord {
    /// TLS record version (e.g., 0x0303 for TLS 1.2).
    /// Used by synthesize_event_from_walked_record to populate event.tls_version.
    pub version: u16,
    /// The record body (payload after the 5-byte header).
    pub body: Vec<u8>,
    /// True if this record was truncated by the 4096-byte payload cap.
    pub truncated: bool,
}

/// Result of walking records in a ServerHello payload.
#[derive(Debug, Clone)]
pub struct WalkedRecords {
    /// Extracted records found after the first record.
    pub records: Vec<ExtractedRecord>,
}

/// Walks TLS records in a payload starting after the first record.
///
/// **Design**: After a ServerHello (first record), walk subsequent complete records.
/// Only process content_type 0x16 (Handshake) with body[0] == 0x0B (Certificate)
/// or 0x0D (CertificateRequest). Stop at incomplete/non-handshake or payload end.
/// Hard-cap at 4 records (defensive).
///
/// **Ownership**: Takes a reference to the payload and returns owned ExtractedRecord
/// data; does not retain the payload reference.
#[cfg(any(target_os = "linux", test))]
pub fn walk_records(payload: &[u8]) -> WalkedRecords {
    let mut records = Vec::new();

    // TLS record header: 5 bytes (content_type u8, version u16, length u16).
    const RECORD_HEADER_LEN: usize = 5;

    // Minimum payload for a valid record: header + at least 1 byte body.
    if payload.len() < RECORD_HEADER_LEN + 1 {
        return WalkedRecords { records };
    }

    // First record offset: assume it starts at 0 and extract its length.
    let first_record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    let mut offset = RECORD_HEADER_LEN + first_record_len;

    // Walk subsequent records.
    let mut record_count = 0;
    while offset + RECORD_HEADER_LEN <= payload.len() && record_count < MAX_RECORDS_TO_WALK {
        let content_type = payload[offset];
        let version = u16::from_be_bytes([payload[offset + 1], payload[offset + 2]]);
        let record_len = u16::from_be_bytes([payload[offset + 3], payload[offset + 4]]) as usize;

        let body_start = offset + RECORD_HEADER_LEN;
        let body_end = body_start + record_len;
        let truncated = body_end > payload.len();

        let body = if truncated {
            // Truncated: extract available bytes.
            payload[body_start..].to_vec()
        } else {
            // Complete record.
            payload[body_start..body_end].to_vec()
        };

        // Only keep Handshake records (0x16) with Certificate (0x0B) or CertificateRequest (0x0D).
        if content_type == 0x16 && !body.is_empty() {
            let handshake_type = body[0];
            if handshake_type == 0x0B || handshake_type == 0x0D {
                records.push(ExtractedRecord {
                    version,
                    body,
                    truncated,
                });
            }
        } else if content_type != 0x16 {
            // Non-handshake: stop the walk.
            break;
        }

        // Move to next record (or stop if incomplete).
        if truncated {
            break;
        }
        offset = body_end;
        record_count += 1;
    }

    WalkedRecords { records }
}

/// Synthesizes a CaptureEvent from a walked record.
///
/// Takes the original ServerHello capture for connection metadata (src/dst/timestamps/pid/comm)
/// and enriches it with the extracted record data. The caller is responsible for parsing
/// the certificate and routing through the correlator.
///
/// **Ownership**: Takes ownership of the original capture (for metadata) and returns
/// data for an owned CaptureEvent. The walked record is borrowed (body not retained).
///
/// Returns a tuple of (event, handshake_type) so the caller can route appropriately.
#[cfg(any(target_os = "linux", test))]
pub fn synthesize_event_from_walked_record(
    original_capture: &RawTlsCapture,
    record: &ExtractedRecord,
) -> (crate::tls::CaptureEvent, u8) {
    // Handshake type: 0x0B = Certificate, 0x0D = CertificateRequest.
    let handshake_type = if record.body.is_empty() {
        0x00
    } else {
        record.body[0]
    };

    // Build the event using the original capture's connection metadata.
    let event = crate::tls::CaptureEvent {
        schema_version: "1",
        timestamp: chrono::Utc::now().to_rfc3339(),
        timestamp_ns: original_capture.timestamp_ns,
        src: format!(
            "{}:{}",
            original_capture.src_addr_str(),
            original_capture.src_port
        ),
        dst: format!(
            "{}:{}",
            original_capture.dst_addr_str(),
            original_capture.dst_port
        ),
        tls_version: tls_version_name(record.version).to_string(),
        handshake_type: handshake_type_name(handshake_type),
        cipher_suites: Vec::new(),
        key_exchange_groups: Vec::new(),
        signature_algorithms: Vec::new(),
        signature_algorithms_cert: None,
        key_share_group: None,
        sni: None,
        process_name: if original_capture.pid == 0 {
            None
        } else {
            let len = original_capture
                .comm
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(original_capture.comm.len());
            Some(String::from_utf8_lossy(&original_capture.comm[..len]).to_string())
        },
        pid: if original_capture.pid == 0 {
            None
        } else {
            Some(original_capture.pid)
        },
        reassembled: None,
        truncated: Some(record.truncated),
        alert_level: None,
        alert_description: None,
        negotiation: None,
        resumption: None,
        cgroup_id: None,
        container_id: None,
        pod_uid: None,
        ja4: None,
        certificate: None,
    };

    (event, handshake_type)
}

#[cfg(any(target_os = "linux", test))]
fn tls_version_name(version: u16) -> &'static str {
    match version {
        0x0304 => "TLS 1.3",
        0x0303 => "TLS 1.2",
        0x0302 => "TLS 1.1",
        0x0301 => "TLS 1.0",
        0x0300 => "SSL 3.0",
        _ => "Unknown",
    }
}

#[cfg(any(target_os = "linux", test))]
fn handshake_type_name(ht: u8) -> &'static str {
    match ht {
        0x0B => "Certificate",
        0x0D => "CertificateRequest",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tls_record(content_type: u8, version: u16, body: &[u8]) -> Vec<u8> {
        let mut record = Vec::new();
        record.push(content_type);
        record.extend_from_slice(&version.to_be_bytes());
        let len = body.len() as u16;
        record.extend_from_slice(&len.to_be_bytes());
        record.extend_from_slice(body);
        record
    }

    #[test]
    fn walk_empty_payload() {
        let walked = walk_records(&[]);
        assert_eq!(walked.records.len(), 0);
    }

    #[test]
    fn walk_payload_too_short() {
        let walked = walk_records(&[0x16, 0x03, 0x03]);
        assert_eq!(walked.records.len(), 0);
    }

    #[test]
    fn walk_single_record_sh_only() {
        // ServerHello only: no subsequent records.
        let mut payload = Vec::new();
        // First record: ServerHello with minimal body.
        let sh_body = [0x02, 0x00, 0x00]; // ServerHello type + minimal payload
        payload.extend(make_tls_record(0x16, 0x0303, &sh_body));

        let walked = walk_records(&payload);
        assert_eq!(walked.records.len(), 0);
    }

    #[test]
    fn walk_sh_then_certificate() {
        // ServerHello | Certificate
        let mut payload = Vec::new();
        let sh_body = [0x02, 0x00, 0x00]; // ServerHello
        payload.extend(make_tls_record(0x16, 0x0303, &sh_body));

        // Certificate record with minimal cert list.
        let mut cert_body = vec![0x0B]; // Certificate type
        cert_body.extend_from_slice(&[0x00, 0x00, 0x03]); // cert list len = 3
        cert_body.extend_from_slice(&[0x00, 0x00, 0x00]); // first cert len = 0 (empty)
        payload.extend(make_tls_record(0x16, 0x0303, &cert_body));

        let walked = walk_records(&payload);
        assert_eq!(walked.records.len(), 1);
        assert_eq!(walked.records[0].body[0], 0x0B); // Certificate
        assert!(!walked.records[0].truncated);
    }

    #[test]
    fn walk_sh_then_certreq() {
        // ServerHello | CertificateRequest
        let mut payload = Vec::new();
        let sh_body = [0x02, 0x00, 0x00];
        payload.extend(make_tls_record(0x16, 0x0303, &sh_body));

        // CertificateRequest record.
        let mut certreq_body = vec![0x0D]; // CertificateRequest type
        certreq_body.extend_from_slice(&[0x00, 0x00, 0x00]); // cert_types len = 0
        payload.extend(make_tls_record(0x16, 0x0303, &certreq_body));

        let walked = walk_records(&payload);
        assert_eq!(walked.records.len(), 1);
        assert_eq!(walked.records[0].body[0], 0x0D); // CertificateRequest
    }

    #[test]
    fn walk_sh_then_serverkellodone() {
        // ServerHello | ServerHelloDone (0x0E, not Certificate/CertificateRequest)
        let mut payload = Vec::new();
        let sh_body = [0x02, 0x00, 0x00];
        payload.extend(make_tls_record(0x16, 0x0303, &sh_body));

        // ServerHelloDone record (not extracted).
        let shd_body = vec![0x0E]; // ServerHelloDone type
        payload.extend(make_tls_record(0x16, 0x0303, &shd_body));

        let walked = walk_records(&payload);
        // ServerHelloDone is Handshake (0x16) but type 0x0E, so not extracted.
        assert_eq!(walked.records.len(), 0);
    }

    #[test]
    fn walk_sh_then_certificate_truncated() {
        // ServerHello | Certificate (truncated mid-cert).
        let mut payload = Vec::new();
        let sh_body = [0x02, 0x00, 0x00];
        payload.extend(make_tls_record(0x16, 0x0303, &sh_body));

        // Certificate record that claims to be 100 bytes but only provide 4.
        let mut cert_record = vec![
            0x16, 0x03, 0x03, // content_type, version
            0x00, 0x64, // length = 100
        ];
        let mut cert_body = vec![0x0B]; // Certificate type
        cert_body.extend_from_slice(&[0x00, 0x00, 0x03]); // cert list len = 3
        cert_record.extend_from_slice(&cert_body);
        // Only 4 bytes of body, claims 100: truncated.

        payload.extend(cert_record);

        let walked = walk_records(&payload);
        assert_eq!(walked.records.len(), 1);
        assert_eq!(walked.records[0].body.len(), 4);
        assert!(walked.records[0].truncated);
    }

    #[test]
    fn walk_exceeds_max_records() {
        // Create 5 Certificate records; only first 4 should be extracted.
        let mut payload = Vec::new();
        let sh_body = [0x02, 0x00, 0x00];
        payload.extend(make_tls_record(0x16, 0x0303, &sh_body));

        for _ in 0..5 {
            let cert_body = vec![0x0B, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00]; // Minimal cert.
            payload.extend(make_tls_record(0x16, 0x0303, &cert_body));
        }

        let walked = walk_records(&payload);
        assert_eq!(walked.records.len(), MAX_RECORDS_TO_WALK);
    }

    #[test]
    fn walk_stops_at_alert() {
        // ServerHello | Alert record (should stop).
        let mut payload = Vec::new();
        let sh_body = [0x02, 0x00, 0x00];
        payload.extend(make_tls_record(0x16, 0x0303, &sh_body));

        // Alert record (content_type = 0x15, not 0x16).
        let alert_body = [0x02, 0x0A]; // Warning, unexpected_message.
        payload.extend(make_tls_record(0x15, 0x0303, &alert_body));

        let walked = walk_records(&payload);
        // Alert (0x15) is not handshake, so walk stops.
        assert_eq!(walked.records.len(), 0);
    }
}
