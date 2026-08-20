#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use schemars::JsonSchema;
use serde::Serialize;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tls_probe_common::{is_grease, ConnKey};
use tls_probe_parser::{ParsedServerHello, TlsAnalysis};

/// Builds the negotiation object for a CH↔SH join. Shared by the normal join
/// (entry evicted) and the mTLS path (entry retained for the client cert).
fn build_negotiation(summary: &ClientHelloSummary, hello: &ParsedServerHello) -> Negotiation {
    let client_max_version = tls_version_name(summary.max_version);
    let selected_group = hello.key_share_group.map(|group_id| SelectedGroup {
        id: group_id,
        name: key_exchange_name(group_id).to_string(),
    });

    // Build client_offered_groups: all offered groups excluding GREASE.
    // GREASE is wire noise by design; filtering it is a reporting choice,
    // documented here so downstream can reconstruct the raw wire values if needed.
    let client_offered_groups: Vec<OfferedGroup> = summary
        .offered_groups
        .iter()
        .filter(|&&g| !is_grease(g))
        .map(|&g| OfferedGroup {
            id: g,
            name: key_exchange_name(g).to_string(),
        })
        .collect();

    Negotiation {
        outcome: "negotiated".to_string(),
        client_max_version: client_max_version.to_string(),
        selected_group,
        client_offered_groups,
        client_sni: summary.sni.clone(),
        psk_selected: hello.psk_selected,
        early_data_offered: summary.early_data_offered,
        mtls_requested: summary.mtls_requested,
        mtls: summary.mtls,
    }
}

/// Compact summary of a ClientHello stored in the correlator's LRU.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ClientHelloSummary {
    max_version: u16,
    offered_groups: Vec<u16>,
    sni: Option<String>,
    /// Captured from ClientHello for completeness; not currently used in negotiation logic.
    psk_offered: bool,
    early_data_offered: bool,
    /// Captured timestamp for potential future correlation or eviction strategies.
    timestamp_ns: u64,
    mtls_requested: bool,
    mtls: bool,
    /// Set at ServerHello join when mtls_requested: the entry survives the
    /// join so the later client Certificate can pick this up with mtls=true.
    post_sh_negotiation: Option<Negotiation>,
}

/// Negotiation object attached to ServerHello or Alert events.
/// Wire facts only: no derived or themed fields. Reasoning about client
/// preferences vs negotiated outcomes is reserved for downstream consumers.
#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
pub struct Negotiation {
    pub outcome: String, // "negotiated" or "failed"
    pub client_max_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_group: Option<SelectedGroup>,
    /// Client's offered supported_groups (GREASE filtered). Empty if no
    /// supported_groups or key_share extension was parsed. Used to determine
    /// whether selected_group was available to the client.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub client_offered_groups: Vec<OfferedGroup>,
    pub client_sni: Option<String>,
    pub psk_selected: bool,
    pub early_data_offered: bool,
    // Always serialized: schemars marks plain bools required, so
    // skip_serializing_if would emit schema-invalid objects when false.
    pub mtls_requested: bool,
    pub mtls: bool,
}

/// Selected key exchange group info.
#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
pub struct SelectedGroup {
    pub id: u16,
    pub name: String,
}

/// Offered key exchange group info.
#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
pub struct OfferedGroup {
    pub id: u16,
    pub name: String,
}

/// Correlator state: LRU-backed mapping from ConnKey to ClientHelloSummary.
/// Bounds: 8192 entries max, 10s TTL, swept on counter tick.
///
/// **Ownership**: Takes ownership of ConnKey values for map keys; borrows
/// TlsAnalysis for reading during on_client_hello/on_server_hello.
pub struct Correlator {
    /// Map from ConnKey to (ClientHelloSummary, insertion_ns).
    pending: HashMap<ConnKey, (ClientHelloSummary, u64)>,
    /// Approximate entry limit for bounded LRU.
    max_entries: usize,
    /// TTL in nanoseconds.
    ttl_ns: u64,
}

impl Correlator {
    /// Creates a new empty Correlator.
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            max_entries: 8192,
            ttl_ns: 10_000_000_000, // 10 seconds in nanoseconds
        }
    }

    /// Records a ClientHello and returns None (always; the join happens on SH).
    ///
    /// **Ownership**: Takes ownership of the key; borrows analysis for reading.
    pub fn on_client_hello(&mut self, key: ConnKey, analysis: &TlsAnalysis) -> Option<Negotiation> {
        if let TlsAnalysis::ClientHello { hello, .. } = analysis {
            // Determine max version, filtering out GREASE.
            let max_version = hello
                .supported_versions
                .iter()
                .find(|&&v| !is_grease(v))
                .copied()
                .unwrap_or(hello.legacy_version);

            // Collect offered groups from key_share_groups or supported_groups fallback.
            let offered_groups = if !hello.key_share_groups.is_empty() {
                hello.key_share_groups.clone()
            } else {
                hello.supported_groups.clone()
            };

            let now_ns = current_time_ns();
            let summary = ClientHelloSummary {
                max_version,
                offered_groups,
                sni: hello.sni.clone(),
                psk_offered: hello.psk_offered,
                early_data_offered: hello.early_data_offered,
                timestamp_ns: now_ns,
                mtls_requested: false,
                mtls: false,
                post_sh_negotiation: None,
            };

            // Enforce bounded LRU: evict oldest entry if at capacity.
            if self.pending.len() >= self.max_entries {
                if let Some(&key_to_evict) = self
                    .pending
                    .iter()
                    .min_by_key(|(_, (_, ts))| ts)
                    .map(|(k, _)| k)
                {
                    self.pending.remove(&key_to_evict);
                }
            }

            // Insert or replace: duplicate CH on same flow replaces.
            self.pending.insert(key, (summary, now_ns));
        }

        None
    }

    /// Joins a ServerHello with a pending ClientHello and returns the negotiation.
    /// If no ClientHello is found, returns None and increments a counter.
    ///
    /// **Ownership**: Takes ownership of the key; borrows analysis for reading.
    pub fn on_server_hello(&mut self, key: ConnKey, analysis: &TlsAnalysis) -> Option<Negotiation> {
        if let TlsAnalysis::ServerHello { hello, .. } = analysis {
            // mTLS flows stay pending past the SH join: the client Certificate
            // arrives later and needs this entry to attach mtls=true to.
            let keep_pending = self
                .pending
                .get(&key)
                .is_some_and(|(s, _)| s.mtls_requested);
            if keep_pending {
                let negotiation = {
                    let (summary, _) = self.pending.get(&key)?;
                    build_negotiation(summary, hello)
                };
                if let Some((summary, _)) = self.pending.get_mut(&key) {
                    summary.post_sh_negotiation = Some(negotiation.clone());
                }
                return Some(negotiation);
            }
            if let Some((summary, _)) = self.pending.remove(&key) {
                return Some(build_negotiation(&summary, hello));
            }
        }

        None
    }

    /// Handles an alert record; joins with a pending ClientHello to produce a negotiation
    /// with outcome="failed". If no ClientHello is found, returns None (alert is dropped).
    ///
    /// **Ownership**: Takes ownership of the key; borrows nothing from alert payload
    /// (the correlator doesn't parse alerts; the caller provides parsed alert values).
    pub fn on_alert(
        &mut self,
        key: ConnKey,
        _alert_level: u8,
        _alert_description: u8,
    ) -> Option<Negotiation> {
        if let Some((summary, _)) = self.pending.remove(&key) {
            let client_max_version = tls_version_name(summary.max_version);

            // Build client_offered_groups: all offered groups excluding GREASE.
            let client_offered_groups: Vec<OfferedGroup> = summary
                .offered_groups
                .iter()
                .filter(|&&g| !is_grease(g))
                .map(|&g| OfferedGroup {
                    id: g,
                    name: key_exchange_name(g).to_string(),
                })
                .collect();

            return Some(Negotiation {
                outcome: "failed".to_string(),
                client_max_version: client_max_version.to_string(),
                selected_group: None,
                client_offered_groups,
                client_sni: summary.sni,
                psk_selected: false,
                early_data_offered: summary.early_data_offered,
                mtls_requested: summary.mtls_requested,
                mtls: summary.mtls,
            });
        }

        None
    }

    /// Records a CertificateRequest handshake (hs type 0x0D) on a flow.
    /// Sets mtls_requested flag on the pending ClientHello summary for this connection.
    ///
    /// **Ownership**: Takes ownership of the key; does not parse any certificate data.
    pub fn on_certificate_request(&mut self, key: ConnKey) {
        if let Some((summary, _)) = self.pending.get_mut(&key) {
            summary.mtls_requested = true;
        }
    }

    /// Records a client Certificate handshake (hs type 0x0B, client direction) on a flow.
    /// This indicates successful mTLS: the server requested it (CertificateRequest seen)
    /// and the client sent a certificate. The ServerHello negotiation was already
    /// emitted by this point, so the completed-mTLS negotiation returned here rides
    /// the client Certificate event instead; the entry is then evicted (terminal).
    ///
    /// **Ownership**: Takes ownership of the key; does not parse any certificate data.
    pub fn on_client_certificate(&mut self, key: ConnKey) -> Option<Negotiation> {
        let has_post_sh = self
            .pending
            .get(&key)
            .is_some_and(|(s, _)| s.post_sh_negotiation.is_some());
        if has_post_sh {
            let (summary, _) = self.pending.remove(&key)?;
            let mut negotiation = summary.post_sh_negotiation?;
            negotiation.mtls = true;
            return Some(negotiation);
        }
        // Client cert observed before the SH join (unusual ordering): record the
        // flag so the eventual SH join carries it.
        if let Some((summary, _)) = self.pending.get_mut(&key) {
            summary.mtls = true;
        }
        None
    }

    /// Sweeps expired entries (older than TTL). Returns count of evicted entries.
    /// Called periodically (on counter tick, ~500 captures).
    pub fn sweep_expired(&mut self) -> usize {
        let now_ns = current_time_ns();
        let initial_len = self.pending.len();

        self.pending.retain(|_, (_, ts)| now_ns - *ts < self.ttl_ns);

        initial_len - self.pending.len()
    }
}

impl Default for Correlator {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns the current time in nanoseconds since UNIX epoch.
fn current_time_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Maps a TLS version to its string name.
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

/// Maps a group ID to its string name (PQC and classical).
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
        0x0200 => "MLKEM512",
        0x0201 => "MLKEM768",
        0x0202 => "MLKEM1024",
        0x11E9 => "SecP256r1MLKEM512",
        0x11EA => "MLKEM512X25519",
        0x11EB => "SecP256r1MLKEM768",
        0x11EC => "X25519MLKEM768",
        0x11ED => "SecP384r1MLKEM1024",
        0x6399 => "X25519Kyber768Draft00",
        0x639A => "SecP256r1Kyber768Draft00",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_ch_to_sh_negotiation() {
        let mut correlator = Correlator::new();
        let key = ConnKey {
            src_addr: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            dst_addr: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            src_port: 12345,
            dst_port: 443,
        };

        // Create a mock ClientHello analysis.
        let ch = tls_probe_parser::ParsedClientHello {
            legacy_version: 0x0303,
            random: [0u8; 32],
            session_id: vec![],
            cipher_suites: vec![0x1301],
            compression_methods: vec![0],
            extensions: vec![],
            supported_versions: vec![0x0304],
            supported_groups: vec![0x001D, 0x11EC],
            signature_algorithms: vec![0x0403],
            signature_algorithms_cert: vec![],
            key_share_groups: vec![0x001D, 0x11EC],
            sni: Some("example.com".to_string()),
            psk_offered: false,
            early_data_offered: false,
            psk_key_exchange_modes_offered: false,
            session_ticket_offered: false,
            extension_ids: vec![],
            alpn: vec![],
        };
        let ch_analysis = TlsAnalysis::ClientHello {
            record_version: 0x0303,
            hello: Box::new(ch),
        };

        // Store the ClientHello.
        assert_eq!(correlator.on_client_hello(key, &ch_analysis), None);

        // Create a mock ServerHello analysis with a negotiated group.
        let sh = tls_probe_parser::ParsedServerHello {
            legacy_version: 0x0303,
            random: [0u8; 32],
            session_id: vec![],
            cipher_suite: 0x1301,
            compression_method: 0,
            extensions: vec![],
            negotiated_version: Some(0x0304),
            key_share_group: Some(0x001D),
            psk_selected: false,
        };
        let sh_analysis = TlsAnalysis::ServerHello {
            record_version: 0x0303,
            hello: sh,
        };

        // Join: should produce a negotiation.
        let neg = correlator.on_server_hello(key, &sh_analysis);
        assert!(neg.is_some());
        let neg = neg.unwrap();
        assert_eq!(neg.outcome, "negotiated");
        assert_eq!(neg.client_max_version, "TLS 1.3");
        assert_eq!(neg.selected_group.map(|g| g.id), Some(0x001D));
        // Verify offered_groups contains both 0x001D and 0x11EC.
        assert_eq!(neg.client_offered_groups.len(), 2);
        assert!(neg.client_offered_groups.iter().any(|g| g.id == 0x001D));
        assert!(neg.client_offered_groups.iter().any(|g| g.id == 0x11EC));
        assert_eq!(neg.client_sni, Some("example.com".to_string()));
    }

    #[test]
    fn downgrade_detection() {
        let mut correlator = Correlator::new();
        let key = ConnKey {
            src_addr: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            dst_addr: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            src_port: 12345,
            dst_port: 443,
        };

        // CH offers TLS 1.3.
        let ch = tls_probe_parser::ParsedClientHello {
            legacy_version: 0x0303,
            random: [0u8; 32],
            session_id: vec![],
            cipher_suites: vec![0x1301],
            compression_methods: vec![0],
            extensions: vec![],
            extension_ids: vec![],
            supported_versions: vec![0x0304],
            supported_groups: vec![],
            signature_algorithms: vec![],
            signature_algorithms_cert: vec![],
            key_share_groups: vec![],
            sni: None,
            alpn: vec![],
            psk_offered: false,
            early_data_offered: false,
            psk_key_exchange_modes_offered: false,
            session_ticket_offered: false,
        };
        let ch_analysis = TlsAnalysis::ClientHello {
            record_version: 0x0303,
            hello: Box::new(ch),
        };
        correlator.on_client_hello(key, &ch_analysis);

        // SH negotiates TLS 1.2: downgrade.
        let sh = tls_probe_parser::ParsedServerHello {
            legacy_version: 0x0303,
            random: [0u8; 32],
            session_id: vec![],
            cipher_suite: 0x1301,
            compression_method: 0,
            extensions: vec![],
            negotiated_version: Some(0x0303),
            key_share_group: None,
            psk_selected: false,
        };
        let sh_analysis = TlsAnalysis::ServerHello {
            record_version: 0x0303,
            hello: sh,
        };

        let neg = correlator.on_server_hello(key, &sh_analysis).unwrap();
        assert_eq!(neg.client_max_version, "TLS 1.3");
        // Verify that the offered groups is empty (no supported_groups extension).
        assert_eq!(neg.client_offered_groups.len(), 0);
    }

    #[test]
    fn sh_without_ch_returns_none() {
        let mut correlator = Correlator::new();
        let key = ConnKey {
            src_addr: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            dst_addr: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            src_port: 12345,
            dst_port: 443,
        };

        let sh = tls_probe_parser::ParsedServerHello {
            legacy_version: 0x0303,
            random: [0u8; 32],
            session_id: vec![],
            cipher_suite: 0x1301,
            compression_method: 0,
            extensions: vec![],
            negotiated_version: Some(0x0304),
            key_share_group: Some(0x001D),
            psk_selected: false,
        };
        let sh_analysis = TlsAnalysis::ServerHello {
            record_version: 0x0303,
            hello: sh,
        };

        let neg = correlator.on_server_hello(key, &sh_analysis);
        assert_eq!(neg, None);
    }

    #[test]
    fn duplicate_ch_replaces() {
        let mut correlator = Correlator::new();
        let key = ConnKey {
            src_addr: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            dst_addr: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            src_port: 12345,
            dst_port: 443,
        };

        let ch1 = tls_probe_parser::ParsedClientHello {
            legacy_version: 0x0303,
            random: [0u8; 32],
            session_id: vec![],
            cipher_suites: vec![0x1301],
            compression_methods: vec![0],
            extensions: vec![],
            extension_ids: vec![],
            supported_versions: vec![0x0304],
            supported_groups: vec![0x001D],
            signature_algorithms: vec![],
            signature_algorithms_cert: vec![],
            key_share_groups: vec![0x001D],
            sni: Some("example.com".to_string()),
            alpn: vec![],
            psk_offered: false,
            early_data_offered: false,
            psk_key_exchange_modes_offered: false,
            session_ticket_offered: false,
        };
        let ch1_analysis = TlsAnalysis::ClientHello {
            record_version: 0x0303,
            hello: Box::new(ch1),
        };

        correlator.on_client_hello(key, &ch1_analysis);
        assert_eq!(correlator.pending.len(), 1);

        let ch2 = tls_probe_parser::ParsedClientHello {
            legacy_version: 0x0303,
            random: [1u8; 32],
            session_id: vec![],
            cipher_suites: vec![0x1301],
            compression_methods: vec![0],
            extensions: vec![],
            extension_ids: vec![],
            supported_versions: vec![0x0304],
            supported_groups: vec![0x11EC],
            signature_algorithms: vec![],
            signature_algorithms_cert: vec![],
            key_share_groups: vec![0x11EC],
            sni: Some("other.com".to_string()),
            alpn: vec![],
            psk_offered: false,
            early_data_offered: false,
            psk_key_exchange_modes_offered: false,
            session_ticket_offered: false,
        };
        let ch2_analysis = TlsAnalysis::ClientHello {
            record_version: 0x0303,
            hello: Box::new(ch2),
        };

        correlator.on_client_hello(key, &ch2_analysis);
        assert_eq!(correlator.pending.len(), 1); // Still 1 entry, replaced.

        let (summary, _) = correlator.pending.get(&key).unwrap();
        assert_eq!(summary.sni, Some("other.com".to_string()));
        assert_eq!(summary.offered_groups, vec![0x11EC]);
    }

    #[test]
    fn pqc_gap_detection() {
        let mut correlator = Correlator::new();
        let key = ConnKey {
            src_addr: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            dst_addr: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            src_port: 12345,
            dst_port: 443,
        };

        // CH offers both X25519 and X25519MLKEM768.
        let ch = tls_probe_parser::ParsedClientHello {
            legacy_version: 0x0303,
            random: [0u8; 32],
            session_id: vec![],
            cipher_suites: vec![0x1301],
            compression_methods: vec![0],
            extensions: vec![],
            supported_versions: vec![0x0304],
            supported_groups: vec![0x001D, 0x11EC],
            signature_algorithms: vec![],
            signature_algorithms_cert: vec![],
            key_share_groups: vec![0x001D, 0x11EC],
            sni: None,
            psk_offered: false,
            early_data_offered: false,
            psk_key_exchange_modes_offered: false,
            session_ticket_offered: false,
            extension_ids: vec![],
            alpn: vec![],
        };
        let ch_analysis = TlsAnalysis::ClientHello {
            record_version: 0x0303,
            hello: Box::new(ch),
        };

        correlator.on_client_hello(key, &ch_analysis);

        // SH selects X25519 (not PQC).
        let sh = tls_probe_parser::ParsedServerHello {
            legacy_version: 0x0303,
            random: [0u8; 32],
            session_id: vec![],
            cipher_suite: 0x1301,
            compression_method: 0,
            extensions: vec![],
            negotiated_version: Some(0x0304),
            key_share_group: Some(0x001D),
            psk_selected: false,
        };
        let sh_analysis = TlsAnalysis::ServerHello {
            record_version: 0x0303,
            hello: sh,
        };

        let neg = correlator.on_server_hello(key, &sh_analysis).unwrap();
        // X25519MLKEM768 (0x11EC) is in offered_groups but not selected.
        assert_eq!(neg.client_offered_groups.len(), 2);
        assert!(neg.client_offered_groups.iter().any(|g| g.id == 0x11EC));
        assert_eq!(neg.selected_group.as_ref().map(|g| g.id), Some(0x001D));
    }

    #[test]
    fn ttl_eviction() {
        let mut correlator = Correlator::new();
        let key = ConnKey {
            src_addr: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            dst_addr: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            src_port: 12345,
            dst_port: 443,
        };

        let ch = tls_probe_parser::ParsedClientHello {
            legacy_version: 0x0303,
            random: [0u8; 32],
            session_id: vec![],
            cipher_suites: vec![0x1301],
            compression_methods: vec![0],
            extensions: vec![],
            extension_ids: vec![],
            supported_versions: vec![0x0304],
            supported_groups: vec![],
            signature_algorithms: vec![],
            signature_algorithms_cert: vec![],
            key_share_groups: vec![],
            sni: None,
            alpn: vec![],
            psk_offered: false,
            early_data_offered: false,
            psk_key_exchange_modes_offered: false,
            session_ticket_offered: false,
        };
        let ch_analysis = TlsAnalysis::ClientHello {
            record_version: 0x0303,
            hello: Box::new(ch),
        };

        correlator.on_client_hello(key, &ch_analysis);
        assert_eq!(correlator.pending.len(), 1);

        // Manually expire the entry by setting TTL to 0 and advancing time past it.
        correlator.ttl_ns = 1; // 1 nanosecond TTL.
        std::thread::sleep(std::time::Duration::from_millis(1)); // Ensure time passes.

        let expired_count = correlator.sweep_expired();
        assert_eq!(expired_count, 1);
        assert_eq!(correlator.pending.len(), 0);
    }

    #[test]
    fn ch_to_alert_produces_outcome_failed() {
        let mut correlator = Correlator::new();
        let key = ConnKey {
            src_addr: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            dst_addr: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            src_port: 12345,
            dst_port: 443,
        };

        let ch = tls_probe_parser::ParsedClientHello {
            legacy_version: 0x0303,
            random: [0u8; 32],
            session_id: vec![],
            cipher_suites: vec![0x1301],
            compression_methods: vec![0],
            extensions: vec![],
            supported_versions: vec![0x0304],
            supported_groups: vec![0x001D],
            signature_algorithms: vec![0x0403],
            signature_algorithms_cert: vec![],
            key_share_groups: vec![0x001D],
            sni: Some("example.com".to_string()),
            psk_offered: false,
            early_data_offered: false,
            psk_key_exchange_modes_offered: false,
            session_ticket_offered: false,
            extension_ids: vec![],
            alpn: vec![],
        };
        let ch_analysis = TlsAnalysis::ClientHello {
            record_version: 0x0303,
            hello: Box::new(ch),
        };

        correlator.on_client_hello(key, &ch_analysis);

        // Alert received (level=2=fatal, description=70=protocol_version).
        let neg = correlator.on_alert(key, 2, 70);
        assert!(neg.is_some());
        let neg = neg.unwrap();
        assert_eq!(neg.outcome, "failed");
        assert_eq!(neg.client_max_version, "TLS 1.3");
        assert_eq!(neg.selected_group, None);
        // Verify offered_groups contains the offered group (0x001D).
        assert_eq!(neg.client_offered_groups.len(), 1);
        assert_eq!(neg.client_offered_groups[0].id, 0x001D);
        assert_eq!(neg.client_sni, Some("example.com".to_string()));

        // Entry should be evicted after alert join.
        assert_eq!(correlator.pending.len(), 0);
    }

    #[test]
    fn alert_without_ch_returns_none() {
        let mut correlator = Correlator::new();
        let key = ConnKey {
            src_addr: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            dst_addr: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            src_port: 12345,
            dst_port: 443,
        };

        let neg = correlator.on_alert(key, 2, 70);
        assert!(neg.is_none());
        assert_eq!(correlator.pending.len(), 0);
    }

    #[test]
    fn ch_to_sh_then_alert_is_dropped() {
        let mut correlator = Correlator::new();
        let key = ConnKey {
            src_addr: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            dst_addr: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            src_port: 12345,
            dst_port: 443,
        };

        let ch = tls_probe_parser::ParsedClientHello {
            legacy_version: 0x0303,
            random: [0u8; 32],
            session_id: vec![],
            cipher_suites: vec![0x1301],
            compression_methods: vec![0],
            extensions: vec![],
            extension_ids: vec![],
            supported_versions: vec![0x0304],
            supported_groups: vec![],
            signature_algorithms: vec![],
            signature_algorithms_cert: vec![],
            key_share_groups: vec![],
            sni: None,
            alpn: vec![],
            psk_offered: false,
            early_data_offered: false,
            psk_key_exchange_modes_offered: false,
            session_ticket_offered: false,
        };
        let ch_analysis = TlsAnalysis::ClientHello {
            record_version: 0x0303,
            hello: Box::new(ch),
        };

        correlator.on_client_hello(key, &ch_analysis);

        // SH arrives and consumes the CH entry.
        let sh = tls_probe_parser::ParsedServerHello {
            legacy_version: 0x0303,
            random: [0u8; 32],
            session_id: vec![],
            cipher_suite: 0x1301,
            compression_method: 0,
            extensions: vec![],
            negotiated_version: Some(0x0304),
            key_share_group: None,
            psk_selected: false,
        };
        let sh_analysis = TlsAnalysis::ServerHello {
            record_version: 0x0303,
            hello: sh,
        };

        let _neg_sh = correlator.on_server_hello(key, &sh_analysis);
        assert_eq!(correlator.pending.len(), 0); // CH entry consumed by SH.

        // Subsequent alert arrives: no CH in correlator, alert is dropped.
        let neg_alert = correlator.on_alert(key, 2, 70);
        assert!(neg_alert.is_none());
    }

    #[test]
    fn mtls_flow_tls_1_2_certificate_request_and_client_cert() {
        let mut correlator = Correlator::new();
        let key = ConnKey {
            src_addr: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            dst_addr: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            src_port: 12345,
            dst_port: 443,
        };

        // CH offering TLS 1.2.
        let ch = tls_probe_parser::ParsedClientHello {
            legacy_version: 0x0303,
            random: [0u8; 32],
            session_id: vec![],
            cipher_suites: vec![0xC02F],
            compression_methods: vec![0],
            extensions: vec![],
            extension_ids: vec![],
            supported_versions: vec![0x0303],
            supported_groups: vec![0x001D],
            signature_algorithms: vec![0x0403],
            signature_algorithms_cert: vec![],
            key_share_groups: vec![],
            sni: Some("example.com".to_string()),
            alpn: vec![],
            psk_offered: false,
            early_data_offered: false,
            psk_key_exchange_modes_offered: false,
            session_ticket_offered: false,
        };
        let ch_analysis = TlsAnalysis::ClientHello {
            record_version: 0x0303,
            hello: Box::new(ch),
        };

        correlator.on_client_hello(key, &ch_analysis);

        // Server sends CertificateRequest (before SH for testing mTLS state tracking).
        correlator.on_certificate_request(key);

        // Retrieve the summary and check mtls_requested was set.
        let (summary, _) = correlator.pending.get(&key).unwrap();
        assert!(summary.mtls_requested);
        assert!(!(summary.mtls));

        // Client sends Certificate.
        correlator.on_client_certificate(key);

        // Check both flags are set.
        let (summary, _) = correlator.pending.get(&key).unwrap();
        assert!(summary.mtls_requested);
        assert!(summary.mtls);

        // Now complete the negotiation with SH.
        let sh = tls_probe_parser::ParsedServerHello {
            legacy_version: 0x0303,
            random: [0u8; 32],
            session_id: vec![],
            cipher_suite: 0xC02F,
            compression_method: 0,
            extensions: vec![],
            negotiated_version: Some(0x0303),
            key_share_group: None,
            psk_selected: false,
        };
        let sh_analysis = TlsAnalysis::ServerHello {
            record_version: 0x0303,
            hello: sh,
        };

        let neg = correlator.on_server_hello(key, &sh_analysis).unwrap();
        assert_eq!(neg.outcome, "negotiated");
        assert_eq!(neg.client_max_version, "TLS 1.2");
        assert!(neg.mtls_requested);
        assert!(neg.mtls);
    }

    #[test]
    fn mtls_flags_persist_to_final_negotiation() {
        let mut correlator = Correlator::new();
        let key = ConnKey {
            src_addr: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            dst_addr: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            src_port: 12345,
            dst_port: 443,
        };

        let ch = tls_probe_parser::ParsedClientHello {
            legacy_version: 0x0303,
            random: [0u8; 32],
            session_id: vec![],
            cipher_suites: vec![0xC02F],
            compression_methods: vec![0],
            extensions: vec![],
            extension_ids: vec![],
            supported_versions: vec![0x0303],
            supported_groups: vec![0x001D],
            signature_algorithms: vec![0x0403],
            signature_algorithms_cert: vec![],
            key_share_groups: vec![],
            sni: None,
            alpn: vec![],
            psk_offered: false,
            early_data_offered: false,
            psk_key_exchange_modes_offered: false,
            session_ticket_offered: false,
        };
        let ch_analysis = TlsAnalysis::ClientHello {
            record_version: 0x0303,
            hello: Box::new(ch),
        };

        correlator.on_client_hello(key, &ch_analysis);
        correlator.on_certificate_request(key);
        correlator.on_client_certificate(key);

        let sh = tls_probe_parser::ParsedServerHello {
            legacy_version: 0x0303,
            random: [0u8; 32],
            session_id: vec![],
            cipher_suite: 0xC02F,
            compression_method: 0,
            extensions: vec![],
            negotiated_version: Some(0x0303),
            key_share_group: None,
            psk_selected: false,
        };
        let sh_analysis = TlsAnalysis::ServerHello {
            record_version: 0x0303,
            hello: sh,
        };

        let neg = correlator.on_server_hello(key, &sh_analysis).unwrap();
        assert!(neg.mtls_requested);
        assert!(neg.mtls);
    }

    #[test]
    fn certificate_request_on_nonexistent_flow_ignored() {
        let mut correlator = Correlator::new();
        let key = ConnKey {
            src_addr: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            dst_addr: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            src_port: 12345,
            dst_port: 443,
        };

        // Call on_certificate_request on a flow with no CH: should not panic or error.
        correlator.on_certificate_request(key);
        assert_eq!(correlator.pending.len(), 0);
    }

    #[test]
    fn client_certificate_on_nonexistent_flow_ignored() {
        let mut correlator = Correlator::new();
        let key = ConnKey {
            src_addr: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            dst_addr: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            src_port: 12345,
            dst_port: 443,
        };

        // Call on_client_certificate on a flow with no CH: should not panic or error.
        correlator.on_client_certificate(key);
        assert_eq!(correlator.pending.len(), 0);
    }
}
