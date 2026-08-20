//! Multi-packet TLS record reassembly for oversized ClientHellos.
//! Keyed by (src, dst, src_port, dst_port); fragments ordered by tcp_seq.
//! Bounded LRU: 1024 flows max, per-entry cap of 4 × 4096 = 16 KB.
//! Timeouts on 3s sweep via counter tick; segment cap hit → truncated.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::BTreeMap;
use std::time::{Duration, Instant};
use tls_probe_common::RawTlsCapture;

/// Flow identifier for reassembly: 4-tuple of addresses, ports, and direction.
/// Direction is derived from FLAG_INGRESS to distinguish client and server packets
/// in bidirectional flows.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
struct FlowKey {
    src_addr: [u8; 16],
    dst_addr: [u8; 16],
    src_port: u16,
    dst_port: u16,
    dir: bool, // true = ingress, false = egress
}

impl FlowKey {
    /// Create a flow key from a capture event, used as the LRU map key.
    /// Direction is extracted from FLAG_INGRESS in the flags field.
    fn from_capture(cap: &RawTlsCapture) -> Self {
        Self {
            src_addr: cap.src_addr,
            dst_addr: cap.dst_addr,
            src_port: cap.src_port,
            dst_port: cap.dst_port,
            dir: cap.flags & tls_probe_common::FLAG_INGRESS != 0,
        }
    }
}

/// Metadata from the FLAG_FRAGMENT packet: addresses, ports, timestamp, pid, comm.
struct HeadInfo {
    seq: u32,
    capture: Box<RawTlsCapture>,
}

/// In-flight reassembly state for one flow.
struct ReassemblyEntry {
    fragments: BTreeMap<u32, Vec<u8>>, // tcp_seq -> payload
    created: Instant,
    head: Option<HeadInfo>,
    expected_total: Option<usize>,
}

/// Multi-packet TLS record reassembler: bounded LRU with timeout sweep.
pub struct Reassembler {
    flows: BTreeMap<FlowKey, ReassemblyEntry>,
    max_flows: usize,
    timeout: Duration,
}

impl Reassembler {
    /// Create a new reassembler with defaults:
    /// - 1024 flows max
    /// - 4 segments × 4096 bytes per flow = 16 KB per flow
    /// - 3 second timeout
    pub fn new() -> Self {
        Self {
            flows: BTreeMap::new(),
            max_flows: 1024,
            timeout: Duration::from_secs(3),
        }
    }

    /// Insert a fragment and attempt complete: returns assembled buffer if complete,
    /// or None if waiting for more fragments. On timeout or segment cap, completes
    /// with available prefix and sets `reassembled` and `truncated` flags.
    pub fn insert(&mut self, cap: &RawTlsCapture) -> Option<AssembledRecord> {
        // Non-fragmented: fast path if no fragment/continuation flags set.
        // FLAG_INGRESS is a direction marker, not a reassembly indicator.
        if cap.flags & (tls_probe_common::FLAG_FRAGMENT | tls_probe_common::FLAG_CONTINUATION) == 0
        {
            return None;
        }

        let key = FlowKey::from_capture(cap);
        let payload = cap.payload_slice().to_vec();

        // Check if this is the start of a fragment sequence.
        if cap.flags & tls_probe_common::FLAG_FRAGMENT != 0 {
            // FLAG_FRAGMENT: new or replacement entry with metadata.
            // Parse expected_total from TLS record header (must be at least 5 bytes).
            let expected_total = if payload.len() >= 5 {
                let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
                Some(record_len + 5) // TLS record: 5-byte header + payload
            } else {
                None
            };

            self.cleanup_if_over_limit();

            // If there's an orphan entry (no head), merge into it; else create new.
            if let Some(entry) = self.flows.get_mut(&key) {
                // Merge: set head and expected_total, keep buffered fragments.
                entry.head = Some(HeadInfo {
                    seq: cap.tcp_seq,
                    capture: Box::new(*cap),
                });
                entry.expected_total = expected_total;
                entry.fragments.insert(cap.tcp_seq, payload);
                return self.check_completion(&key);
            }

            // Create new entry.
            let mut entry = ReassemblyEntry {
                fragments: BTreeMap::new(),
                created: Instant::now(),
                head: Some(HeadInfo {
                    seq: cap.tcp_seq,
                    capture: Box::new(*cap),
                }),
                expected_total,
            };
            entry.fragments.insert(cap.tcp_seq, payload);
            self.flows.insert(key, entry);
            return self.check_completion(&key);
        }

        // This is a continuation.
        if cap.flags & tls_probe_common::FLAG_CONTINUATION != 0 {
            // Deduplicate: if this tcp_seq exists, ignore (retransmit).
            if let Some(entry) = self.flows.get(&key) {
                if entry.fragments.contains_key(&cap.tcp_seq) {
                    return None;
                }
            }

            // Get or create orphan entry (no head yet).
            self.flows.entry(key).or_insert_with(|| ReassemblyEntry {
                fragments: BTreeMap::new(),
                created: Instant::now(),
                head: None,
                expected_total: None,
            });

            if let Some(entry) = self.flows.get_mut(&key) {
                entry.fragments.insert(cap.tcp_seq, payload);

                // Check segment cap (4 segments max).
                if entry.fragments.len() >= 4 {
                    return self.finalize_entry(&key, true);
                }

                // Check timeout.
                if entry.created.elapsed() >= self.timeout {
                    return self.finalize_entry(&key, true);
                }

                return self.check_completion(&key);
            }
        }

        None
    }

    /// Check if reassembly is complete: walk fragments from head.seq,
    /// accumulating strictly contiguous bytes. If contiguous bytes >= expected_total,
    /// finalize with truncated=false and exact expected_total bytes.
    fn check_completion(&mut self, key: &FlowKey) -> Option<AssembledRecord> {
        let entry = self.flows.get(key)?;

        // Need both head and expected_total to verify completion.
        let head_seq = entry.head.as_ref()?.seq;
        let expected_total = entry.expected_total?;

        let mut contiguous_bytes = 0usize;
        let mut next_seq = head_seq;
        let mut buffer = Vec::new();

        for (frag_seq, frag_payload) in entry.fragments.iter() {
            if *frag_seq == next_seq {
                buffer.extend_from_slice(frag_payload);
                contiguous_bytes += frag_payload.len();
                next_seq = next_seq.wrapping_add(frag_payload.len() as u32);
            } else if *frag_seq > next_seq {
                // Gap detected; stop accumulating.
                break;
            }
            // Skip if *frag_seq < next_seq (should not happen with BTreeMap).
        }

        // Check if we have enough contiguous bytes.
        if contiguous_bytes >= expected_total {
            // Finalize: remove entry and return truncated buffer to exactly expected_total.
            if let Some(entry) = self.flows.remove(key) {
                buffer.truncate(expected_total);
                return Some(AssembledRecord {
                    head_capture: entry.head?.capture,
                    buffer,
                    truncated: false,
                });
            }
        }

        None
    }

    /// Called periodically to sweep expired entries (3s timeout).
    pub fn sweep_expired(&mut self) -> Vec<AssembledRecord> {
        let mut completed = Vec::new();
        let mut expired_keys = Vec::new();

        for (key, entry) in self.flows.iter() {
            if entry.created.elapsed() >= self.timeout {
                expired_keys.push(*key);
            }
        }

        for key in expired_keys {
            if let Some(record) = self.finalize_entry(&key, true) {
                completed.push(record);
            }
        }

        completed
    }

    /// Assemble contiguous bytes from head and return the buffer with truncated flag.
    /// If no head exists (orphan-only entry), return None (drop silently).
    fn finalize_entry(&mut self, key: &FlowKey, truncated: bool) -> Option<AssembledRecord> {
        let entry = self.flows.remove(key)?;
        let head = entry.head?;

        let head_seq = head.seq;
        let mut buffer = Vec::new();
        let mut next_seq = head_seq;

        for (frag_seq, frag_payload) in entry.fragments.iter() {
            if *frag_seq == next_seq {
                buffer.extend_from_slice(frag_payload);
                next_seq = next_seq.wrapping_add(frag_payload.len() as u32);
            } else if *frag_seq > next_seq {
                // Gap detected; stop accumulating.
                break;
            }
        }

        Some(AssembledRecord {
            head_capture: head.capture,
            buffer,
            truncated,
        })
    }

    /// Remove least-recently-created flow if over limit.
    fn cleanup_if_over_limit(&mut self) {
        if self.flows.len() >= self.max_flows {
            if let Some(&key) = self.flows.keys().next() {
                self.flows.remove(&key);
            }
        }
    }
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

/// Output of a completed reassembly.
/// Owned TLS record with assembled buffer and metadata from the head (FLAG_FRAGMENT) packet.
pub struct AssembledRecord {
    /// The head (FLAG_FRAGMENT) packet, carrying network addresses, ports, timestamp, pid, comm.
    /// Used to source the final event's metadata (capture.rs, Linux only).
    pub head_capture: Box<RawTlsCapture>,
    /// Assembled TLS record bytes (may exceed 4096 when reassembled).
    pub buffer: Vec<u8>,
    /// True if incomplete (gap, timeout, or segment cap); false if fully contiguous.
    pub truncated: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_capture(tcp_seq: u32, payload: &[u8], flags: u8) -> RawTlsCapture {
        let mut cap = RawTlsCapture {
            tcp_seq,
            flags,
            payload_len: payload.len() as u16,
            ..Default::default()
        };
        cap.payload[..payload.len()].copy_from_slice(payload);
        cap
    }

    #[test]
    fn in_order_two_fragment_completion() {
        let mut reasm = Reassembler::new();

        // Fragment 1: TLS record header (0x16, 0x03, 0x03, len=0x00, 0x0a) + "hello"
        // TLS record length is 10 bytes (len field = 0x0a), so expected_total = 10 + 5 = 15.
        // We only send 10 bytes in fragment 1: need 5 more in fragment 2.
        let mut frag1_payload = vec![0x16u8, 0x03, 0x03, 0x00, 0x0a];
        frag1_payload.extend_from_slice(b"hello"); // 5 bytes, total 10

        // Fragment 2: continuation " worl" (5 bytes)
        // tcp_seq = 100 + 10 = 110 (contiguous)
        let frag2_payload = b" worl";

        let cap1 = make_capture(100, &frag1_payload, tls_probe_common::FLAG_FRAGMENT);
        let cap2 = make_capture(110, frag2_payload, tls_probe_common::FLAG_CONTINUATION);

        assert!(reasm.insert(&cap1).is_none());
        let result = reasm.insert(&cap2);
        assert!(result.is_some());

        let record = result.unwrap();
        assert_eq!(record.buffer.len(), 15); // Exactly expected_total bytes.
        assert!(!record.truncated);
    }

    #[test]
    fn out_of_order_then_head_arrives() {
        let mut reasm = Reassembler::new();

        // Continuation arrives first (at seq 110, which is after seq 100+10).
        let cap_cont = make_capture(110, b" worl", tls_probe_common::FLAG_CONTINUATION);
        assert!(reasm.insert(&cap_cont).is_none());

        // Now the head fragment arrives with expected_total.
        let mut frag1_payload = vec![0x16u8, 0x03, 0x03, 0x00, 0x0a];
        frag1_payload.extend_from_slice(b"hello");
        let cap_head = make_capture(100, &frag1_payload, tls_probe_common::FLAG_FRAGMENT);

        let result = reasm.insert(&cap_head);
        assert!(result.is_some());

        let record = result.unwrap();
        assert_eq!(record.buffer.len(), 15);
        assert!(!record.truncated);
    }

    #[test]
    fn retransmit_dedup() {
        let mut reasm = Reassembler::new();

        let mut frag1_payload = vec![0x16u8, 0x03, 0x03, 0x00, 0x0a];
        frag1_payload.extend_from_slice(b"hello");

        let cap1 = make_capture(100, &frag1_payload, tls_probe_common::FLAG_FRAGMENT);
        let cap1_dup = make_capture(100, &frag1_payload, tls_probe_common::FLAG_CONTINUATION);

        assert!(reasm.insert(&cap1).is_none());
        // Duplicate with same tcp_seq is ignored.
        assert!(reasm.insert(&cap1_dup).is_none());
    }

    #[test]
    fn gap_prevents_completion() {
        let mut reasm = Reassembler::new();

        let mut frag1_payload = vec![0x16u8, 0x03, 0x03, 0x00, 0x0f]; // 15 bytes expected.
        frag1_payload.extend_from_slice(b"hello");

        let cap1 = make_capture(100, &frag1_payload, tls_probe_common::FLAG_FRAGMENT);
        let cap2 = make_capture(115, b"frag2", tls_probe_common::FLAG_CONTINUATION);
        // Gap: cap3 does not follow cap2 sequentially.
        let cap3 = make_capture(130, b"frag3", tls_probe_common::FLAG_CONTINUATION);

        assert!(reasm.insert(&cap1).is_none());
        assert!(reasm.insert(&cap2).is_none());
        assert!(reasm.insert(&cap3).is_none()); // No completion due to gap.

        // Verify entry still exists.
        assert_eq!(reasm.flows.len(), 1);
    }

    #[test]
    fn segment_cap_triggers_truncated() {
        let mut reasm = Reassembler::new();

        let mut frag1_payload = vec![0x16u8, 0x03, 0x03, 0x00, 0x20]; // expecting 32 + 5 = 37 bytes
        frag1_payload.extend_from_slice(b"seg1");

        let cap1 = make_capture(100, &frag1_payload, tls_probe_common::FLAG_FRAGMENT);
        let cap2 = make_capture(109, b"seg2", tls_probe_common::FLAG_CONTINUATION);
        let cap3 = make_capture(113, b"seg3", tls_probe_common::FLAG_CONTINUATION);
        let cap4 = make_capture(117, b"seg4", tls_probe_common::FLAG_CONTINUATION);

        assert!(reasm.insert(&cap1).is_none());
        assert!(reasm.insert(&cap2).is_none());
        assert!(reasm.insert(&cap3).is_none());
        let result = reasm.insert(&cap4);

        // At 4 segments, assembly is triggered with truncated=true.
        assert!(result.is_some());
        let record = result.unwrap();
        assert!(record.truncated);
    }

    #[test]
    fn lru_capacity() {
        let mut reasm = Reassembler::new();
        reasm.max_flows = 2; // Small limit for testing.

        let mut frag1_payload = vec![0x16u8, 0x03, 0x03, 0x00, 0x10]; // expecting 16 + 5 = 21 bytes
        frag1_payload.extend_from_slice(b"a");

        let cap1 = make_capture(100, &frag1_payload, tls_probe_common::FLAG_FRAGMENT);
        let mut cap2 = make_capture(101, &frag1_payload, tls_probe_common::FLAG_FRAGMENT);
        cap2.src_port = 1; // Different flow.

        let mut cap3 = make_capture(100, &frag1_payload, tls_probe_common::FLAG_FRAGMENT);
        cap3.src_port = 2; // Third flow, should evict first.

        reasm.insert(&cap1);
        reasm.insert(&cap2);
        assert_eq!(reasm.flows.len(), 2);

        reasm.insert(&cap3);
        // Oldest flow (cap1) is evicted.
        assert_eq!(reasm.flows.len(), 2);
    }

    #[test]
    fn timeout_sweep() {
        let mut reasm = Reassembler::new();
        reasm.timeout = Duration::from_millis(10); // Very short for testing.

        let mut frag1_payload = vec![0x16u8, 0x03, 0x03, 0x00, 0x10]; // expecting 16 + 5 = 21 bytes
        frag1_payload.extend_from_slice(b"data");

        let cap = make_capture(100, &frag1_payload, tls_probe_common::FLAG_FRAGMENT);
        reasm.insert(&cap);
        assert_eq!(reasm.flows.len(), 1);

        std::thread::sleep(Duration::from_millis(20));
        let expired = reasm.sweep_expired();

        assert_eq!(reasm.flows.len(), 0);
        assert_eq!(expired.len(), 1);
        assert!(expired[0].truncated);
    }

    #[test]
    fn orphan_only_entry_expires_silently() {
        let mut reasm = Reassembler::new();
        reasm.timeout = Duration::from_millis(10);

        // Only a continuation arrives (orphan entry, no head).
        let cap = make_capture(200, b"continuation", tls_probe_common::FLAG_CONTINUATION);
        reasm.insert(&cap);
        assert_eq!(reasm.flows.len(), 1);

        std::thread::sleep(Duration::from_millis(20));
        let expired = reasm.sweep_expired();

        // Orphan entry is removed silently (finalize_entry returns None).
        assert_eq!(reasm.flows.len(), 0);
        assert_eq!(expired.len(), 0);
    }

    #[test]
    fn direction_separation_egress_vs_ingress() {
        let mut reasm = Reassembler::new();

        // Create two captures with identical 4-tuple but different directions (flags).
        let mut frag1_payload = vec![0x16u8, 0x03, 0x03, 0x00, 0x0a];
        frag1_payload.extend_from_slice(b"hello");

        // Egress fragment (FLAG_FRAGMENT, no FLAG_INGRESS)
        let mut cap_egress = make_capture(100, &frag1_payload, tls_probe_common::FLAG_FRAGMENT);
        cap_egress.src_port = 8080;
        cap_egress.dst_port = 443;

        // Ingress fragment (FLAG_FRAGMENT | FLAG_INGRESS) - same 4-tuple, different direction
        let mut cap_ingress = make_capture(
            100,
            &frag1_payload,
            tls_probe_common::FLAG_FRAGMENT | tls_probe_common::FLAG_INGRESS,
        );
        cap_ingress.src_port = 8080;
        cap_ingress.dst_port = 443;

        // Insert both — they should create separate flows due to direction difference
        assert!(reasm.insert(&cap_egress).is_none());
        assert!(reasm.insert(&cap_ingress).is_none());

        // Verify two separate flow entries
        assert_eq!(reasm.flows.len(), 2);
    }

    #[test]
    fn fast_path_flag_ingress_only() {
        let mut reasm = Reassembler::new();

        // Create a capture with only FLAG_INGRESS set (no fragment/continuation flags).
        let cap = make_capture(100, b"test", tls_probe_common::FLAG_INGRESS);

        // Fast path should ignore it (return None, don't add to flows).
        let result = reasm.insert(&cap);
        assert!(result.is_none());
        assert_eq!(reasm.flows.len(), 0);
    }
}
