//! JA4 TLS client fingerprint per FoxIO spec.
//! Format: t + version + sni_marker + cipher_count + extension_count + alpn_chars + _ + cipher_hash + _ + extension_hash
//!
//! This fingerprint is designed to be:
//! - invariant to GREASE values in ciphers, extensions, and versions
//! - stable across minor TLS stack updates
//! - suitable for threat detection and client identification

#![allow(dead_code)]

use sha2::{Digest, Sha256};
use tls_probe_parser::ParsedClientHello;

/// Check whether a value is a GREASE placeholder (0x??0A where ? is the same in both bytes).
/// GREASE (GRE­ASE: Generate Random Extensions And Sustain Extensibility) are harmless reserved
/// values injected to ensure compatibility with new extensions/versions.
fn is_grease(value: u16) -> bool {
    let hi = (value >> 8) as u8;
    let lo = (value & 0xFF) as u8;
    hi == lo && (hi & 0x0F) == 0x0A
}

/// Map TLS version to JA4 version string.
/// Filters for GREASE values in supported_versions; uses the max GREASE-filtered version.
/// If no supported_versions ext, uses legacy_version.
fn ja4_version_string(hello: &ParsedClientHello) -> &'static str {
    let version = if hello.supported_versions.is_empty() {
        hello.legacy_version
    } else {
        // Find max non-GREASE version
        hello
            .supported_versions
            .iter()
            .copied()
            .filter(|&v| !is_grease(v))
            .max()
            .unwrap_or(hello.legacy_version)
    };

    match version {
        0x0304 => "13", // TLS 1.3
        0x0303 => "12", // TLS 1.2
        0x0302 => "11", // TLS 1.1
        0x0301 => "10", // TLS 1.0
        _ => "00",      // Unknown or older
    }
}

/// SNI marker: 'd' if SNI present, else 'i'.
fn sni_marker(hello: &ParsedClientHello) -> char {
    if hello.sni.is_some() {
        'd'
    } else {
        'i'
    }
}

/// ALPN characters: first and last character of the first ALPN protocol string.
/// If no ALPN: "00".
/// If first/last chars are non-alphanumeric, returns "99" per FoxIO spec guidance.
fn alpn_chars(hello: &ParsedClientHello) -> String {
    if hello.alpn.is_empty() {
        return "00".to_string();
    }

    let proto = &hello.alpn[0];
    if proto.is_empty() {
        return "00".to_string();
    }

    let first_char = proto.chars().next().unwrap_or('0');
    let last_char = proto.chars().last().unwrap_or('0');

    // Per spec: if first or last char is non-alphanumeric, use "99"
    if !first_char.is_ascii_alphanumeric() || !last_char.is_ascii_alphanumeric() {
        "99".to_string()
    } else {
        format!("{}{}", first_char, last_char)
    }
}

/// Cipher hash: SHA256 of comma-joined lowercase-hex 4-digit cipher ids, GREASE excluded, sorted.
/// First 12 hex chars. Empty list -> "000000000000".
fn cipher_hash(hello: &ParsedClientHello) -> String {
    let mut ciphers: Vec<u16> = hello
        .cipher_suites
        .iter()
        .copied()
        .filter(|&c| !is_grease(c))
        .collect();

    if ciphers.is_empty() {
        return "000000000000".to_string();
    }

    ciphers.sort_unstable();

    let cipher_str = ciphers
        .iter()
        .map(|c| format!("{:04x}", c))
        .collect::<Vec<_>>()
        .join(",");

    let hash = Sha256::digest(cipher_str.as_bytes());
    format!("{:x}", hash)[..12].to_string()
}

/// Extension hash: SHA256 of sorted extension ids (GREASE excluded, excluding SNI and ALPN),
/// then `_` + signature_algorithms in wire order.
/// Format: `ext1,ext2,...,extN_sig1,sig2`
/// First 12 hex chars. Empty -> "000000000000".
fn extension_hash(hello: &ParsedClientHello) -> String {
    let mut exts: Vec<u16> = hello
        .extension_ids
        .iter()
        .copied()
        .filter(|&e| {
            !is_grease(e) && e != 0x0000 && e != 0x0010 // Exclude GREASE, SNI (0x0000), ALPN (0x0010)
        })
        .collect();

    exts.sort_unstable();

    // Spec requires 4-digit lowercase hex ids, same as the cipher hash.
    let mut hash_input = exts
        .iter()
        .map(|e| format!("{:04x}", e))
        .collect::<Vec<_>>()
        .join(",");

    // Append signature_algorithms in wire order
    if !hello.signature_algorithms.is_empty() {
        hash_input.push('_');
        let sigs = hello
            .signature_algorithms
            .iter()
            .map(|s| format!("{:04x}", s))
            .collect::<Vec<_>>()
            .join(",");
        hash_input.push_str(&sigs);
    }

    if hash_input.is_empty() || hash_input == "_" {
        return "000000000000".to_string();
    }

    let hash = Sha256::digest(hash_input.as_bytes());
    format!("{:x}", hash)[..12].to_string()
}

/// Compute JA4 fingerprint for a ClientHello.
/// Returns the JA4 string per FoxIO spec.
pub fn ja4(hello: &ParsedClientHello) -> String {
    let version = ja4_version_string(hello);
    let sni = sni_marker(hello);

    // Count ciphers and extensions (GREASE excluded, capped at 99)
    let cipher_count = hello
        .cipher_suites
        .iter()
        .filter(|&&c| !is_grease(c))
        .count()
        .min(99);

    let extension_count = hello
        .extension_ids
        .iter()
        .filter(|&&e| !is_grease(e))
        .count()
        .min(99);

    let alpn = alpn_chars(hello);
    let c_hash = cipher_hash(hello);
    let e_hash = extension_hash(hello);

    // Format: t + version + sni + cipher_count + extension_count + alpn + _ + c_hash + _ + e_hash
    // Note: hardcoded "t" for TCP; "q" would be for QUIC (future)
    format!(
        "t{}{}{:02}{:02}{}_{}_{}",
        version, sni, cipher_count, extension_count, alpn, c_hash, e_hash
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-answer vector computed independently (python hashlib) per the
    /// FoxIO spec: ciphers sorted+hex-joined -> sha256[:12]; extensions
    /// sorted minus SNI/ALPN, "_", sigalgs in wire order -> sha256[:12].
    ///   cipher_str = "1301,1302,1303"          -> 55b375c5d22e
    ///   ext_str    = "000d,002b,0033_0804,0805" -> 87c083d729a1
    #[test]
    fn ja4_known_answer_vector() {
        let hello = test_hello(
            0x0303,
            vec![0x1301, 0x1302, 0x1303],
            vec![0x0000, 0x0010, 0x002b, 0x000d, 0x0033],
            Some("example.com".to_string()),
            vec!["h2".to_string()],
        );
        assert_eq!(ja4(&hello), "t13d0305h2_55b375c5d22e_87c083d729a1");
    }

    /// Helper to build a minimal ClientHello for testing.
    fn test_hello(
        legacy_version: u16,
        cipher_suites: Vec<u16>,
        extension_ids: Vec<u16>,
        sni: Option<String>,
        alpn: Vec<String>,
    ) -> ParsedClientHello {
        ParsedClientHello {
            legacy_version,
            random: [0u8; 32],
            session_id: Vec::new(),
            cipher_suites,
            compression_methods: vec![0],
            extensions: Vec::new(),
            extension_ids,
            supported_versions: vec![0x0304],
            supported_groups: Vec::new(),
            signature_algorithms: vec![0x0804, 0x0805], // Example sigs
            signature_algorithms_cert: Vec::new(),
            key_share_groups: Vec::new(),
            sni,
            alpn,
            psk_offered: false,
            early_data_offered: false,
            psk_key_exchange_modes_offered: false,
            session_ticket_offered: false,
        }
    }

    #[test]
    fn test_grease_detection() {
        assert!(is_grease(0x0A0A));
        assert!(is_grease(0x1A1A));
        assert!(is_grease(0xFAFA));
        assert!(!is_grease(0x0000));
        assert!(!is_grease(0x0A0B));
        assert!(!is_grease(0x1301));
    }

    #[test]
    fn test_version_string() {
        let hello = test_hello(0x0303, vec![0x1301], vec![], None, vec![]);
        assert_eq!(ja4_version_string(&hello), "13");
    }

    #[test]
    fn test_sni_marker_with_sni() {
        let hello = test_hello(
            0x0303,
            vec![0x1301],
            vec![],
            Some("example.com".into()),
            vec![],
        );
        assert_eq!(sni_marker(&hello), 'd');
    }

    #[test]
    fn test_sni_marker_without_sni() {
        let hello = test_hello(0x0303, vec![0x1301], vec![], None, vec![]);
        assert_eq!(sni_marker(&hello), 'i');
    }

    #[test]
    fn test_alpn_chars_present() {
        let hello = test_hello(0x0303, vec![0x1301], vec![], None, vec!["h2".into()]);
        assert_eq!(alpn_chars(&hello), "h2");
    }

    #[test]
    fn test_alpn_chars_http_1_1() {
        let hello = test_hello(0x0303, vec![0x1301], vec![], None, vec!["http/1.1".into()]);
        assert_eq!(alpn_chars(&hello), "h1");
    }

    #[test]
    fn test_alpn_chars_absent() {
        let hello = test_hello(0x0303, vec![0x1301], vec![], None, vec![]);
        assert_eq!(alpn_chars(&hello), "00");
    }

    #[test]
    fn test_alpn_chars_non_alphanumeric() {
        let hello = test_hello(0x0303, vec![0x1301], vec![], None, vec!["_test".into()]);
        assert_eq!(alpn_chars(&hello), "99");
    }

    #[test]
    fn test_cipher_hash_basic() {
        // Simple case: two ciphers, no GREASE
        let hello = test_hello(0x0303, vec![0x1301, 0x1302], vec![], None, vec![]);
        let hash = cipher_hash(&hello);
        assert_eq!(hash.len(), 12);
        // Verify it's hex
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_cipher_hash_with_grease() {
        // Same ciphers but with GREASE inserted → should produce same hash
        let hello1 = test_hello(0x0303, vec![0x1301, 0x1302], vec![], None, vec![]);
        let hello2 = test_hello(
            0x0303,
            vec![0x0A0A, 0x1301, 0x1A1A, 0x1302],
            vec![],
            None,
            vec![],
        );

        let hash1 = cipher_hash(&hello1);
        let hash2 = cipher_hash(&hello2);
        assert_eq!(
            hash1, hash2,
            "GREASE insertion should not change cipher hash"
        );
    }

    #[test]
    fn test_cipher_hash_empty() {
        let hello = test_hello(0x0303, vec![], vec![], None, vec![]);
        assert_eq!(cipher_hash(&hello), "000000000000");
    }

    #[test]
    fn test_extension_hash_basic() {
        // Extensions excluding SNI (0x0000) and ALPN (0x0010)
        let hello = test_hello(0x0303, vec![0x1301], vec![0x000D, 0x000A], None, vec![]);
        let hash = extension_hash(&hello);
        assert_eq!(hash.len(), 12);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_extension_hash_excludes_sni_alpn() {
        // With SNI and ALPN
        let hello = test_hello(
            0x0303,
            vec![0x1301],
            vec![0x0000, 0x000D, 0x0010, 0x000A],
            None,
            vec![],
        );
        let hash = extension_hash(&hello);
        // Should be same as without SNI/ALPN
        let hello2 = test_hello(0x0303, vec![0x1301], vec![0x000D, 0x000A], None, vec![]);
        assert_eq!(hash, extension_hash(&hello2));
    }

    #[test]
    fn test_ja4_format() {
        let hello = test_hello(
            0x0303,
            vec![0x1301, 0x1302],
            vec![0x0000, 0x000D, 0x000A, 0x0010],
            Some("example.com".into()),
            vec!["h2".into()],
        );
        let ja4_str = ja4(&hello);

        // Check format: t + version + sni + cipher_count + extension_count + alpn + _ + c_hash + _ + e_hash
        assert!(ja4_str.starts_with("t13d"));
        let parts: Vec<&str> = ja4_str.split('_').collect();
        assert_eq!(parts.len(), 3, "Expected 3 parts separated by _");

        // First part: t + version + sni + counts + alpn
        assert!(parts[0].ends_with("h2")); // alpn_chars

        // Second and third parts should be 12-char hex hashes
        assert_eq!(parts[1].len(), 12);
        assert_eq!(parts[2].len(), 12);
    }

    #[test]
    fn test_ja4_grease_invariance() {
        // Two hellos that differ only in GREASE values should have same JA4
        let hello1 = test_hello(
            0x0303,
            vec![0x1301, 0x1302],
            vec![0x000D, 0x000A],
            Some("example.com".into()),
            vec!["h2".into()],
        );

        let mut hello2 = hello1.clone();
        // Add GREASE to hello2
        hello2.cipher_suites.insert(0, 0x0A0A);
        hello2.cipher_suites.push(0x1A1A);
        hello2.extension_ids.insert(0, 0x2A2A);
        hello2.supported_versions.push(0x3A3A);

        let ja4_1 = ja4(&hello1);
        let ja4_2 = ja4(&hello2);

        assert_eq!(ja4_1, ja4_2, "GREASE insertion should not change JA4");
    }

    #[test]
    fn test_ja4_count_capping() {
        // Create a hello with >99 ciphers and extensions
        let mut ciphers = vec![0x1301];
        for i in 0..150 {
            if !is_grease(i as u16) {
                ciphers.push(0x1000 + i as u16);
            }
        }

        let mut exts = vec![0x000D];
        for i in 0..150 {
            let e = 0x1000 + i as u16;
            if !is_grease(e) {
                exts.push(e);
            }
        }

        let hello = ParsedClientHello {
            legacy_version: 0x0303,
            random: [0u8; 32],
            session_id: Vec::new(),
            cipher_suites: ciphers,
            compression_methods: vec![0],
            extensions: Vec::new(),
            extension_ids: exts,
            supported_versions: vec![0x0304],
            supported_groups: Vec::new(),
            signature_algorithms: vec![0x0804],
            signature_algorithms_cert: Vec::new(),
            key_share_groups: Vec::new(),
            sni: Some("test.com".into()),
            alpn: vec!["h2".into()],
            psk_offered: false,
            early_data_offered: false,
            psk_key_exchange_modes_offered: false,
            session_ticket_offered: false,
        };

        let ja4_str = ja4(&hello);
        // Extract the counts from the JA4 string: t13d{cc}{ee}h2_...
        let counts_part = &ja4_str[4..8]; // Skip "t13d"
        assert_eq!(counts_part, "9999", "Counts should be capped at 99");
    }
}
