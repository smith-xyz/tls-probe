//! TLS protocol constants: record types, handshake types, versions, extensions, cipher suites, signature algorithms, and related codes.
//!
//! Organized by protocol area with named byte/word constants replacing magic numbers throughout the codebase.
//! See RFC 5246 (TLS 1.2) and RFC 8446 (TLS 1.3) for normative definitions.

// ============================================================================
// TLS Record Content Types (RFC 5246 §6.2.1)
// ============================================================================

/// Content type: change_cipher_spec (0x14)
pub const CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 0x14;

/// Content type: alert (0x15)
pub const CONTENT_TYPE_ALERT: u8 = 0x15;

/// Content type: handshake (0x16)
pub const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;

/// Content type: application_data (0x17)
pub const CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;

// ============================================================================
// TLS Handshake Types (RFC 5246 §7.4, RFC 8446 §4)
// ============================================================================

/// Handshake type: client_hello (0x01)
pub const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;

/// Handshake type: server_hello (0x02)
pub const HANDSHAKE_SERVER_HELLO: u8 = 0x02;

/// Handshake type: new_session_ticket (0x04)
pub const HANDSHAKE_NEW_SESSION_TICKET: u8 = 0x04;

/// Handshake type: encrypted_extensions (0x08, TLS 1.3)
pub const HANDSHAKE_ENCRYPTED_EXTENSIONS: u8 = 0x08;

/// Handshake type: certificate (0x0B)
pub const HANDSHAKE_CERTIFICATE: u8 = 0x0B;

/// Handshake type: certificate_request (0x0D)
pub const HANDSHAKE_CERTIFICATE_REQUEST: u8 = 0x0D;

/// Handshake type: certificate_verify (0x0F)
pub const HANDSHAKE_CERTIFICATE_VERIFY: u8 = 0x0F;

/// Handshake type: finished (0x14)
pub const HANDSHAKE_FINISHED: u8 = 0x14;

// ============================================================================
// TLS Record Versions (as sent in record header, RFC 5246 §6.2)
// ============================================================================

/// Record version: SSL 3.0 (0x0300) — legacy identifier
pub const VERSION_SSL_3_0: u16 = 0x0300;

/// Record version: TLS 1.0 (0x0301)
pub const VERSION_TLS_1_0: u16 = 0x0301;

/// Record version: TLS 1.1 (0x0302)
pub const VERSION_TLS_1_1: u16 = 0x0302;

/// Record version: TLS 1.2 (0x0303) — most common record version
pub const VERSION_TLS_1_2: u16 = 0x0303;

/// Record version: TLS 1.3 (0x0304) — negotiated via supported_versions extension
pub const VERSION_TLS_1_3: u16 = 0x0304;

// ============================================================================
// TLS Extensions (RFC 5246 §7.4.1.4, RFC 8446 §4.2)
// ============================================================================

/// Extension: server_name (SNI, 0x0000)
pub const EXT_SERVER_NAME: u16 = 0x0000;

/// Extension: signature_algorithms (0x000D)
pub const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000D;

/// Extension: supported_groups (formerly elliptic_curves, 0x000A)
pub const EXT_SUPPORTED_GROUPS: u16 = 0x000A;

/// Extension: application_layer_protocol_negotiation (ALPN, 0x0010)
pub const EXT_ALPN: u16 = 0x0010;

/// Extension: session_ticket (0x0023)
pub const EXT_SESSION_TICKET: u16 = 0x0023;

/// Extension: pre_shared_key (PSK, 0x0029, TLS 1.3)
pub const EXT_PSK: u16 = 0x0029;

/// Extension: early_data (0x002A, TLS 1.3 0-RTT)
pub const EXT_EARLY_DATA: u16 = 0x002A;

/// Extension: supported_versions (0x002B, TLS 1.3)
pub const EXT_SUPPORTED_VERSIONS: u16 = 0x002B;

/// Extension: psk_key_exchange_modes (0x002D, TLS 1.3)
pub const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002D;

/// Extension: signature_algorithms_cert (0x0032, TLS 1.3)
pub const EXT_SIGNATURE_ALGORITHMS_CERT: u16 = 0x0032;

/// Extension: key_share (0x0033, TLS 1.3)
pub const EXT_KEY_SHARE: u16 = 0x0033;

// ============================================================================
// Signature Algorithms (RFC 5246 §7.4.1.4.1, RFC 8446 §4.2.3, Post-Quantum)
// ============================================================================

// RSA (PKCS#1 v1.5)
pub const SIG_ALG_RSA_PKCS1_SHA1: u16 = 0x0201;
pub const SIG_ALG_RSA_PKCS1_SHA224: u16 = 0x0301;
pub const SIG_ALG_RSA_PKCS1_SHA256: u16 = 0x0401;
pub const SIG_ALG_RSA_PKCS1_SHA384: u16 = 0x0501;
pub const SIG_ALG_RSA_PKCS1_SHA512: u16 = 0x0601;

// ECDSA
pub const SIG_ALG_ECDSA_SHA1: u16 = 0x0203;
pub const SIG_ALG_ECDSA_SECP256R1_SHA256: u16 = 0x0403;
pub const SIG_ALG_ECDSA_SECP384R1_SHA384: u16 = 0x0503;
pub const SIG_ALG_ECDSA_SECP521R1_SHA512: u16 = 0x0603;

// DSA
pub const SIG_ALG_DSA_SHA1: u16 = 0x0202;
pub const SIG_ALG_DSA_SHA224: u16 = 0x0302;
pub const SIG_ALG_DSA_SHA256: u16 = 0x0402;

// RSA PSS (RFC 8017)
pub const SIG_ALG_RSA_PSS_RSAE_SHA256: u16 = 0x0804;
pub const SIG_ALG_RSA_PSS_RSAE_SHA384: u16 = 0x0805;
pub const SIG_ALG_RSA_PSS_RSAE_SHA512: u16 = 0x0806;
pub const SIG_ALG_RSA_PSS_PSS_SHA256: u16 = 0x0809;
pub const SIG_ALG_RSA_PSS_PSS_SHA384: u16 = 0x080A;
pub const SIG_ALG_RSA_PSS_PSS_SHA512: u16 = 0x080B;

// EdDSA
pub const SIG_ALG_ED25519: u16 = 0x0807;
pub const SIG_ALG_ED448: u16 = 0x0808;

// Brainpool (RFC 8734)
pub const SIG_ALG_ECDSA_BRAINPOOL256: u16 = 0x081A;
pub const SIG_ALG_ECDSA_BRAINPOOL384: u16 = 0x081B;
pub const SIG_ALG_ECDSA_BRAINPOOL512: u16 = 0x081C;

// Post-Quantum: ML-DSA (FIPS 204 / RFC 9090-draft)
pub const SIG_ALG_MLDSA44: u16 = 0x0904;
pub const SIG_ALG_MLDSA65: u16 = 0x0905;
pub const SIG_ALG_MLDSA87: u16 = 0x0906;

// ============================================================================
// Named Groups / Key Exchange Groups (RFC 8422, RFC 7919, RFC 9090-draft, PQC hybrids)
// ============================================================================

// Elliptic Curve Diffie-Hellman (ECDH) groups
pub const KEX_SECP160R1: u16 = 0x0010;
pub const KEX_SECP192R1: u16 = 0x0013;
pub const KEX_SECP224R1: u16 = 0x0015;
pub const KEX_SECP256R1: u16 = 0x0017;
pub const KEX_SECP384R1: u16 = 0x0018;
pub const KEX_SECP521R1: u16 = 0x0019;
pub const KEX_X25519: u16 = 0x001D;
pub const KEX_X448: u16 = 0x001E;

// Finite Field Diffie-Hellman (FFDH) groups (RFC 7919)
pub const KEX_FFDHE2048: u16 = 0x0100;
pub const KEX_FFDHE3072: u16 = 0x0101;
pub const KEX_FFDHE4096: u16 = 0x0102;
pub const KEX_FFDHE6144: u16 = 0x0103;
pub const KEX_FFDHE8192: u16 = 0x0104;

// Standalone ML-KEM (draft-connolly-tls-mlkem-key-agreement-05)
pub const KEX_MLKEM512: u16 = 0x0200;
pub const KEX_MLKEM768: u16 = 0x0201;
pub const KEX_MLKEM1024: u16 = 0x0202;

// Hybrid PQ: ECDH with ML-KEM (RFC-ietf-tls-ecdhe-mlkem-05)
pub const KEX_SECP256R1_MLKEM512: u16 = 0x11E9;
pub const KEX_MLKEM512_X25519: u16 = 0x11EA;
pub const KEX_SECP256R1_MLKEM768: u16 = 0x11EB;
pub const KEX_X25519_MLKEM768: u16 = 0x11EC;
pub const KEX_SECP384R1_MLKEM1024: u16 = 0x11ED;

// Pre-standard Kyber (obsoleted by RFC-ietf-tls-ecdhe-mlkem-05 §8)
pub const KEX_X25519_KYBER768_DRAFT00: u16 = 0x6399;
pub const KEX_SECP256R1_KYBER768_DRAFT00: u16 = 0x639A;

// ============================================================================
// Alert Codes (RFC 8446 §6)
// ============================================================================

pub const ALERT_CLOSE_NOTIFY: u8 = 0;
pub const ALERT_UNEXPECTED_MESSAGE: u8 = 10;
pub const ALERT_BAD_RECORD_MAC: u8 = 20;
pub const ALERT_RECORD_OVERFLOW: u8 = 22;
pub const ALERT_HANDSHAKE_FAILURE: u8 = 40;
pub const ALERT_BAD_CERTIFICATE: u8 = 42;
pub const ALERT_UNSUPPORTED_CERTIFICATE: u8 = 43;
pub const ALERT_CERTIFICATE_REVOKED: u8 = 44;
pub const ALERT_CERTIFICATE_EXPIRED: u8 = 45;
pub const ALERT_CERTIFICATE_UNKNOWN: u8 = 46;
pub const ALERT_ILLEGAL_PARAMETER: u8 = 47;
pub const ALERT_UNKNOWN_CA: u8 = 48;
pub const ALERT_ACCESS_DENIED: u8 = 49;
pub const ALERT_DECODE_ERROR: u8 = 50;
pub const ALERT_DECRYPT_ERROR: u8 = 51;
pub const ALERT_PROTOCOL_VERSION: u8 = 70;
pub const ALERT_INSUFFICIENT_SECURITY: u8 = 71;
pub const ALERT_INTERNAL_ERROR: u8 = 80;
pub const ALERT_INAPPROPRIATE_FALLBACK: u8 = 86;
pub const ALERT_USER_CANCELED: u8 = 90;
pub const ALERT_MISSING_EXTENSION: u8 = 109;
pub const ALERT_UNSUPPORTED_EXTENSION: u8 = 110;
pub const ALERT_UNRECOGNIZED_NAME: u8 = 112;
pub const ALERT_BAD_CERTIFICATE_STATUS_RESPONSE: u8 = 113;
pub const ALERT_UNKNOWN_PSK_IDENTITY: u8 = 115;
pub const ALERT_CERTIFICATE_REQUIRED: u8 = 116;
pub const ALERT_NO_APPLICATION_PROTOCOL: u8 = 120;

// ============================================================================
// Socket Address Families (Linux socket.h AF_* constants)
// ============================================================================

/// Address family: IPv4
pub const AF_INET: u32 = 2;

/// Address family: IPv6
pub const AF_INET6: u32 = 10;

// ============================================================================
// Predicate Functions
// ============================================================================

/// Checks if a 16-bit value matches the GREASE pattern (RFC 8701).
///
/// GREASE values have the form 0x?A?A (each byte matches 0xAA masked to the nibble).
/// They are used to encourage extensibility by appearing in ClientHello and ServerHello
/// without being assigned any semantic meaning.
#[inline]
pub fn is_grease(value: u16) -> bool {
    let hi = (value >> 8) as u8;
    let lo = (value & 0xFF) as u8;
    hi == lo && (hi & 0x0F) == 0x0A
}

/// Checks if a signature algorithm ID is post-quantum (ML-DSA).
#[inline]
pub fn is_pqc_sig_alg(id: u16) -> bool {
    (0x0904..=0x0906).contains(&id)
}

/// Checks if a named group ID is post-quantum or PQC-hybrid.
#[inline]
pub fn is_pqc_group(id: u16) -> bool {
    // Standalone ML-KEM: 0x0200-0x0202
    // Hybrid PQ: 0x11E9-0x11ED, 0x6399, 0x639A
    (0x0200..=0x0202).contains(&id)
        || (0x11E9..=0x11ED).contains(&id)
        || id == 0x6399
        || id == 0x639A
}

/// Checks if a handshake type is ClientHello.
#[inline]
pub fn is_client_hello(handshake_type: u8) -> bool {
    handshake_type == HANDSHAKE_CLIENT_HELLO
}

/// Checks if a handshake type is ServerHello.
#[inline]
pub fn is_server_hello(handshake_type: u8) -> bool {
    handshake_type == HANDSHAKE_SERVER_HELLO
}
