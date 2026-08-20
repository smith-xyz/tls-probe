//! Certificate parsing from TLS Certificate handshake messages.
//!
//! Extracts and parses the leaf certificate from TLS 1.2 and TLS 1.3 Certificate messages.
//! Wire format (RFC 5246/8446):
//! - Handshake header: type 0x0B, u24 length
//! - u24 certificates_list_length (total bytes of all certs, including their u24 lengths)
//! - For each certificate: u24 length + DER bytes
//! - (Optional) Extensions (TLS 1.3 only)
//!
//! We extract the FIRST DER blob (leaf certificate) and parse it with x509-parser.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use schemars::JsonSchema;
use serde::Serialize;

/// Parsed leaf certificate from a TLS Certificate handshake message.
#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
pub struct Certificate {
    /// RFC 3339 timestamp (not_before)
    pub not_before: String,
    /// RFC 3339 timestamp (not_after)
    pub not_after: String,
    /// Whether the certificate has expired relative to capture wall clock
    pub expired: bool,
    /// Public key algorithm: "rsa", "ec", "dsa", or "unknown"
    pub public_key_algorithm: String,
    /// Public key size: RSA modulus bits or EC curve size
    pub public_key_bits: u16,
    /// Signature algorithm from the certificate: "sha256WithRSAEncryption", etc.
    pub signature_algorithm: String,
    /// Whether issuer == subject
    pub self_signed: bool,
    /// Subject CN; None if absent
    pub subject_cn: Option<String>,
    /// Issuer CN; None if absent
    pub issuer_cn: Option<String>,
    /// Count of Subject Alternative Names (SAN)
    pub san_count: u16,
}

/// Parses a TLS Certificate handshake message payload and extracts the leaf certificate.
///
/// **Ownership**: Takes a reference to the payload slice; does not retain or allocate
/// beyond the parsing operation. The returned Certificate is owned by the caller.
///
/// Returns None if:
/// - Payload is too short (< 3 bytes for certificate list length)
/// - First certificate is truncated or malformed
/// - x509 parsing fails
pub fn parse_certificate(payload: &[u8]) -> Option<Certificate> {
    if payload.len() < 3 {
        return None;
    }

    // Read u24 certificates_list_length (big-endian).
    let cert_list_len = u24_from_be(&payload[0..3]) as usize;

    // Minimum check: u24 + at least one u24 length field for first cert.
    if payload.len() < 6 || cert_list_len < 3 {
        return None;
    }

    // Extract first certificate's u24 length.
    let first_cert_len = u24_from_be(&payload[3..6]) as usize;

    // Check if the first certificate's DER bytes are fully present.
    if payload.len() < 6 + first_cert_len {
        return None;
    }

    // Extract the first DER blob (leaf).
    let der_bytes = &payload[6..6 + first_cert_len];

    // Parse the DER certificate.
    parse_der_certificate(der_bytes)
}

/// Parses a DER-encoded X.509 certificate and extracts key fields.
fn parse_der_certificate(der_bytes: &[u8]) -> Option<Certificate> {
    #[allow(unused_imports)]
    use x509_parser::prelude::{parse_x509_certificate, X509Certificate};

    let (_, cert) = parse_x509_certificate(der_bytes).ok()?;

    // Extract not_before and not_after using RFC3339 formatting.
    let not_before = asn1_time_to_rfc3339(&cert.validity().not_before);
    let not_after = asn1_time_to_rfc3339(&cert.validity().not_after);

    // Determine if expired (compare not_after with current time).
    let expired = is_certificate_expired(&cert.validity().not_after);

    // Extract public key algorithm and size.
    let (pk_alg, pk_bits) = extract_public_key_info(&cert);

    // Extract signature algorithm from the signature_algorithm field.
    let sig_alg = extract_signature_algorithm_name(&cert);

    // Extract issuer and subject CNs.
    let subject_cn = extract_cn(cert.subject());
    let issuer_cn = extract_cn(cert.issuer());

    // Determine self-signed (issuer == subject).
    let self_signed = cert.issuer() == cert.subject();

    // Count SANs.
    let san_count = count_san_entries(&cert);

    Some(Certificate {
        not_before,
        not_after,
        expired,
        public_key_algorithm: pk_alg,
        public_key_bits: pk_bits,
        signature_algorithm: sig_alg,
        self_signed,
        subject_cn,
        issuer_cn,
        san_count,
    })
}

/// Reads a u24 big-endian value from a 3-byte slice.
fn u24_from_be(bytes: &[u8]) -> u32 {
    ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | (bytes[2] as u32)
}

/// Converts an ASN.1 time to RFC 3339 string.
fn asn1_time_to_rfc3339(time: &x509_parser::time::ASN1Time) -> String {
    // to_datetime() returns an OffsetDateTime from the time crate.
    // Convert to chrono for RFC 3339 formatting.
    let dt = time.to_datetime();
    let timestamp = dt.unix_timestamp();
    if let Some(chrono_dt) = chrono::DateTime::<chrono::Utc>::from_timestamp(timestamp, 0) {
        chrono_dt.to_rfc3339()
    } else {
        "1970-01-01T00:00:00Z".to_string()
    }
}

/// Checks if a certificate has expired relative to the current wall clock.
fn is_certificate_expired(not_after: &x509_parser::time::ASN1Time) -> bool {
    // to_datetime() returns an OffsetDateTime from the time crate.
    let exp_dt = not_after.to_datetime();
    let exp_timestamp = exp_dt.unix_timestamp();
    let now = chrono::Utc::now();
    now.timestamp() > exp_timestamp
}

use x509_parser::der_parser::asn1_rs::{oid, Oid};

/// Public key algorithms the probe names, keyed by the OID that declares them.
/// Each variant pairs the defining RFC's OID with the emitted string in one place.
#[derive(Debug, Clone, Copy, PartialEq)]
enum PublicKeyAlgorithm {
    /// PKCS#1 rsaEncryption (RFC 8017).
    Rsa,
    /// id-ecPublicKey (RFC 5480). The curve is a separate OID in the
    /// AlgorithmIdentifier parameters, not part of this one.
    Ec,
    /// id-dsa (RFC 3279).
    Dsa,
    Unknown,
}

impl PublicKeyAlgorithm {
    const BY_OID: &'static [(Oid<'static>, PublicKeyAlgorithm)] = &[
        (oid!(1.2.840 .113549 .1 .1 .1), PublicKeyAlgorithm::Rsa),
        (oid!(1.2.840 .10045 .2 .1), PublicKeyAlgorithm::Ec),
        (oid!(1.2.840 .10040 .4 .1), PublicKeyAlgorithm::Dsa),
    ];

    fn from_oid(oid: &Oid<'_>) -> Self {
        Self::BY_OID
            .iter()
            .find(|(known, _)| known == oid)
            .map(|&(_, alg)| alg)
            .unwrap_or(PublicKeyAlgorithm::Unknown)
    }

    fn as_str(self) -> &'static str {
        match self {
            PublicKeyAlgorithm::Rsa => "rsa",
            PublicKeyAlgorithm::Ec => "ec",
            PublicKeyAlgorithm::Dsa => "dsa",
            PublicKeyAlgorithm::Unknown => "unknown",
        }
    }
}

/// Certificate signature algorithms the probe names (RFC 8017 for RSA,
/// RFC 5758 for ECDSA), OID → variant → emitted string in one place.
#[derive(Debug, Clone, Copy, PartialEq)]
enum SignatureAlgorithm {
    Sha1WithRsa,
    Sha256WithRsa,
    Sha384WithRsa,
    Sha512WithRsa,
    EcdsaWithSha256,
    EcdsaWithSha384,
    EcdsaWithSha512,
    Unknown,
}

impl SignatureAlgorithm {
    const BY_OID: &'static [(Oid<'static>, SignatureAlgorithm)] = &[
        (
            oid!(1.2.840 .113549 .1 .1 .5),
            SignatureAlgorithm::Sha1WithRsa,
        ),
        (
            oid!(1.2.840 .113549 .1 .1 .11),
            SignatureAlgorithm::Sha256WithRsa,
        ),
        (
            oid!(1.2.840 .113549 .1 .1 .12),
            SignatureAlgorithm::Sha384WithRsa,
        ),
        (
            oid!(1.2.840 .113549 .1 .1 .13),
            SignatureAlgorithm::Sha512WithRsa,
        ),
        (
            oid!(1.2.840 .10045 .4 .3 .2),
            SignatureAlgorithm::EcdsaWithSha256,
        ),
        (
            oid!(1.2.840 .10045 .4 .3 .3),
            SignatureAlgorithm::EcdsaWithSha384,
        ),
        (
            oid!(1.2.840 .10045 .4 .3 .4),
            SignatureAlgorithm::EcdsaWithSha512,
        ),
    ];

    fn from_oid(oid: &Oid<'_>) -> Self {
        Self::BY_OID
            .iter()
            .find(|(known, _)| known == oid)
            .map(|&(_, alg)| alg)
            .unwrap_or(SignatureAlgorithm::Unknown)
    }

    fn as_str(self) -> &'static str {
        match self {
            SignatureAlgorithm::Sha1WithRsa => "sha1WithRSAEncryption",
            SignatureAlgorithm::Sha256WithRsa => "sha256WithRSAEncryption",
            SignatureAlgorithm::Sha384WithRsa => "sha384WithRSAEncryption",
            SignatureAlgorithm::Sha512WithRsa => "sha512WithRSAEncryption",
            SignatureAlgorithm::EcdsaWithSha256 => "sha256WithECDSA",
            SignatureAlgorithm::EcdsaWithSha384 => "sha384WithECDSA",
            SignatureAlgorithm::EcdsaWithSha512 => "sha512WithECDSA",
            SignatureAlgorithm::Unknown => "unknown",
        }
    }
}

/// Extracts public key algorithm and size from a certificate.
fn extract_public_key_info(cert: &x509_parser::certificate::X509Certificate<'_>) -> (String, u16) {
    let pk = cert.public_key();

    let alg = PublicKeyAlgorithm::from_oid(&pk.algorithm.algorithm).as_str();

    // PublicKey::key_size() is documented as "key size (in bits) or 0" and
    // covers RSA (modulus), EC (curve field), and DSA uniformly.
    let bits = pk
        .parsed()
        .map(|parsed| parsed.key_size() as u16)
        .unwrap_or(0);

    (alg.to_string(), bits)
}

/// Extracts the signature algorithm name from the certificate.
fn extract_signature_algorithm_name(
    cert: &x509_parser::certificate::X509Certificate<'_>,
) -> String {
    SignatureAlgorithm::from_oid(&cert.signature_algorithm.algorithm)
        .as_str()
        .to_string()
}

/// Extracts the CN (Common Name) from a DN (Distinguished Name).
fn extract_cn(dn: &x509_parser::x509::X509Name<'_>) -> Option<String> {
    for attr in dn.iter_common_name() {
        if let Ok(cn_data) = attr.as_str() {
            return Some(cn_data.to_string());
        }
    }
    None
}

/// Counts the number of SAN (Subject Alternative Name) entries.
fn count_san_entries(cert: &x509_parser::certificate::X509Certificate<'_>) -> u16 {
    #[allow(unused_imports)]
    use x509_parser::prelude::ParsedExtension;

    // No OID inspection needed: the parser already discriminates extensions.
    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san_names) = ext.parsed_extension() {
            return san_names.general_names.len() as u16;
        }
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_certificate_payload_too_short() {
        // Less than 3 bytes.
        assert_eq!(parse_certificate(&[0x00, 0x00]), None);
    }

    #[test]
    fn parse_certificate_empty_cert_list() {
        // Cert list length = 0.
        assert_eq!(parse_certificate(&[0x00, 0x00, 0x00]), None);
    }

    #[test]
    fn parse_certificate_first_cert_truncated() {
        // Cert list len = 10, but only 3 bytes total after list header.
        let payload = [0x00, 0x00, 0x0a, 0x00, 0x00, 0x05]; // Claims 5-byte cert, has 0.
        assert_eq!(parse_certificate(&payload), None);
    }

    #[test]
    fn u24_from_be_conversion() {
        assert_eq!(u24_from_be(&[0x00, 0x00, 0x01]), 1);
        assert_eq!(u24_from_be(&[0x00, 0x01, 0x00]), 256);
        assert_eq!(u24_from_be(&[0x01, 0x00, 0x00]), 65536);
        assert_eq!(u24_from_be(&[0xFF, 0xFF, 0xFF]), 16777215);
    }
}
