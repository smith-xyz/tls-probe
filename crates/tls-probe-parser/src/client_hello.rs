use crate::error::ParseError;
use crate::extensions::{
    extract_alpn, extract_key_share_groups, extract_signature_algorithms,
    extract_signature_algorithms_cert, extract_sni, extract_supported_groups,
    extract_supported_versions, has_early_data, has_pre_shared_key, has_psk_key_exchange_modes,
    has_session_ticket, parse_extensions, ExtensionType,
};
use crate::types::ParsedClientHello;
use crate::{TLS_HANDSHAKE_HDR_LEN, TLS_RANDOM_LEN, TLS_RECORD_HDR_LEN};

pub fn parse_client_hello(payload: &[u8]) -> Result<ParsedClientHello, ParseError> {
    let hello_start = TLS_RECORD_HDR_LEN + TLS_HANDSHAKE_HDR_LEN;

    if payload.len() < hello_start + 2 + TLS_RANDOM_LEN + 1 {
        return Err(ParseError::TooShort);
    }

    let mut offset = hello_start;

    let legacy_version = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
    offset += 2;

    let mut random = [0u8; 32];
    random.copy_from_slice(&payload[offset..offset + TLS_RANDOM_LEN]);
    offset += TLS_RANDOM_LEN;

    let session_id_len = payload[offset] as usize;
    offset += 1;

    if offset + session_id_len > payload.len() {
        return Err(ParseError::UnexpectedEnd(offset));
    }
    let session_id = payload[offset..offset + session_id_len].to_vec();
    offset += session_id_len;

    if offset + 2 > payload.len() {
        return Err(ParseError::UnexpectedEnd(offset));
    }
    let cipher_len = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
    offset += 2;

    if offset + cipher_len > payload.len() {
        return Err(ParseError::UnexpectedEnd(offset));
    }

    let mut cipher_suites = Vec::new();
    let cipher_end = offset + cipher_len;
    while offset + 2 <= cipher_end {
        cipher_suites.push(u16::from_be_bytes([payload[offset], payload[offset + 1]]));
        offset += 2;
    }
    offset = cipher_end;

    if offset >= payload.len() {
        return Err(ParseError::UnexpectedEnd(offset));
    }
    let comp_len = payload[offset] as usize;
    offset += 1;

    if offset + comp_len > payload.len() {
        return Err(ParseError::UnexpectedEnd(offset));
    }
    let compression_methods = payload[offset..offset + comp_len].to_vec();
    offset += comp_len;

    let mut extensions = Vec::new();
    let mut extension_ids = Vec::new();
    let mut supported_versions = Vec::new();
    let mut supported_groups = Vec::new();
    let mut signature_algorithms = Vec::new();
    let mut signature_algorithms_cert = Vec::new();
    let mut key_share_groups = Vec::new();
    let mut sni = None;
    let mut alpn = Vec::new();
    let mut psk_offered = false;
    let mut early_data_offered = false;
    let mut psk_key_exchange_modes_offered = false;
    let mut session_ticket_offered = false;

    if offset + 2 <= payload.len() {
        let ext_len = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
        offset += 2;

        let available = payload.len().saturating_sub(offset);
        let parse_len = available.min(ext_len);

        if parse_len > 0 {
            // Extract raw extension IDs from the extension data
            let mut ext_offset = offset;
            while ext_offset + 4 <= offset + parse_len {
                let ext_type = u16::from_be_bytes([payload[ext_offset], payload[ext_offset + 1]]);
                let ext_data_len =
                    u16::from_be_bytes([payload[ext_offset + 2], payload[ext_offset + 3]]) as usize;
                extension_ids.push(ext_type);
                ext_offset += 4 + ext_data_len;
            }

            extensions = parse_extensions(&payload[offset..offset + parse_len])?;

            for ext in &extensions {
                match ext.ext_type {
                    ExtensionType::SupportedVersions => {
                        supported_versions = extract_supported_versions(ext, true);
                    }
                    ExtensionType::SupportedGroups => {
                        supported_groups = extract_supported_groups(ext);
                    }
                    ExtensionType::SignatureAlgorithms => {
                        signature_algorithms = extract_signature_algorithms(ext);
                    }
                    ExtensionType::SignatureAlgorithmsCert => {
                        signature_algorithms_cert = extract_signature_algorithms_cert(ext);
                    }
                    ExtensionType::KeyShare => {
                        key_share_groups = extract_key_share_groups(ext, true);
                    }
                    ExtensionType::ServerName => {
                        sni = extract_sni(ext);
                    }
                    ExtensionType::PreSharedKey => {
                        psk_offered = has_pre_shared_key(ext);
                    }
                    ExtensionType::EarlyData => {
                        early_data_offered = has_early_data(ext);
                    }
                    ExtensionType::PskKeyExchangeModes => {
                        psk_key_exchange_modes_offered = has_psk_key_exchange_modes(ext);
                    }
                    ExtensionType::SessionTicket => {
                        session_ticket_offered = has_session_ticket(ext);
                    }
                    // Extract ALPN for JA4 fingerprinting
                    ExtensionType::ApplicationLayerProtocolNegotiation => {
                        alpn = extract_alpn(ext);
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(ParsedClientHello {
        legacy_version,
        random,
        session_id,
        cipher_suites,
        compression_methods,
        extensions,
        extension_ids,
        supported_versions,
        supported_groups,
        signature_algorithms,
        signature_algorithms_cert,
        key_share_groups,
        sni,
        alpn,
        psk_offered,
        early_data_offered,
        psk_key_exchange_modes_offered,
        session_ticket_offered,
    })
}
