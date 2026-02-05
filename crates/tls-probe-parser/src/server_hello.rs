use crate::error::ParseError;
use crate::extensions::{
    extract_key_share_groups, extract_supported_versions, parse_extensions, ExtensionType,
};
use crate::types::ParsedServerHello;
use crate::{TLS_HANDSHAKE_HDR_LEN, TLS_RANDOM_LEN, TLS_RECORD_HDR_LEN};

pub fn parse_server_hello(payload: &[u8]) -> Result<ParsedServerHello, ParseError> {
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
    let cipher_suite = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
    offset += 2;

    if offset >= payload.len() {
        return Err(ParseError::UnexpectedEnd(offset));
    }
    let compression_method = payload[offset];
    offset += 1;

    let mut extensions = Vec::new();
    let mut negotiated_version = None;
    let mut key_share_group = None;

    if offset + 2 <= payload.len() {
        let ext_len = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
        offset += 2;

        let available = payload.len().saturating_sub(offset);
        let parse_len = available.min(ext_len);

        if parse_len > 0 {
            extensions = parse_extensions(&payload[offset..offset + parse_len])?;

            for ext in &extensions {
                match ext.ext_type {
                    ExtensionType::SupportedVersions => {
                        let versions = extract_supported_versions(ext, false);
                        negotiated_version = versions.first().copied();
                    }
                    ExtensionType::KeyShare => {
                        let groups = extract_key_share_groups(ext, false);
                        key_share_group = groups.first().copied();
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(ParsedServerHello {
        legacy_version,
        random,
        session_id,
        cipher_suite,
        compression_method,
        extensions,
        negotiated_version,
        key_share_group,
    })
}
