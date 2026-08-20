use crate::error::ParseError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionType {
    ServerName,
    ApplicationLayerProtocolNegotiation,
    SupportedGroups,
    SignatureAlgorithms,
    SupportedVersions,
    KeyShare,
    SignatureAlgorithmsCert,
    SessionTicket,
    EarlyData,
    PskKeyExchangeModes,
    PreSharedKey,
    Unknown(u16),
}

impl From<u16> for ExtensionType {
    fn from(v: u16) -> Self {
        match v {
            0x0000 => ExtensionType::ServerName,
            0x0010 => ExtensionType::ApplicationLayerProtocolNegotiation,
            0x000A => ExtensionType::SupportedGroups,
            0x000D => ExtensionType::SignatureAlgorithms,
            0x0023 => ExtensionType::SessionTicket,
            0x002A => ExtensionType::EarlyData,
            0x002B => ExtensionType::SupportedVersions,
            0x002D => ExtensionType::PskKeyExchangeModes,
            0x0029 => ExtensionType::PreSharedKey,
            0x0032 => ExtensionType::SignatureAlgorithmsCert,
            0x0033 => ExtensionType::KeyShare,
            other => ExtensionType::Unknown(other),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Extension {
    pub ext_type: ExtensionType,
    pub data: Vec<u8>,
}

pub fn parse_extensions(data: &[u8]) -> Result<Vec<Extension>, ParseError> {
    let mut extensions = Vec::new();
    let mut offset = 0;

    while offset + 4 <= data.len() {
        let ext_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let ext_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;

        if offset + ext_len > data.len() {
            break;
        }

        extensions.push(Extension {
            ext_type: ExtensionType::from(ext_type),
            data: data[offset..offset + ext_len].to_vec(),
        });

        offset += ext_len;
    }

    Ok(extensions)
}

pub fn extract_supported_versions(ext: &Extension, is_client: bool) -> Vec<u16> {
    let mut versions = Vec::new();
    let data = &ext.data;

    if is_client {
        if data.is_empty() {
            return versions;
        }
        let list_len = data[0] as usize;
        let mut offset = 1;
        while offset + 2 <= data.len() && offset < 1 + list_len {
            versions.push(u16::from_be_bytes([data[offset], data[offset + 1]]));
            offset += 2;
        }
    } else if data.len() >= 2 {
        versions.push(u16::from_be_bytes([data[0], data[1]]));
    }

    versions
}

pub fn extract_supported_groups(ext: &Extension) -> Vec<u16> {
    let mut groups = Vec::new();
    let data = &ext.data;

    if data.len() < 2 {
        return groups;
    }

    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut offset = 2;

    while offset + 2 <= data.len() && offset < 2 + list_len {
        groups.push(u16::from_be_bytes([data[offset], data[offset + 1]]));
        offset += 2;
    }

    groups
}

pub fn extract_signature_algorithms(ext: &Extension) -> Vec<u16> {
    let mut algs = Vec::new();
    let data = &ext.data;

    if data.len() < 2 {
        return algs;
    }

    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut offset = 2;

    while offset + 2 <= data.len() && offset < 2 + list_len {
        algs.push(u16::from_be_bytes([data[offset], data[offset + 1]]));
        offset += 2;
    }

    algs
}

pub fn extract_signature_algorithms_cert(ext: &Extension) -> Vec<u16> {
    let mut algs = Vec::new();
    let data = &ext.data;

    if data.len() < 2 {
        return algs;
    }

    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut offset = 2;

    while offset + 2 <= data.len() && offset < 2 + list_len {
        algs.push(u16::from_be_bytes([data[offset], data[offset + 1]]));
        offset += 2;
    }

    algs
}

pub fn extract_key_share_groups(ext: &Extension, is_client: bool) -> Vec<u16> {
    let mut groups = Vec::new();
    let data = &ext.data;

    if is_client {
        if data.len() < 2 {
            return groups;
        }
        let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        let mut offset = 2;

        while offset + 4 <= data.len() && offset < 2 + list_len {
            let group = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let key_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            groups.push(group);
            offset += 4 + key_len;
        }
    } else if data.len() >= 2 {
        groups.push(u16::from_be_bytes([data[0], data[1]]));
    }

    groups
}

pub fn extract_sni(ext: &Extension) -> Option<String> {
    let data = &ext.data;

    if data.len() < 5 {
        return None;
    }

    let _list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let name_type = data[2];

    if name_type != 0 {
        return None;
    }

    let name_len = u16::from_be_bytes([data[3], data[4]]) as usize;

    if data.len() < 5 + name_len {
        return None;
    }

    String::from_utf8(data[5..5 + name_len].to_vec()).ok()
}

/// Check whether the pre_shared_key extension (0x0029) is present.
/// The actual PSK identity/binder is not parsed — we only record presence.
pub fn has_pre_shared_key(ext: &Extension) -> bool {
    matches!(ext.ext_type, ExtensionType::PreSharedKey)
}

/// Check whether the psk_key_exchange_modes extension (0x002D) is present.
pub fn has_psk_key_exchange_modes(ext: &Extension) -> bool {
    matches!(ext.ext_type, ExtensionType::PskKeyExchangeModes)
}

/// Check whether the early_data extension (0x002A) is present.
pub fn has_early_data(ext: &Extension) -> bool {
    matches!(ext.ext_type, ExtensionType::EarlyData)
}

/// Check whether the session_ticket extension (0x0023) is present.
pub fn has_session_ticket(ext: &Extension) -> bool {
    matches!(ext.ext_type, ExtensionType::SessionTicket)
}

/// In a ServerHello, check if pre_shared_key was selected (identity indicates resumption).
/// Returns true if the extension is present with non-empty selected identity (identity < 255).
pub fn is_psk_selected(ext: &Extension) -> bool {
    matches!(ext.ext_type, ExtensionType::PreSharedKey) && !ext.data.is_empty()
}

/// Extract ALPN protocol names from the ALPN extension (0x0010).
/// Returns a list of protocol strings (lossy UTF-8 is fine per spec).
pub fn extract_alpn(ext: &Extension) -> Vec<String> {
    let mut protocols = Vec::new();
    let data = &ext.data;

    if data.len() < 2 {
        return protocols;
    }

    // First 2 bytes: list length
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut offset = 2;

    while offset < data.len() && offset < 2 + list_len {
        if offset >= data.len() {
            break;
        }
        let proto_len = data[offset] as usize;
        offset += 1;

        if offset + proto_len > data.len() {
            break;
        }

        // Lossy UTF-8 decode per spec
        let proto_bytes = &data[offset..offset + proto_len];
        let proto = String::from_utf8_lossy(proto_bytes).to_string();
        protocols.push(proto);

        offset += proto_len;
    }

    protocols
}
