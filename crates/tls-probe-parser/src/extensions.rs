use crate::error::ParseError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionType {
    ServerName,
    SupportedGroups,
    SignatureAlgorithms,
    SupportedVersions,
    KeyShare,
    Unknown(u16),
}

impl From<u16> for ExtensionType {
    fn from(v: u16) -> Self {
        match v {
            0x0000 => ExtensionType::ServerName,
            0x000A => ExtensionType::SupportedGroups,
            0x000D => ExtensionType::SignatureAlgorithms,
            0x002B => ExtensionType::SupportedVersions,
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
