use crate::extensions::Extension;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    Ssl30,
    Tls10,
    Tls11,
    Tls12,
    Tls13,
    Unknown(u16),
}

impl From<u16> for TlsVersion {
    fn from(v: u16) -> Self {
        match v {
            0x0300 => TlsVersion::Ssl30,
            0x0301 => TlsVersion::Tls10,
            0x0302 => TlsVersion::Tls11,
            0x0303 => TlsVersion::Tls12,
            0x0304 => TlsVersion::Tls13,
            other => TlsVersion::Unknown(other),
        }
    }
}

impl TlsVersion {
    pub fn as_str(&self) -> &'static str {
        match self {
            TlsVersion::Ssl30 => "SSL 3.0",
            TlsVersion::Tls10 => "TLS 1.0",
            TlsVersion::Tls11 => "TLS 1.1",
            TlsVersion::Tls12 => "TLS 1.2",
            TlsVersion::Tls13 => "TLS 1.3",
            TlsVersion::Unknown(_) => "Unknown",
        }
    }

    pub fn to_u16(&self) -> u16 {
        match self {
            TlsVersion::Ssl30 => 0x0300,
            TlsVersion::Tls10 => 0x0301,
            TlsVersion::Tls11 => 0x0302,
            TlsVersion::Tls12 => 0x0303,
            TlsVersion::Tls13 => 0x0304,
            TlsVersion::Unknown(v) => *v,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ParsedClientHello {
    pub legacy_version: u16,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub compression_methods: Vec<u8>,
    pub extensions: Vec<Extension>,
    pub extension_ids: Vec<u16>,
    pub supported_versions: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
    pub signature_algorithms_cert: Vec<u16>,
    pub key_share_groups: Vec<u16>,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub psk_offered: bool,
    pub early_data_offered: bool,
    pub psk_key_exchange_modes_offered: bool,
    pub session_ticket_offered: bool,
}

#[derive(Debug, Clone)]
pub struct ParsedServerHello {
    pub legacy_version: u16,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suite: u16,
    pub compression_method: u8,
    pub extensions: Vec<Extension>,
    pub negotiated_version: Option<u16>,
    pub key_share_group: Option<u16>,
    pub psk_selected: bool,
}
