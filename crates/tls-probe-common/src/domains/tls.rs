pub const RAW_PAYLOAD_SIZE: usize = 1400;
const ADDR_SIZE: usize = 16;

/// Size of the fixed header portion of [`RawTlsCapture`] (all fields except `payload`).
/// Used by the ringbuf transport to emit only header + actual payload bytes.
pub const RAW_CAPTURE_HEADER_SIZE: usize = 8 + 16 + 16 + 2 + 2 + 1 + 1 + 2 + 2 + 2 + 4 + 16; // 72 with repr(C) padding before pid

pub const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
pub const TLS_HANDSHAKE_SERVER_HELLO: u8 = 0x02;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawTlsCapture {
    pub timestamp_ns: u64,
    pub src_addr: [u8; ADDR_SIZE],
    pub dst_addr: [u8; ADDR_SIZE],
    pub src_port: u16,
    pub dst_port: u16,
    pub is_ipv6: u8,
    pub handshake_type: u8,
    pub record_version: u16,
    pub payload_len: u16,
    pub pid: u32,
    pub comm: [u8; 16],
    /// Must remain last — variable-length tail for ringbuf wire format.
    pub payload: [u8; RAW_PAYLOAD_SIZE],
}

impl Default for RawTlsCapture {
    fn default() -> Self {
        Self {
            timestamp_ns: 0,
            src_addr: [0u8; ADDR_SIZE],
            dst_addr: [0u8; ADDR_SIZE],
            src_port: 0,
            dst_port: 0,
            is_ipv6: 0,
            handshake_type: 0,
            record_version: 0,
            payload_len: 0,
            pid: 0,
            comm: [0u8; 16],
            payload: [0u8; RAW_PAYLOAD_SIZE],
        }
    }
}

#[cfg(feature = "user")]
impl RawTlsCapture {
    pub fn is_ipv6(&self) -> bool {
        self.is_ipv6 != 0
    }

    pub fn src_addr_str(&self) -> std::string::String {
        format_addr(&self.src_addr, self.is_ipv6())
    }

    pub fn dst_addr_str(&self) -> std::string::String {
        format_addr(&self.dst_addr, self.is_ipv6())
    }

    pub fn payload_slice(&self) -> &[u8] {
        let len = (self.payload_len as usize).min(RAW_PAYLOAD_SIZE);
        &self.payload[..len]
    }

    pub fn is_client_hello(&self) -> bool {
        self.handshake_type == TLS_HANDSHAKE_CLIENT_HELLO
    }

    pub fn is_server_hello(&self) -> bool {
        self.handshake_type == TLS_HANDSHAKE_SERVER_HELLO
    }
}

#[cfg(feature = "user")]
fn format_addr(addr: &[u8; ADDR_SIZE], is_ipv6: bool) -> std::string::String {
    if is_ipv6 {
        let ipv6 = std::net::Ipv6Addr::from(*addr);
        std::format!("{}", ipv6)
    } else {
        std::format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
    }
}

#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for RawTlsCapture {}

#[cfg(all(test, feature = "user"))]
mod tests {
    use core::mem::offset_of;

    use super::*;

    const _: () = assert!(offset_of!(RawTlsCapture, payload) == RAW_CAPTURE_HEADER_SIZE);

    #[test]
    fn default_values() {
        let capture = RawTlsCapture::default();
        assert_eq!(capture.timestamp_ns, 0);
        assert_eq!(capture.payload_len, 0);
        assert!(!capture.is_ipv6());
    }

    #[test]
    fn payload_slice_returns_correct_length() {
        let mut capture = RawTlsCapture::default();
        capture.payload[0] = 0x16;
        capture.payload[1] = 0x03;
        capture.payload[2] = 0x03;
        capture.payload_len = 3;

        let slice = capture.payload_slice();
        assert_eq!(slice.len(), 3);
        assert_eq!(slice, &[0x16, 0x03, 0x03]);
    }

    #[test]
    fn payload_slice_caps_at_max() {
        let capture = RawTlsCapture {
            payload_len: 5000,
            ..Default::default()
        };

        let slice = capture.payload_slice();
        assert_eq!(slice.len(), RAW_PAYLOAD_SIZE);
    }

    #[test]
    fn handshake_type_detection() {
        let capture = RawTlsCapture {
            handshake_type: TLS_HANDSHAKE_CLIENT_HELLO,
            ..Default::default()
        };
        assert!(capture.is_client_hello());
        assert!(!capture.is_server_hello());

        let capture = RawTlsCapture {
            handshake_type: TLS_HANDSHAKE_SERVER_HELLO,
            ..Default::default()
        };
        assert!(!capture.is_client_hello());
        assert!(capture.is_server_hello());
    }

    #[test]
    fn ipv4_address_formatting() {
        let mut capture = RawTlsCapture::default();
        capture.src_addr[0] = 192;
        capture.src_addr[1] = 168;
        capture.src_addr[2] = 1;
        capture.src_addr[3] = 100;
        capture.is_ipv6 = 0;

        assert_eq!(capture.src_addr_str(), "192.168.1.100");
    }

    #[test]
    fn ipv6_address_formatting() {
        let capture = RawTlsCapture {
            src_addr: [
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01,
            ],
            is_ipv6: 1,
            ..Default::default()
        };

        assert_eq!(capture.src_addr_str(), "2001:db8::1");
    }
}
