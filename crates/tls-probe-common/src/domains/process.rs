pub const COMM_SIZE: usize = 16;

/// TCP 4-tuple used to correlate a `tcp_v4_connect`/`tcp_v6_connect` kprobe
/// observation with a TC-classified TLS handshake for the same connection.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnKey {
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
}

/// Process attribution recorded at `connect()` time for a given `ConnKey`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnInfo {
    pub pid: u32,
    pub tgid: u32,
    pub comm: [u8; COMM_SIZE],
}

#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for ConnKey {}
#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for ConnInfo {}
