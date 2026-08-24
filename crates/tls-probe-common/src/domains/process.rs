pub const COMM_SIZE: usize = 16;

/// TCP 4-tuple used to correlate a `tcp_v4_connect`/`tcp_v6_connect` kprobe
/// observation with a TC-classified TLS handshake for the same connection.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ConnKey {
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
}

// NOTE: no mirror/swap helper on ConnKey by design. Both the connect kprobes
// and the accept kretprobe read `sock_common` as (local, remote), and the TC
// classifier normalizes every flow to that same local-first orientation, so
// all CONN_MAP keys share one convention. A mirrored accept-side key would
// never match classifier lookups and would collide with the connect-side
// entry on loopback.

/// Process attribution recorded at `connect()` time for a given `ConnKey`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnInfo {
    pub pid: u32,
    pub tgid: u32,
    pub comm: [u8; COMM_SIZE],
    pub cgroup_id: u64,
}

/// Stash entry passed from a connect kprobe (entry) to its kretprobe (return).
/// At kprobe entry the source address/port are not yet assigned; the kretprobe
/// reads the now-populated `sock_common` via `sock_ptr` and inserts into
/// `CONN_MAP` using the saved `info`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnStash {
    pub sock_ptr: u64,
    pub info: ConnInfo,
}

#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for ConnKey {}
#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for ConnInfo {}
#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for ConnStash {}
