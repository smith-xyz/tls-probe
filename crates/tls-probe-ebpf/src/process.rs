//! Process attribution via kprobe/kretprobe pairs and `inet_csk_accept` kretprobe.
//!
//! **Outbound (connect-side):**
//! A kprobe on `tcp_v4_connect`/`tcp_v6_connect` fires at entry in the calling
//! process's context, capturing PID/TGID/comm/cgroup_id and the `sock *` pointer.
//! These are stashed in `CONNECT_STASH` keyed by `pid_tgid`. At function return
//! the kretprobe retrieves the stash, reads the now-populated 4-tuple from
//! `sock_common` (source IP/port are unset at entry time), and inserts into
//! `CONN_MAP` for the TC classifier to look up.
//!
//! **Inbound (accept-side):**
//! The `inet_csk_accept` kretprobe fires after a socket is accepted, capturing the
//! accepting task's PID/TGID/comm. The accepted socket's 4-tuple is `(local, remote)` —
//! the same orientation the connect kprobes record and the classifier normalizes to
//! (it swaps src/dst on ingress, yielding local-first on every path). Accept-side
//! inserts therefore use the tuple as read, with no mirroring.
//!
//! NOTE: `sock_common` field offsets below are fixed (not CO-RE/BTF-relocated,
//! since aya's BTF support does not yet cover `bpf_core_read` for this crate's
//! aya-ebpf version). They match the mainline `struct sock_common` layout as of
//! recent mainline kernels (5.14+) but may need adjustment if the target kernel's
//! layout differs.

use aya_ebpf::helpers::{
    bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
    bpf_probe_read_kernel,
};
use aya_ebpf::macros::{kprobe, kretprobe};
use aya_ebpf::programs::{ProbeContext, RetProbeContext};
use tls_probe_common::{ConnInfo, ConnKey, ConnStash, COMM_SIZE};

use crate::{CONNECT_STASH, CONN_MAP};

const SKC_DADDR_OFFSET: usize = 0;
const SKC_RCV_SADDR_OFFSET: usize = 4;
const SKC_DPORT_OFFSET: usize = 12;
const SKC_NUM_OFFSET: usize = 14;
const SKC_FAMILY_OFFSET: usize = 16;
const SKC_V6_DADDR_OFFSET: usize = 32;
const SKC_V6_RCV_SADDR_OFFSET: usize = 48;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

// ---------------------------------------------------------------------------
// Outbound: tcp_v4_connect / tcp_v6_connect kprobe + kretprobe pairs
// ---------------------------------------------------------------------------

/// Kprobe entry: stash the sock pointer + process info for the kretprobe.
/// Source IP/port are NOT yet assigned at this point.
#[kprobe]
pub fn tcp_v4_connect(ctx: ProbeContext) -> u32 {
    let _ = stash_connect_entry(&ctx);
    0
}

/// Kprobe entry: IPv6 variant — same stash logic.
#[kprobe]
pub fn tcp_v6_connect(ctx: ProbeContext) -> u32 {
    let _ = stash_connect_entry(&ctx);
    0
}

/// Kretprobe: `tcp_v4_connect` has returned — source IP/port are now assigned.
/// Read the 4-tuple and move the stash into CONN_MAP.
#[kretprobe]
pub fn tcp_v4_connect_ret(ctx: RetProbeContext) -> u32 {
    let _ = finish_connect_v4(&ctx);
    0
}

/// Kretprobe: IPv6 variant.
#[kretprobe]
pub fn tcp_v6_connect_ret(ctx: RetProbeContext) -> u32 {
    let _ = finish_connect_v6(&ctx);
    0
}

// ---------------------------------------------------------------------------
// Inbound: inet_csk_accept kretprobe
// ---------------------------------------------------------------------------

/// Kretprobe on `inet_csk_accept`: fires after a socket is accepted, in the
/// accepting task's context. The return value is the accepted `struct sock *`.
#[kretprobe]
pub fn inet_csk_accept(ctx: RetProbeContext) -> u32 {
    let _ = try_record_accept(&ctx);
    0
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[inline(always)]
fn current_conn_info() -> ConnInfo {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tgid = pid_tgid as u32;
    let comm = bpf_get_current_comm().unwrap_or([0u8; COMM_SIZE]);
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    ConnInfo {
        pid,
        tgid,
        comm,
        cgroup_id,
    }
}

/// Stash the sock pointer and process info at kprobe entry, keyed by pid_tgid.
#[inline(always)]
fn stash_connect_entry(ctx: &ProbeContext) -> Result<(), ()> {
    let sk: *const u8 = ctx.arg(0).ok_or(())?;
    let pid_tgid = bpf_get_current_pid_tgid();
    let stash = ConnStash {
        sock_ptr: sk as u64,
        info: current_conn_info(),
    };
    let _ = CONNECT_STASH.insert(&pid_tgid, &stash, 0);
    Ok(())
}

/// Kretprobe handler for tcp_v4_connect: read the IPv4 4-tuple and insert CONN_MAP.
#[inline(always)]
fn finish_connect_v4(ctx: &RetProbeContext) -> Result<(), ()> {
    // Non-zero return from tcp_v4_connect means connect failed.
    let ret: i32 = ctx.ret();
    if ret != 0 {
        // Clean up stash on failure.
        let pid_tgid = bpf_get_current_pid_tgid();
        let _ = CONNECT_STASH.remove(&pid_tgid);
        return Err(());
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let stash = unsafe { CONNECT_STASH.get(&pid_tgid) }.ok_or(())?;
    let sk = stash.sock_ptr as *const u8;
    let info = stash.info;
    let _ = CONNECT_STASH.remove(&pid_tgid);

    let mut src_addr = [0u8; 16];
    let mut dst_addr = [0u8; 16];

    let saddr_ptr = unsafe { sk.add(SKC_RCV_SADDR_OFFSET) as *const [u8; 4] };
    if let Ok(saddr) = unsafe { bpf_probe_read_kernel(saddr_ptr) } {
        src_addr[..4].copy_from_slice(&saddr);
    }
    let daddr_ptr = unsafe { sk.add(SKC_DADDR_OFFSET) as *const [u8; 4] };
    if let Ok(daddr) = unsafe { bpf_probe_read_kernel(daddr_ptr) } {
        dst_addr[..4].copy_from_slice(&daddr);
    }

    let (sport, dport) = read_ports(sk)?;

    let key = ConnKey {
        src_addr,
        dst_addr,
        src_port: sport,
        dst_port: dport,
    };
    let _ = CONN_MAP.insert(&key, &info, 0);
    Ok(())
}

/// Kretprobe handler for tcp_v6_connect: read the IPv6 4-tuple and insert CONN_MAP.
#[inline(always)]
fn finish_connect_v6(ctx: &RetProbeContext) -> Result<(), ()> {
    let ret: i32 = ctx.ret();
    if ret != 0 {
        let pid_tgid = bpf_get_current_pid_tgid();
        let _ = CONNECT_STASH.remove(&pid_tgid);
        return Err(());
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let stash = unsafe { CONNECT_STASH.get(&pid_tgid) }.ok_or(())?;
    let sk = stash.sock_ptr as *const u8;
    let info = stash.info;
    let _ = CONNECT_STASH.remove(&pid_tgid);

    let saddr_ptr = unsafe { sk.add(SKC_V6_RCV_SADDR_OFFSET) as *const [u8; 16] };
    let src_addr = unsafe { bpf_probe_read_kernel(saddr_ptr) }.unwrap_or([0u8; 16]);
    let daddr_ptr = unsafe { sk.add(SKC_V6_DADDR_OFFSET) as *const [u8; 16] };
    let dst_addr = unsafe { bpf_probe_read_kernel(daddr_ptr) }.unwrap_or([0u8; 16]);

    let (sport, dport) = read_ports(sk)?;

    let key = ConnKey {
        src_addr,
        dst_addr,
        src_port: sport,
        dst_port: dport,
    };
    let _ = CONN_MAP.insert(&key, &info, 0);
    Ok(())
}

/// Reads `skc_num` (host-order local port) and `skc_dport` (network-order
/// remote port) from `sock_common`, returning `(src_port, dst_port)` both in
/// host byte order.
#[inline(always)]
fn read_ports(sk: *const u8) -> Result<(u16, u16), ()> {
    let dport_ptr = unsafe { sk.add(SKC_DPORT_OFFSET) as *const u16 };
    let sport_ptr = unsafe { sk.add(SKC_NUM_OFFSET) as *const u16 };
    let dport = unsafe { bpf_probe_read_kernel(dport_ptr) }.unwrap_or(0);
    let sport = unsafe { bpf_probe_read_kernel(sport_ptr) }.unwrap_or(0);
    Ok((sport, u16::from_be(dport)))
}

/// Accept-side: read the 4-tuple from the accepted sock and insert CONN_MAP.
#[inline(always)]
fn try_record_accept(ctx: &RetProbeContext) -> Result<(), ()> {
    let sk: *const u8 = ctx.ret();
    if sk.is_null() {
        return Err(());
    }

    let mut src_addr = [0u8; 16];
    let mut dst_addr = [0u8; 16];

    let family_ptr = unsafe { sk.add(SKC_FAMILY_OFFSET) as *const u16 };
    let family = unsafe { bpf_probe_read_kernel(family_ptr) }.map_err(|_| ())?;

    match family {
        AF_INET => {
            let saddr_ptr = unsafe { sk.add(SKC_RCV_SADDR_OFFSET) as *const [u8; 4] };
            if let Ok(saddr) = unsafe { bpf_probe_read_kernel(saddr_ptr) } {
                src_addr[..4].copy_from_slice(&saddr);
            }
            let daddr_ptr = unsafe { sk.add(SKC_DADDR_OFFSET) as *const [u8; 4] };
            if let Ok(daddr) = unsafe { bpf_probe_read_kernel(daddr_ptr) } {
                dst_addr[..4].copy_from_slice(&daddr);
            }
        }
        AF_INET6 => {
            let saddr_ptr = unsafe { sk.add(SKC_V6_RCV_SADDR_OFFSET) as *const [u8; 16] };
            if let Ok(saddr) = unsafe { bpf_probe_read_kernel(saddr_ptr) } {
                src_addr = saddr;
            }
            let daddr_ptr = unsafe { sk.add(SKC_V6_DADDR_OFFSET) as *const [u8; 16] };
            if let Ok(daddr) = unsafe { bpf_probe_read_kernel(daddr_ptr) } {
                dst_addr = daddr;
            }
        }
        _ => return Err(()),
    }

    let (sport, dport) = read_ports(sk)?;

    let key = ConnKey {
        src_addr,
        dst_addr,
        src_port: sport,
        dst_port: dport,
    };
    let _ = CONN_MAP.insert(&key, &current_conn_info(), 0);
    Ok(())
}
