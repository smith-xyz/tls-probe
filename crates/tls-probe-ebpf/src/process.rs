//! Process attribution via `tcp_v4_connect`/`tcp_v6_connect` kprobes and `inet_csk_accept` kretprobe.
//!
//! **Outbound (connect-side):**
//! The kprobes fire in the calling process's context at `connect(2)` time, so we can
//! read PID/TGID/comm directly from the current task and correlate them with
//! the connection's 4-tuple. The TC classifier in `tls.rs` looks up `CONN_MAP`
//! by that 4-tuple to attribute an outbound TLS handshake to its originating process.
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
//! layout differs. The same offsets are used for both connect-side (outbound TCP
//! clients) and accept-side (inbound servers), reading the 4-tuple from the
//! accepted `struct sock *` return value of `inet_csk_accept`.

use aya_ebpf::helpers::{
    bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
    bpf_probe_read_kernel,
};
use aya_ebpf::macros::{kprobe, kretprobe};
use aya_ebpf::programs::{ProbeContext, RetProbeContext};
use tls_probe_common::{ConnInfo, ConnKey, COMM_SIZE};

use crate::CONN_MAP;

const SKC_DADDR_OFFSET: usize = 0;
const SKC_RCV_SADDR_OFFSET: usize = 4;
const SKC_DPORT_OFFSET: usize = 12;
const SKC_NUM_OFFSET: usize = 14;
const SKC_V6_DADDR_OFFSET: usize = 32;
const SKC_V6_RCV_SADDR_OFFSET: usize = 48;

#[kprobe]
pub fn tcp_v4_connect(ctx: ProbeContext) -> u32 {
    match try_record_connect_v4(&ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

#[kprobe]
pub fn tcp_v6_connect(ctx: ProbeContext) -> u32 {
    match try_record_connect_v6(&ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

/// Kretprobe on `inet_csk_accept`: fires after a socket is accepted, in the
/// accepting task's context. The return value is the accepted `struct sock *`.
/// Reads the 4-tuple from `sock_common` and inserts into CONN_MAP with the
/// SAME (local, remote) orientation the connect kprobes use — the classifier
/// normalizes every flow to (local, remote) on this host, so no mirroring is
/// needed (and mirroring would collide with the connect-side entry on
/// loopback). NULL returns are skipped; TCP fast-open and kernel-accepted
/// sockets before accept() returns are known misses.
#[kretprobe]
pub fn inet_csk_accept(ctx: RetProbeContext) -> u32 {
    match try_record_accept(&ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn current_conn_info() -> ConnInfo {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tgid = pid_tgid as u32;
    let comm = bpf_get_current_comm().unwrap_or([0u8; COMM_SIZE]);
    // SAFETY: plain BPF helper call; valid in kprobe context, no pointers involved.
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    ConnInfo {
        pid,
        tgid,
        comm,
        cgroup_id,
    }
}

#[inline(always)]
fn try_record_connect_v4(ctx: &ProbeContext) -> Result<(), ()> {
    let sk: *const u8 = ctx.arg(0).ok_or(())?;

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

    let _ = CONN_MAP.insert(&key, &current_conn_info(), 0);
    Ok(())
}

#[inline(always)]
fn try_record_connect_v6(ctx: &ProbeContext) -> Result<(), ()> {
    let sk: *const u8 = ctx.arg(0).ok_or(())?;

    let mut src_addr = [0u8; 16];
    let mut dst_addr = [0u8; 16];

    let saddr_ptr = unsafe { sk.add(SKC_V6_RCV_SADDR_OFFSET) as *const [u8; 16] };
    if let Ok(saddr) = unsafe { bpf_probe_read_kernel(saddr_ptr) } {
        src_addr = saddr;
    }

    let daddr_ptr = unsafe { sk.add(SKC_V6_DADDR_OFFSET) as *const [u8; 16] };
    if let Ok(daddr) = unsafe { bpf_probe_read_kernel(daddr_ptr) } {
        dst_addr = daddr;
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

const SKC_FAMILY_OFFSET: usize = 16;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

#[inline(always)]
fn try_record_accept(ctx: &RetProbeContext) -> Result<(), ()> {
    // Return value of inet_csk_accept is the accepted `struct sock *`;
    // NULL means the accept failed — nothing to record. (This aya version's
    // RetProbeContext::ret() returns T directly, not Option.)
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

    // The accepted socket's `sock_common` is (local = server, remote = client)
    // — the SAME orientation the connect kprobes record (local, remote) and
    // the classifier normalizes to on this host. Insert unmirrored; a mirrored
    // key would never match classifier lookups and, on loopback, would
    // overwrite the connect-side entry for the same flow.
    let key = ConnKey {
        src_addr,
        dst_addr,
        src_port: sport,
        dst_port: dport,
    };

    let _ = CONN_MAP.insert(&key, &current_conn_info(), 0);
    Ok(())
}
