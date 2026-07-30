use aya_ebpf::bindings::TC_ACT_PIPE;
use aya_ebpf::helpers::{bpf_ktime_get_ns, bpf_skb_load_bytes};
use aya_ebpf::macros::classifier;
use aya_ebpf::programs::TcContext;
use tls_probe_common::{
    ConnKey, RAW_CAPTURE_HEADER_SIZE, RAW_PAYLOAD_SIZE, TLS_HANDSHAKE_CLIENT_HELLO,
    TLS_HANDSHAKE_SERVER_HELLO,
};

use crate::{CONN_MAP, RINGBUF_DROPS, SCRATCH, TLS_EVENTS};

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const IPPROTO_TCP: u8 = 6;
const TLS_CONTENT_HANDSHAKE: u8 = 0x16;

const ETH_HDR_LEN: usize = 14;
const IPV6_HDR_LEN: usize = 40;
const MIN_IP_HDR_LEN: usize = 20;
const MIN_TCP_HDR_LEN: usize = 20;
const TLS_RECORD_HDR_LEN: usize = 5;

#[classifier]
pub fn tls_ingress(ctx: TcContext) -> i32 {
    match try_capture_tls(&ctx, false) {
        Ok(_) => TC_ACT_PIPE,
        Err(_) => TC_ACT_PIPE,
    }
}

#[classifier]
pub fn tls_egress(ctx: TcContext) -> i32 {
    match try_capture_tls(&ctx, true) {
        Ok(_) => TC_ACT_PIPE,
        Err(_) => TC_ACT_PIPE,
    }
}

#[inline(always)]
unsafe fn load_bytes_fixed<const N: u32>(ctx: &TcContext, offset: usize, dst: *mut u8) -> bool {
    bpf_skb_load_bytes(ctx.skb.skb as *const _, offset as u32, dst as *mut _, N) >= 0
}

// Helper read, not direct packet access: reaches paged (GSO) data and keeps
// dynamic offsets out of the verifier's packet-range analysis. Use for any
// offset that is not a compile-time constant.
#[inline(always)]
unsafe fn load_u8(ctx: &TcContext, offset: usize) -> Option<u8> {
    let mut b = 0u8;
    if load_bytes_fixed::<1>(ctx, offset, &mut b as *mut u8) {
        Some(b)
    } else {
        None
    }
}

// Direct packet access is only verifier-safe at constant nonzero offsets;
// see load_u8 for dynamic offsets.
#[inline(always)]
unsafe fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Option<*const T> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    let start = data + offset;
    let end = start + core::mem::size_of::<T>();
    if end > data_end {
        return None;
    }
    Some(start as *const T)
}

#[inline(always)]
unsafe fn read_u8(ctx: &TcContext, offset: usize) -> Option<u8> {
    Some(*ptr_at::<u8>(ctx, offset)?)
}

#[inline(always)]
unsafe fn read_u16_be(ctx: &TcContext, offset: usize) -> Option<u16> {
    Some(u16::from_be(*ptr_at::<u16>(ctx, offset)?))
}

#[inline(always)]
fn try_capture_tls(ctx: &TcContext, is_egress: bool) -> Result<(), ()> {
    let pkt_len = ctx.len() as usize;

    if pkt_len < ETH_HDR_LEN + MIN_IP_HDR_LEN + MIN_TCP_HDR_LEN + TLS_RECORD_HDR_LEN + 1 {
        return Ok(());
    }

    let eth_proto = match unsafe { read_u16_be(ctx, 12) } {
        Some(v) => v,
        None => return Ok(()),
    };

    let (is_ipv6, ip_hdr_len, src_offset, dst_offset) = match eth_proto {
        ETH_P_IP => {
            let ip_proto = match unsafe { read_u8(ctx, 23) } {
                Some(v) => v,
                None => return Ok(()),
            };
            if ip_proto != IPPROTO_TCP {
                return Ok(());
            }
            let version_ihl = match unsafe { read_u8(ctx, 14) } {
                Some(v) => v,
                None => return Ok(()),
            };
            let ip_hdr_len = ((version_ihl & 0x0F) as usize) * 4;
            if ip_hdr_len < MIN_IP_HDR_LEN {
                return Ok(());
            }
            (false, ip_hdr_len, 26usize, 30usize)
        }
        ETH_P_IPV6 => {
            let ip_proto = match unsafe { read_u8(ctx, 20) } {
                Some(v) => v,
                None => return Ok(()),
            };
            if ip_proto != IPPROTO_TCP {
                return Ok(());
            }
            (true, IPV6_HDR_LEN, 22usize, 38usize)
        }
        _ => return Ok(()),
    };

    let tcp_start = ETH_HDR_LEN + ip_hdr_len;

    if tcp_start + 13 > pkt_len {
        return Ok(());
    }
    let tcp_off_byte = match unsafe { load_u8(ctx, tcp_start + 12) } {
        Some(v) => v,
        None => return Ok(()),
    };
    let tcp_data_off = ((tcp_off_byte >> 4) as usize) * 4;
    if tcp_data_off < MIN_TCP_HDR_LEN || tcp_data_off > 60 {
        return Ok(());
    }

    let tls_start = tcp_start + tcp_data_off;

    if tls_start + TLS_RECORD_HDR_LEN + 1 > pkt_len {
        return Ok(());
    }

    // Record header + handshake type in one helper call.
    let mut rec = [0u8; TLS_RECORD_HDR_LEN + 1];
    if !unsafe { load_bytes_fixed::<6>(ctx, tls_start, rec.as_mut_ptr()) } {
        return Ok(());
    }

    if rec[0] != TLS_CONTENT_HANDSHAKE {
        return Ok(());
    }

    let record_version = u16::from_be_bytes([rec[1], rec[2]]);
    if !(0x0300..=0x0303).contains(&record_version) {
        return Ok(());
    }

    let hs_type = rec[5];
    if hs_type != TLS_HANDSHAKE_CLIENT_HELLO && hs_type != TLS_HANDSHAKE_SERVER_HELLO {
        return Ok(());
    }

    let scratch = SCRATCH.get_ptr_mut(0).ok_or(())?;
    let scratch = unsafe { &mut *scratch };

    scratch.event.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    scratch.event.handshake_type = hs_type;
    scratch.event.record_version = record_version;
    scratch.event.is_ipv6 = is_ipv6 as u8;

    if is_ipv6 {
        if src_offset + 16 > pkt_len || dst_offset + 16 > pkt_len {
            return Ok(());
        }
        if !unsafe { load_bytes_fixed::<16>(ctx, src_offset, scratch.event.src_addr.as_mut_ptr()) }
        {
            return Ok(());
        }
        if !unsafe { load_bytes_fixed::<16>(ctx, dst_offset, scratch.event.dst_addr.as_mut_ptr()) }
        {
            return Ok(());
        }
    } else {
        scratch.event.src_addr = [0u8; 16];
        scratch.event.dst_addr = [0u8; 16];
        if src_offset + 4 > pkt_len || dst_offset + 4 > pkt_len {
            return Ok(());
        }
        let mut src4 = [0u8; 4];
        let mut dst4 = [0u8; 4];
        if !unsafe { load_bytes_fixed::<4>(ctx, src_offset, src4.as_mut_ptr()) } {
            return Ok(());
        }
        if !unsafe { load_bytes_fixed::<4>(ctx, dst_offset, dst4.as_mut_ptr()) } {
            return Ok(());
        }
        scratch.event.src_addr[0] = src4[0];
        scratch.event.src_addr[1] = src4[1];
        scratch.event.src_addr[2] = src4[2];
        scratch.event.src_addr[3] = src4[3];
        scratch.event.dst_addr[0] = dst4[0];
        scratch.event.dst_addr[1] = dst4[1];
        scratch.event.dst_addr[2] = dst4[2];
        scratch.event.dst_addr[3] = dst4[3];
    }

    if !is_egress {
        let tmp = scratch.event.src_addr;
        scratch.event.src_addr = scratch.event.dst_addr;
        scratch.event.dst_addr = tmp;
    }

    if tcp_start + 4 > pkt_len {
        return Ok(());
    }
    let mut ports = [0u8; 4];
    if !unsafe { load_bytes_fixed::<4>(ctx, tcp_start, ports.as_mut_ptr()) } {
        return Ok(());
    }
    scratch.event.src_port = u16::from_be_bytes([ports[0], ports[1]]);
    scratch.event.dst_port = u16::from_be_bytes([ports[2], ports[3]]);

    if !is_egress {
        let tmp = scratch.event.src_port;
        scratch.event.src_port = scratch.event.dst_port;
        scratch.event.dst_port = tmp;
    }

    let payload_avail = pkt_len.saturating_sub(tls_start);
    scratch.event.payload_len = 0;

    // Exact-length copy (no bucket rounding, which truncated e.g. 300→256 and
    // could clip SNI). Redundant-looking bounds give the verifier the explicit
    // [1, RAW_PAYLOAD_SIZE] range bpf_skb_load_bytes requires for a
    // register-sized length.
    let mut copy_len = payload_avail;
    if copy_len > RAW_PAYLOAD_SIZE {
        copy_len = RAW_PAYLOAD_SIZE;
    }
    if copy_len >= 1
        && unsafe {
            bpf_skb_load_bytes(
                ctx.skb.skb as *const _,
                tls_start as u32,
                scratch.event.payload.as_mut_ptr() as *mut _,
                copy_len as u32,
            ) >= 0
        }
    {
        scratch.event.payload_len = copy_len as u16;
    }

    scratch.event.pid = 0;
    scratch.event.comm = [0u8; 16];
    let conn_key = ConnKey {
        src_addr: scratch.event.src_addr,
        dst_addr: scratch.event.dst_addr,
        src_port: scratch.event.src_port,
        dst_port: scratch.event.dst_port,
    };
    if let Some(info) = unsafe { CONN_MAP.get(&conn_key) } {
        scratch.event.pid = info.pid;
        scratch.event.comm = info.comm;
    }

    let payload_len = scratch.event.payload_len as usize;
    let capped_payload = payload_len.min(RAW_PAYLOAD_SIZE);
    let total_len = RAW_CAPTURE_HEADER_SIZE + capped_payload;
    let event_ptr = &scratch.event as *const _ as *const u8;
    let event_bytes = unsafe { core::slice::from_raw_parts(event_ptr, total_len) };
    if TLS_EVENTS.output::<[u8]>(event_bytes, 0).is_err() {
        if let Some(cnt) = RINGBUF_DROPS.get_ptr_mut(0) {
            unsafe { *cnt += 1 };
        }
    }
    Ok(())
}
