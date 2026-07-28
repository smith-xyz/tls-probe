use aya_ebpf::bindings::TC_ACT_PIPE;
use aya_ebpf::helpers::{bpf_ktime_get_ns, bpf_skb_load_bytes};
use aya_ebpf::macros::classifier;
use aya_ebpf::programs::TcContext;
use tls_probe_common::{ConnKey, TLS_HANDSHAKE_CLIENT_HELLO, TLS_HANDSHAKE_SERVER_HELLO};

use crate::{CONN_MAP, SCRATCH, TLS_EVENTS};

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

#[inline(always)]
fn try_capture_tls(ctx: &TcContext, is_egress: bool) -> Result<(), ()> {
    let pkt_len = ctx.len() as usize;

    if pkt_len < ETH_HDR_LEN + MIN_IP_HDR_LEN + MIN_TCP_HDR_LEN + TLS_RECORD_HDR_LEN + 1 {
        return Ok(());
    }

    let mut eth_proto_bytes = [0u8; 2];
    if !unsafe { load_bytes_fixed::<2>(ctx, 12, eth_proto_bytes.as_mut_ptr()) } {
        return Ok(());
    }
    let eth_proto = u16::from_be_bytes(eth_proto_bytes);

    let (is_ipv6, ip_hdr_len, proto_offset, src_offset, dst_offset) = match eth_proto {
        ETH_P_IP => {
            let mut version_ihl = [0u8; 1];
            if !unsafe { load_bytes_fixed::<1>(ctx, 14, version_ihl.as_mut_ptr()) } {
                return Ok(());
            }
            let ip_hdr_len = ((version_ihl[0] & 0x0F) as usize) * 4;
            if ip_hdr_len < MIN_IP_HDR_LEN {
                return Ok(());
            }
            (false, ip_hdr_len, 23usize, 26usize, 30usize)
        }
        ETH_P_IPV6 => (true, IPV6_HDR_LEN, 20usize, 22usize, 38usize),
        _ => return Ok(()),
    };

    let mut ip_proto = [0u8; 1];
    if !unsafe { load_bytes_fixed::<1>(ctx, proto_offset, ip_proto.as_mut_ptr()) } {
        return Ok(());
    }
    if ip_proto[0] != IPPROTO_TCP {
        return Ok(());
    }

    let tcp_start = ETH_HDR_LEN + ip_hdr_len;

    if tcp_start + 13 > pkt_len {
        return Ok(());
    }
    let mut tcp_off_byte = [0u8; 1];
    if !unsafe { load_bytes_fixed::<1>(ctx, tcp_start + 12, tcp_off_byte.as_mut_ptr()) } {
        return Ok(());
    }
    let tcp_data_off = ((tcp_off_byte[0] >> 4) as usize) * 4;
    if tcp_data_off < MIN_TCP_HDR_LEN || tcp_data_off > 60 {
        return Ok(());
    }

    let tls_start = tcp_start + tcp_data_off;

    if tls_start + TLS_RECORD_HDR_LEN + 1 > pkt_len {
        return Ok(());
    }
    let mut tls_hdr = [0u8; 6];
    if !unsafe { load_bytes_fixed::<6>(ctx, tls_start, tls_hdr.as_mut_ptr()) } {
        return Ok(());
    }

    let content_type = tls_hdr[0];
    if content_type != TLS_CONTENT_HANDSHAKE {
        return Ok(());
    }

    let record_version = u16::from_be_bytes([tls_hdr[1], tls_hdr[2]]);
    if record_version < 0x0300 || record_version > 0x0303 {
        return Ok(());
    }

    let hs_type = tls_hdr[5];
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

    if payload_avail >= 1400 {
        if unsafe { load_bytes_fixed::<1400>(ctx, tls_start, scratch.event.payload.as_mut_ptr()) } {
            scratch.event.payload_len = 1400;
        }
    } else if payload_avail >= 1024 {
        if unsafe { load_bytes_fixed::<1024>(ctx, tls_start, scratch.event.payload.as_mut_ptr()) } {
            scratch.event.payload_len = 1024;
        }
    } else if payload_avail >= 512 {
        if unsafe { load_bytes_fixed::<512>(ctx, tls_start, scratch.event.payload.as_mut_ptr()) } {
            scratch.event.payload_len = 512;
        }
    } else if payload_avail >= 256 {
        if unsafe { load_bytes_fixed::<256>(ctx, tls_start, scratch.event.payload.as_mut_ptr()) } {
            scratch.event.payload_len = 256;
        }
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

    TLS_EVENTS.output(ctx, &scratch.event, 0);
    Ok(())
}
