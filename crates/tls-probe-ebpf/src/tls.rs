use aya_ebpf::bindings::TC_ACT_PIPE;
use aya_ebpf::helpers::{bpf_ktime_get_ns, bpf_skb_load_bytes};
use aya_ebpf::macros::classifier;
use aya_ebpf::programs::TcContext;
use tls_probe_common::{
    ConnKey, ReasmKey, ReasmState, FLAG_ALERT, FLAG_CONTINUATION, FLAG_FRAGMENT, FLAG_INGRESS,
    MAX_REASM_SEGMENTS, RAW_CAPTURE_HEADER_SIZE, RAW_PAYLOAD_SIZE, TLS_HANDSHAKE_CERTIFICATE,
    TLS_HANDSHAKE_CERTIFICATE_REQUEST, TLS_HANDSHAKE_CLIENT_HELLO, TLS_HANDSHAKE_SERVER_HELLO,
};

use crate::{CONN_MAP, REASM_MAP, RINGBUF_DROPS, SCRATCH, TLS_EVENTS};

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const IPPROTO_TCP: u8 = 6;
const TLS_CONTENT_HANDSHAKE: u8 = 0x16;
const TLS_CONTENT_ALERT: u8 = 0x15;

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

    // Extract addresses and ports early for REASM_MAP continuation lookup.
    // This is O(1) — we've already validated the packet structure above.
    let mut src_addr = [0u8; 16];
    let mut dst_addr = [0u8; 16];
    if is_ipv6 {
        if !unsafe {
            load_bytes_fixed::<16>(ctx, src_offset, src_addr.as_mut_ptr())
                && load_bytes_fixed::<16>(ctx, dst_offset, dst_addr.as_mut_ptr())
        } {
            return Ok(());
        }
    } else {
        let mut src4 = [0u8; 4];
        let mut dst4 = [0u8; 4];
        if !unsafe {
            load_bytes_fixed::<4>(ctx, src_offset, src4.as_mut_ptr())
                && load_bytes_fixed::<4>(ctx, dst_offset, dst4.as_mut_ptr())
        } {
            return Ok(());
        }
        src_addr[0] = src4[0];
        src_addr[1] = src4[1];
        src_addr[2] = src4[2];
        src_addr[3] = src4[3];
        dst_addr[0] = dst4[0];
        dst_addr[1] = dst4[1];
        dst_addr[2] = dst4[2];
        dst_addr[3] = dst4[3];
    }
    let mut ports = [0u8; 4];
    if !unsafe { load_bytes_fixed::<4>(ctx, tcp_start, ports.as_mut_ptr()) } {
        return Ok(());
    }
    let src_port = u16::from_be_bytes([ports[0], ports[1]]);
    let dst_port = u16::from_be_bytes([ports[2], ports[3]]);

    // Swap addresses/ports for ingress (probe sees server side).
    let (check_src_addr, check_dst_addr, check_src_port, check_dst_port) = if is_egress {
        (src_addr, dst_addr, src_port, dst_port)
    } else {
        (dst_addr, src_addr, dst_port, src_port)
    };

    let check_key = ConnKey {
        src_addr: check_src_addr,
        dst_addr: check_dst_addr,
        src_port: check_src_port,
        dst_port: check_dst_port,
    };

    // Build the reassembly key with direction: egress=0, ingress=1.
    let reasm_key = ReasmKey {
        conn: check_key,
        dir: if is_egress { 0 } else { 1 },
        _pad: [0; 3],
    };

    // Check if this is a continuation of a fragmented record.
    let is_continuation = unsafe { REASM_MAP.get(&reasm_key).is_some() };

    // Record header + handshake type in one helper call.
    let mut rec = [0u8; TLS_RECORD_HDR_LEN + 1];
    if !unsafe { load_bytes_fixed::<6>(ctx, tls_start, rec.as_mut_ptr()) } {
        return Ok(());
    }

    // If this is a continuation, we don't require 0x16 (it's pure record payload).
    // Otherwise, require handshake (0x16) or alert (0x15) content type.
    if rec[0] != TLS_CONTENT_HANDSHAKE && rec[0] != TLS_CONTENT_ALERT && !is_continuation {
        return Ok(());
    }

    let record_version = u16::from_be_bytes([rec[1], rec[2]]);
    if !is_continuation && !(0x0300..=0x0303).contains(&record_version) {
        return Ok(());
    }

    let hs_type = rec[5];
    // Skip handshake type filter for alert records (rec[0] == 0x15).
    // For handshake records (rec[0] == 0x16), verify it's a CH or SH.
    if !is_continuation && rec[0] == TLS_CONTENT_HANDSHAKE {
        // CH/SH always; Certificate/CertificateRequest are cleartext only in
        // TLS 1.2 and below (1.3 encrypted-handshake records are content type
        // 0x17, so they never reach this filter) — userspace drops the rare
        // uncorrelated-1.3 leftovers.
        if hs_type != TLS_HANDSHAKE_CLIENT_HELLO
            && hs_type != TLS_HANDSHAKE_SERVER_HELLO
            && hs_type != TLS_HANDSHAKE_CERTIFICATE
            && hs_type != TLS_HANDSHAKE_CERTIFICATE_REQUEST
        {
            return Ok(());
        }
    }

    let record_len = u16::from_be_bytes([rec[3], rec[4]]) as u32;

    let scratch = SCRATCH.get_ptr_mut(0).ok_or(())?;
    let scratch = unsafe { &mut *scratch };

    scratch.event.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    scratch.event.cgroup_id = 0;
    // For alerts, handshake_type is always 0 (sentinel); for continuations, also 0.
    // For handshake records, use the actual hs_type.
    scratch.event.handshake_type = if is_continuation || rec[0] == TLS_CONTENT_ALERT {
        0
    } else {
        hs_type
    };
    scratch.event.record_version = if is_continuation { 0 } else { record_version };
    scratch.event.is_ipv6 = is_ipv6 as u8;
    scratch.event.flags = if is_egress { 0 } else { FLAG_INGRESS };
    // Set FLAG_ALERT if this is an alert record.
    if rec[0] == TLS_CONTENT_ALERT {
        scratch.event.flags |= FLAG_ALERT;
    }
    scratch.event.content_type = rec[0];

    // Use pre-extracted addresses/ports.
    scratch.event.src_addr = src_addr;
    scratch.event.dst_addr = dst_addr;

    if !is_egress {
        let tmp = scratch.event.src_addr;
        scratch.event.src_addr = scratch.event.dst_addr;
        scratch.event.dst_addr = tmp;
    }

    scratch.event.src_port = src_port;
    scratch.event.dst_port = dst_port;

    if !is_egress {
        let tmp = scratch.event.src_port;
        scratch.event.src_port = scratch.event.dst_port;
        scratch.event.dst_port = tmp;
    }

    // Extract TCP sequence number (4 bytes at offset 4 from TCP header start).
    let mut tcp_seq_bytes = [0u8; 4];
    if tcp_start + 8 > pkt_len
        || !unsafe { load_bytes_fixed::<4>(ctx, tcp_start + 4, tcp_seq_bytes.as_mut_ptr()) }
    {
        scratch.event.tcp_seq = 0;
    } else {
        scratch.event.tcp_seq = u32::from_be_bytes(tcp_seq_bytes);
    }

    let payload_avail = pkt_len.saturating_sub(tls_start);
    // For continuations, payload_len will reflect actual payload bytes (per packet).
    // For normal packets, it will reflect available TLS record data.
    scratch.event.payload_len = 0;

    // Exact-length copy (no bucket rounding, which truncated e.g. 300→256 and
    // could clip SNI). bpf_skb_load_bytes requires a register-sized length the
    // verifier can prove is in [1, RAW_PAYLOAD_SIZE]. LLVM proves
    // payload_avail >= 6 from the record-header bounds check above and deletes
    // a plain `>= 1` guard, but the verifier cannot re-derive that relation
    // across saturating_sub and rejects the call with "invalid zero-sized
    // read". black_box hides the value's provenance so both bounds checks
    // survive into the emitted bytecode.
    let mut copy_len = core::hint::black_box(payload_avail);
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
    scratch.event.cgroup_id = 0;
    if let Some(info) = unsafe { CONN_MAP.get(&check_key) } {
        scratch.event.pid = info.pid;
        scratch.event.comm = info.comm;
        scratch.event.cgroup_id = info.cgroup_id;
    }

    // Handle continuation: if we looked up REASM_MAP and found a pending reassembly,
    // emit this as a FLAG_CONTINUATION and update the state.
    if is_continuation {
        if let Some(reasm_state) = unsafe { REASM_MAP.get(&reasm_key) } {
            scratch.event.flags |= FLAG_CONTINUATION;

            // Decrement segments_left; if we've received all segments or segments_left is 0,
            // delete the entry to allow GC.
            let new_remaining = reasm_state.remaining.saturating_sub(payload_avail as u32);
            if new_remaining == 0 || reasm_state.segments_left == 0 {
                let _ = REASM_MAP.remove(&reasm_key);
            } else {
                // Update state: decrement segments_left.
                let updated_state = ReasmState {
                    remaining: new_remaining,
                    segments_left: reasm_state.segments_left.saturating_sub(1),
                    _pad: [0; 3],
                };
                let _ = REASM_MAP.insert(&reasm_key, &updated_state, 0);
            }
        }
    } else {
        // Not a continuation: check if this (first) packet is fragmented across TCP segments.
        // record_len is the TLS record payload length (excluding the 5-byte header).
        // If we don't have the full record, mark it as a fragment and track in REASM_MAP.
        let total_record_bytes = record_len as usize + TLS_RECORD_HDR_LEN;
        if total_record_bytes > payload_avail {
            // Record is fragmented: emit this fragment and track the reassembly.
            scratch.event.flags |= FLAG_FRAGMENT;
            let remaining = (total_record_bytes - payload_avail) as u32;
            let reasm_state = ReasmState {
                remaining,
                segments_left: (MAX_REASM_SEGMENTS - 1),
                _pad: [0; 3],
            };
            // Insert or update the reassembly state for this flow.
            let _ = REASM_MAP.insert(&reasm_key, &reasm_state, 0);
        }
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
