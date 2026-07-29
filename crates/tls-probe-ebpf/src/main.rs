#![no_std]
#![no_main]

mod process;
mod tls;

use aya_ebpf::macros::map;
use aya_ebpf::maps::{LruHashMap, PerCpuArray, RingBuf};
use tls_probe_common::{ConnInfo, ConnKey, RawTlsCapture};

#[map(name = "TLS_EVENTS")]
static TLS_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Connections observed via the `tcp_v4_connect`/`tcp_v6_connect` kprobes,
/// keyed by 4-tuple so the TC classifier can attribute a TLS handshake to
/// the process that initiated the underlying TCP connection.
#[map(name = "CONN_MAP")]
static CONN_MAP: LruHashMap<ConnKey, ConnInfo> = LruHashMap::with_max_entries(8192, 0);

#[repr(C)]
pub struct ScratchBuf {
    pub event: RawTlsCapture,
}

#[map(name = "SCRATCH")]
static SCRATCH: PerCpuArray<ScratchBuf> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "RINGBUF_DROPS")]
static RINGBUF_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
