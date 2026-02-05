#![no_std]
#![no_main]

mod tls;

use aya_ebpf::macros::map;
use aya_ebpf::maps::{PerCpuArray, PerfEventArray};
use tls_probe_common::RawTlsCapture;

#[map(name = "TLS_EVENTS")]
static TLS_EVENTS: PerfEventArray<RawTlsCapture> = PerfEventArray::new(0);

#[repr(C)]
pub struct ScratchBuf {
    pub event: RawTlsCapture,
}

#[map(name = "SCRATCH")]
static SCRATCH: PerCpuArray<ScratchBuf> = PerCpuArray::with_max_entries(1, 0);

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
