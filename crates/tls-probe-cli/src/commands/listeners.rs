#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

//! TCP listeners (LISTEN state). Reads /proc/net/tcp and /proc/net/tcp6.
//!
//! A bpf_iter-based version would look like this once aya-ebpf exposes
//! BPF_PROG_TYPE_ITER and TcpIterContext (kernel provides the socket per iteration):
//!
//! ```ignore
//! #[bpf_iter(name = "trace_tcp")]
//! pub fn trace_tcp(ctx: TcpIterContext) -> i32 {
//!     let sock = unsafe { ctx.sock() };
//!     if sock.is_null() { return 0; }
//!     if unsafe { (*sock).__sk_common.skc_state } == TCP_LISTEN {
//!         let port = unsafe { (*sock).__sk_common.skc_num };
//!         // send (netns, port) to userspace via ringbuf/perf
//!     }
//!     0
//! }
//! ```

use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result};
use clap::Args;
use serde::Serialize;

const STATE_LISTEN: u8 = 0x0A;

#[derive(Args, Default)]
pub struct ListenersArgs {
    #[arg(
        long,
        help = "Output as JSON (one object per line or array with --json-array)"
    )]
    pub json: bool,

    #[arg(long, help = "With --json, output a single JSON array")]
    pub json_array: bool,

    #[arg(long, default_value = "/proc", help = "Root path to proc filesystem (e.g. /host/proc)")]
    pub proc_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ListenEntry {
    pub addr: IpAddr,
    pub port: u16,
}

fn parse_hex_port(s: &str) -> Result<u16> {
    let port = u16::from_str_radix(s, 16)
        .with_context(|| format!("invalid port hex: {}", s))?;
    Ok(port)
}

fn parse_ipv4_hex(hex: &str) -> Result<IpAddr> {
    let hex = hex.trim_start_matches('0');
    let full = if hex.is_empty() {
        "0"
    } else {
        hex
    };
    let value = u32::from_str_radix(full, 16)
        .with_context(|| format!("invalid IPv4 hex: {}", hex))?;
    let octets = value.to_be_bytes();
    Ok(IpAddr::V4(std::net::Ipv4Addr::new(
        octets[0], octets[1], octets[2], octets[3],
    )))
}

fn parse_ipv6_hex(hex: &str) -> Result<IpAddr> {
    if hex.len() != 32 {
        anyhow::bail!("invalid IPv6 hex length: {}", hex.len());
    }
    let mut bytes = [0u8; 16];
    for word in 0..4 {
        let chunk = &hex[word * 8..(word + 1) * 8];
        let val = u32::from_str_radix(chunk, 16)
            .with_context(|| format!("invalid IPv6 hex word: {}", chunk))?;
        bytes[word * 4..(word + 1) * 4].copy_from_slice(&u32::from_le(val).to_be_bytes());
    }
    Ok(IpAddr::V6(std::net::Ipv6Addr::from(bytes)))
}

fn parse_listen_line(
    line: &str,
    parse_addr: fn(&str) -> Result<IpAddr>,
) -> Option<Result<ListenEntry>> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }
    let state = u8::from_str_radix(parts.get(3)?, 16).ok()?;
    if state != STATE_LISTEN {
        return None;
    }
    let local = *parts.get(1)?;
    let mut split = local.split(':');
    let ip_hex = split.next()?;
    let port_hex = split.next()?;
    let port = parse_hex_port(port_hex).ok()?;
    let addr = parse_addr(ip_hex).ok()?;
    Some(Ok(ListenEntry { addr, port }))
}

fn read_listeners_proc(path: &Path, parse_line: fn(&str) -> Option<Result<ListenEntry>>) -> Result<Vec<ListenEntry>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?;
    let mut out = Vec::new();
    for line in content.lines().skip(1) {
        if let Some(entry) = parse_line(line) {
            match entry {
                Ok(e) => out.push(e),
                Err(e) => return Err(e),
            }
        }
    }
    Ok(out)
}

pub fn run(args: ListenersArgs) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let root = Path::new(&args.proc_root);
        let tcp_path = root.join("net/tcp");
        let tcp6_path = root.join("net/tcp6");

        let mut entries = Vec::new();
        if tcp_path.exists() {
            entries.extend(read_listeners_proc(&tcp_path, |l| parse_listen_line(l, parse_ipv4_hex))?);
        }
        if tcp6_path.exists() {
            entries.extend(read_listeners_proc(&tcp6_path, |l| parse_listen_line(l, parse_ipv6_hex))?);
        }
        entries.sort_by(|a, b| (a.addr, a.port).cmp(&(b.addr, b.port)));

        if args.json_array {
            println!("{}", serde_json::to_string_pretty(&entries)?);
        } else if args.json {
            for e in &entries {
                println!("{}", serde_json::to_string(e)?);
            }
        } else {
            println!("TCP listeners (LISTEN):");
            for e in &entries {
                println!("  {}:{}", e.addr, e.port);
            }
            println!("Total: {}", entries.len());
        }
        return Ok(());
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        anyhow::bail!("listeners command is only supported on Linux (reads /proc/net/tcp)");
    }
}
