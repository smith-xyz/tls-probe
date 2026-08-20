//! Attribution self-test: validates sock_common offset correctness at startup.
//!
//! At probe startup, after probes attach but before the main capture loop,
//! the probe makes one loopback TCP connection to itself and verifies the
//! connect kprobe attributed it (the accepting process must match the
//! connecting process PID). This catches sock_common fixed-offset issues
//! before they silently degrade event quality.

use aya::maps::{HashMap as AyaHashMap, MapData};
use std::net::{TcpListener, TcpStream};
use std::process;
use std::time::Duration;
use tls_probe_common::{ConnInfo, ConnKey};
use tracing::{info, warn};

/// Runs the attribution self-test: bind a listener on 127.0.0.1:0, connect to it,
/// then check the CONN_MAP to verify the connecting process was attributed.
///
/// Returns `true` if the test passed, `false` if it failed or was skipped.
pub fn run_self_test(conn_map: Option<&AyaHashMap<MapData, ConnKey, ConnInfo>>) -> bool {
    let Some(conn_map) = conn_map else {
        warn!("CONN_MAP not available; skipping attribution self-test");
        return false;
    };

    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(e) => {
            warn!("Failed to bind loopback listener for self-test: {}", e);
            return false;
        }
    };

    let local_addr = match listener.local_addr() {
        Ok(addr) => addr,
        Err(e) => {
            warn!("Failed to get listener address: {}", e);
            return false;
        }
    };

    // Set listener to non-blocking so we can check for connections.
    let _ = listener.set_nonblocking(true);

    let pid = process::id();

    // Connect from this process to the listener.
    let connect_result = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        TcpStream::connect(local_addr)
    });

    // Try to accept the connection within a timeout.
    let accepted = wait_for_accept(&listener, Duration::from_secs(2));
    let _ = connect_result.join();
    let _ = listener.set_nonblocking(false);

    if !accepted {
        warn!("Self-test: failed to establish loopback connection within timeout");
        return false;
    }

    // Now check CONN_MAP for the self-connection. ConnKey stores addresses as
    // [u8; 16] with IPv4 in the first four bytes (as the kprobes copy them).
    let mut localhost = [0u8; 16];
    localhost[..4].copy_from_slice(&[127, 0, 0, 1]);

    // Give the kernel a moment to update CONN_MAP.
    std::thread::sleep(Duration::from_millis(100));

    // Search CONN_MAP for an entry matching our PID.
    for (key, info) in conn_map.iter().flatten() {
        if key.src_addr == localhost && key.dst_addr == localhost && info.pid == pid {
            info!("attribution self-test passed (pid {} attributed)", pid);
            return true;
        }
    }

    // Self-test failed: we expected to find ourselves in CONN_MAP.
    // This indicates a sock_common offset mismatch.
    let warning_msg = format!(
        "Attribution self-test FAILED: The probe could not attribute the loopback \
         self-connection to pid {}. This is likely due to sock_common fixed-offset mismatch \
         (see process.rs offsets). Events from this probe will carry pid: null. \
         Workaround: migrate to BTF/CO-RE relocations when aya coverage allows.",
        pid
    );
    warn!("{}", warning_msg);

    false
}

/// Helper: wait for an incoming connection on the listener.
fn wait_for_accept(listener: &TcpListener, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;

    loop {
        match listener.accept() {
            Ok(_) => return true,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if std::time::Instant::now() >= deadline {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                warn!("Error accepting connection: {}", e);
                return false;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conn_key_self_connection() {
        // ConnKey stores addresses as [u8; 16] with IPv4 in the first four
        // bytes — the same layout run_self_test matches against.
        let mut localhost = [0u8; 16];
        localhost[..4].copy_from_slice(&[127, 0, 0, 1]);
        let any_port = 12345u16;

        let key = ConnKey {
            src_addr: localhost,
            dst_addr: localhost,
            src_port: any_port,
            dst_port: any_port,
        };

        assert_eq!(key.src_addr[..4], [127, 0, 0, 1]);
        assert_eq!(key.src_addr, key.dst_addr);
    }
}
