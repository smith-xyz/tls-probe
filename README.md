# tls-probe

eBPF-based TLS handshake capture at the network layer. Uses TC classifiers on Linux to inspect TLS ClientHello and ServerHello in packets and report TLS version, cipher suites, key exchange groups (including PQC/hybrid: ML-KEM, Kyber), signature algorithms, and key_share. Works with any TLS stack (OpenSSL, BoringSSL, Go, rustls). No process context (no pid/comm). Large handshakes may be truncated to a single packet; IPv6 with complex extension headers is not fully supported.

Prerequisites: Linux 5.8+ (or 5.x with CAP_SYS_ADMIN), BTF, Rust nightly, bpf-linker.

Install Rust nightly and bpf-linker:

```bash
rustup install nightly
rustup component add rust-src --toolchain nightly
cargo install bpf-linker
```

Build (eBPF + CLI, release):

```bash
make release
```

Or: `cargo xtask build-ebpf` then `cargo build --release -p tls-probe`. eBPF binary is at `target/bpfel-unknown-none/release/tls-probe-ebpf`.

Run with enough privilege (capabilities or root). Required: CAP_BPF, CAP_NET_ADMIN, CAP_PERFMON, CAP_SYS_RESOURCE; or CAP_SYS_ADMIN on older kernels. On RHEL/Fedora with SELinux enforcing, install the policy under `selinux/` or run in permissive mode for testing.

```bash
sudo ./target/release/tls-probe capture
```

Continuous capture, Ctrl+C to stop. Optional: `--duration N` (seconds), `--output path.json` (write JSON to file), `--interface auto|all|eth0`, `--analyze` (richer JSON), `--summary` (print stats at end). With `--output`, the file contains a JSON array of analyzed events (timestamp, src, dst, handshake type, TLS version, cipher_suites, key_exchange_groups, key_share_group, signature_algorithms, pqc_ready, pqc_groups). Without `--output`, events are logged to stdout; with `--analyze` each line is full analysis JSON.

Minimal privileges instead of sudo:

```bash
sudo setcap 'cap_bpf,cap_net_admin,cap_perfmon,cap_sys_resource+ep' ./target/release/tls-probe
./target/release/tls-probe capture
```

Docker: `make docker` then run the image with cap-add BPF, NET_ADMIN, PERFMON, SYS_RESOURCE, --net=host, and mounts for /sys/kernel/debug, /sys/fs/bpf. Systemd: copy `contrib/tls-probe.service` to /etc/systemd/system and enable (service expects binary at /usr/local/bin/tls-probe).

License: Apache-2.0
