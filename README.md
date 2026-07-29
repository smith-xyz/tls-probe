# tls-probe

eBPF-based TLS handshake capture at the network layer. Uses TC classifiers on Linux to inspect TLS ClientHello and ServerHello packets and report TLS version, cipher suites, key exchange groups (including PQC/hybrid: ML-KEM, Kyber), signature algorithms, SNI, key_share, and process attribution (pid/comm via kprobe). Works with any TLS stack (OpenSSL, BoringSSL, Go, rustls). Large handshakes may be truncated to a single packet; IPv6 with complex extension headers is not fully supported.

## Prerequisites

Linux 5.8+ (or 5.x with CAP_SYS_ADMIN), Rust nightly, bpf-linker.

```bash
rustup install nightly
rustup component add rust-src --toolchain nightly
cargo install bpf-linker
```

## Build

```bash
make release
```

Or manually: `cargo xtask build-ebpf --profile release` then `cargo build --release -p tls-probe`.

## Usage

### capture

Captures TLS handshake events via eBPF and streams them as JSONL.

```bash
sudo ./target/release/tls-probe capture
```

Continuous capture, Ctrl+C to stop. Each event is one JSON line with: timestamp, src, dst, handshake_type, tls_version, cipher_suites, key_exchange_groups, key_share_group, signature_algorithms, sni, pqc_ready, pqc_groups, process_name, pid.

**Flags:**

| Flag | Description |
|------|-------------|
| `--duration N` | Capture for N seconds (0 or omit for continuous) |
| `--output path.json` | Stream events to file (JSONL) |
| `--output-timestamped` | Append Unix timestamp to output filename |
| `--interface auto\|all\|eth0` | Network interface (default: `auto` — default route) |
| `--ebpf path` | Path to compiled eBPF program (default: `target/bpfel-unknown-none/release/tls-probe-ebpf`) |

With `--output`, events are flushed to disk immediately — a crash or kill never loses more than the in-flight line. Without `--output`, the same JSONL is emitted to stdout. The probe only emits structured per-event data; aggregation and summarization are downstream concerns.

### listeners

Lists TCP sockets in LISTEN state by reading `/proc/net/tcp{,6}`.

```bash
sudo ./target/release/tls-probe listeners
sudo ./target/release/tls-probe listeners --json
sudo ./target/release/tls-probe listeners --json --json-array
sudo ./target/release/tls-probe listeners --proc-root /host/proc
```

### Global flags

| Flag | Description |
|------|-------------|
| `-l`, `--log-level` | Log level: trace, debug, info, warn, error (default: info) |

## Minimal privileges

```bash
sudo setcap 'cap_bpf,cap_net_admin,cap_perfmon,cap_sys_resource+ep' ./target/release/tls-probe
./target/release/tls-probe capture
```

## Systemd

Copy `contrib/tls-probe.service` to `/etc/systemd/system/` and enable. The service expects the binary at `/usr/local/bin/tls-probe` and eBPF object at `/usr/local/lib/tls-probe-ebpf`.

## Container

Pre-built multi-arch images are published to GHCR:

| Tag | When |
|-----|------|
| `:dev` | Every successful CI run on `main` (also `:sha-<commit>`) |
| `:latest` / `:vX.Y.Z` | Tagged releases |

```bash
# bleeding edge from main
docker pull ghcr.io/smith-xyz/tls-probe:dev

docker run --rm --privileged --net=host \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /data:/data \
  ghcr.io/smith-xyz/tls-probe:dev
```

## SELinux

On RHEL/Fedora with SELinux enforcing, install the policy under `selinux/` or run in permissive mode for testing.

## Release

Binaries and container images are built by GitHub Actions on tag push:

```bash
git tag v1.0.0
git push origin v1.0.0
```

This produces:
- GitHub Release with `tls-probe-linux-{amd64,arm64}` and `tls-probe-ebpf-{amd64,arm64}`
- GHCR image `ghcr.io/smith-xyz/tls-probe:<tag>` and `:latest` (linux/amd64 + linux/arm64)

## License

Apache-2.0
