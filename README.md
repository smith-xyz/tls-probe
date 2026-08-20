# tls-probe

Passive TLS negotiation and posture probe built on eBPF. TC classifiers inspect TLS handshake traffic at the network layer — no TLS-library uprobes, no Kubernetes API calls, no agents in workloads — and stream one structured JSON event per handshake message. Works with any TLS stack (OpenSSL, BoringSSL, Go, rustls) because it never touches the stack: it reads packets.

Built for PQC-readiness analysis: it captures hybrid post-quantum ClientHellos (X25519MLKEM768) intact across packet boundaries, correlates what clients offer against what servers select, and flags the gap.

## Coverage

One row per thing on the wire: what the probe emits for it, and what it cannot see there. The TC classifier matches on TLS record content type, not port numbers — **any TCP port** on the attached interfaces (`--interface auto|all|<name>`) is covered, no port list to maintain.

| On the wire | Event emitted | Key fields | Not visible here |
|-------------|---------------|------------|------------------|
| TLS 1.2/1.3 ClientHello — any TCP port, any TLS stack | `ClientHello` | `cipher_suites`, `key_exchange_groups`, `key_share_group`, `signature_algorithms`, `signature_algorithms_cert` (ML-DSA here = PQC-cert readiness), `sni`, `ja4`, `resumption` offer flags | Records split across IP fragments — TCP segmentation is handled, IP fragmentation is not ([packet handling](docs/limitations.md#packet-and-record-handling)) |
| Oversized/segmented ClientHello — hybrid PQC (X25519MLKEM768, ~1.9 KB, spans TCP segments at MTU 1500) | Same `ClientHello`, reassembled in userspace, `reassembled: true` | All ClientHello fields, parsed whole | Past 4 segments / 16 KB / 3 s per flow, the available prefix is parsed and `truncated: true` is set ([reassembly caps](docs/limitations.md#reassembly-caps)) |
| ServerHello | `ServerHello`, correlated to its ClientHello | Negotiated `tls_version` and `key_share_group`; `negotiation`: `outcome`, `client_offered_groups` (the client's supported_groups, GREASE filtered), `selected_group`, `psk_selected`, `mtls_requested`/`mtls`; `resumption.psk_selected` — reasoning about PQC gaps and downgrades is reserved for downstream consumers given the offered/selected groups | Everything after the ServerHello on TLS 1.3 flows is encrypted ([TLS 1.3 boundary](docs/limitations.md#tls-13-encryption-boundary)) |
| Plaintext alert rejecting a ClientHello | `Alert`, joined to the offering ClientHello | `alert_level`, named `alert_description` (`protocol_version`, `handshake_failure`, …), `negotiation.outcome: "failed"` | Encrypted (post-ServerHello TLS 1.3) alerts; alerts with no matching ClientHello are dropped, counted in `alerts_dropped` ([plaintext alerts only](docs/limitations.md#plaintext-alerts-only)) |
| TLS 1.2 server certificate | `Certificate` | `certificate`: `not_before`/`not_after`, `expired`, `public_key_algorithm` + `public_key_bits`, `signature_algorithm`, `self_signed`, subject/issuer CN, `san_count` | Leaf only, not the chain; TLS 1.3 certificates are encrypted — filtered out, counted in `certs_dropped_13` ([TLS 1.3 boundary](docs/limitations.md#tls-13-encryption-boundary)) |
| mTLS on TLS 1.2 | `CertificateRequest` event; `mtls_requested` / `mtls` flags on `negotiation` | `mtls_requested` (server asked for a client cert), `mtls` (client presented one) | TLS 1.3 client certificates — encrypted ([TLS 1.3 boundary](docs/limitations.md#tls-13-encryption-boundary)) |
| Resumption / 0-RTT | `resumption` object on ClientHello (offers) and ServerHello (selection) | `psk_offered`, `psk_selected`, `early_data_offered`, `session_ticket_offered` — replay-exposure and ticket-hygiene visibility | 0-RTT *acceptance* (TLS 1.3 EncryptedExtensions) — encrypted; offer and PSK selection are the signals |
| Client identity | `ja4` on every ClientHello | JA4 TLS-client fingerprint | JA4 only — no JA3, no JA4+ siblings (JA4S, JA4H, …) |
| The process behind any event above | `pid`, `process_name` on the event | Outbound via `tcp_v{4,6}_connect` kprobes; inbound (server side) via `inet_csk_accept` kretprobe | Fixed `sock_common` offsets can drift on patched kernels — the startup loopback canary warns loudly if attribution is broken; TFO/pre-accept handshakes yield `pid: null` ([process attribution](docs/limitations.md#process-attribution-coverage)) |
| The container/pod behind any event above | `cgroup_id`, `container_id`, `pod_uid` on the event | Resolved from cgroupfs paths — CRI-O, containerd, Docker, podman — no Kubernetes API calls | cgroup v2 only; pod name/namespace is a downstream join on `pod_uid` ([container attribution](docs/limitations.md#containerpod-attribution)) |
| Probe health | Periodic `counters:` log line | `emitted`, `dropped`, `kernel_lost`, `chunks_evicted`, `correlator_sh_without_ch`, `alerts_dropped`, `certs_dropped_13` | Meanings in the [capture section](#capture) below |

**Not covered:** QUIC (TLS over UDP), SSH, and plaintext-protocol inventory — future work, not captured today. TLS 1.3 certificates, encrypted alerts, and IP-fragmented records are hard passive-capture boundaries — see [docs/limitations.md](docs/limitations.md).

Every event carries `schema_version`; evolution within v1 is additive. See [docs/field-reference.md](docs/field-reference.md) for the full field reference (generated from the committed schema, `specs/capture-event.schema.json`) and [docs/kernel-support.md](docs/kernel-support.md) for the kernel matrix.

**Know what it can't see:** [docs/limitations.md](docs/limitations.md) — TLS 1.3 encryption boundary, attribution edge cases, reassembly caps, and more. Read it before trusting absence of evidence.

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

On macOS or another non-Linux host, build/test/smoke/bench via the
committed dev container instead: `make container-test` — see
[docs/dev-container.md](docs/dev-container.md).

## Usage

### capture

Captures TLS handshake events via eBPF and streams them as JSONL.

```bash
sudo ./target/release/tls-probe capture
```

Continuous capture, Ctrl+C to stop. Each event is one JSON line; core fields: `schema_version`, `timestamp`, `src`, `dst`, `handshake_type`, `tls_version`, `cipher_suites`, `key_exchange_groups`, `key_share_group`, `signature_algorithms`, `signature_algorithms_cert`, `sni`, `ja4`, `process_name`, `pid`, `cgroup_id`, `container_id`, `pod_uid`, plus per-message objects: `negotiation`, `resumption`, `certificate`, `alert_level`/`alert_description`, `reassembled`/`truncated`.

**Flags:**

| Flag | Description |
|------|-------------|
| `--duration N` | Capture for N seconds (0 or omit for continuous) |
| `--output path.json` | Stream events to file (JSONL) |
| `--output-timestamped` | Append Unix timestamp to output filename |
| `--max-output-bytes N` | Rotate output chunks at N bytes (spool mode) |
| `--max-total-bytes N` | Cap total spool size; evict oldest complete chunks |
| `--interface auto\|all\|eth0` | Network interface (default: `auto` — default route) |
| `--ebpf path` | Path to compiled eBPF program (default: `target/bpfel-unknown-none/release/tls-probe-ebpf`) |
| `--cgroup-root path` | Root of the cgroup v2 filesystem for container attribution (default `/sys/fs/cgroup`; set to the host mount, e.g. `/host/sys/fs/cgroup`, when running containerized) |
| `--no-self-test` | Skip the startup attribution self-test (a loopback canary that verifies process attribution works on this kernel — see [docs/limitations.md](docs/limitations.md)) |

With `--output`, events are flushed to disk immediately — a crash or kill never loses more than the in-flight line. Without `--output`, the same JSONL is emitted to stdout. The probe only emits structured per-event data; aggregation and summarization are downstream concerns.

**Counters:** the probe logs a counters line periodically and at shutdown so operators can see every subsystem working:

```
counters: emitted=… dropped=… kernel_lost=… chunks_evicted=… correlator_sh_without_ch=… alerts_dropped=… certs_dropped_13=…
```

| Counter | Meaning |
|---------|---------|
| `emitted` | Events written to output |
| `dropped` | Events dropped in userspace (channel backpressure) |
| `kernel_lost` | Ringbuf reservations that failed in the kernel (events lost before userspace) |
| `chunks_evicted` | Spool chunks evicted under `--max-total-bytes` |
| `correlator_sh_without_ch` | ServerHellos with no pending ClientHello (probe started mid-handshake, or CH missed) |
| `alerts_dropped` | Alert records without a matching ClientHello, or malformed (dropped, not emitted) |
| `certs_dropped_13` | Certificate/CertificateRequest messages on TLS 1.3 flows dropped (encrypted-handshake noise filter) |

Non-zero `kernel_lost` under load → the 512 KiB ringbuf is saturating; sustained `correlator_sh_without_ch` growth on a quiet host is normal churn from mid-handshake attach.

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

Copy `contrib/tls-probe.service` to `/etc/systemd/system/` and enable. The service expects the binary at `/usr/local/bin/tls-probe` and eBPF object at `/usr/local/lib/tls-probe-ebpf`. The unit runs with only the four capabilities above (no full root privileges kept) and read-only access to `/sys/fs/cgroup` for container attribution; on a host deploy the default `--cgroup-root` is correct as-is.

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
  -v /sys/fs/cgroup:/host/sys/fs/cgroup:ro \
  -v /data:/data \
  ghcr.io/smith-xyz/tls-probe:dev \
  capture --cgroup-root /host/sys/fs/cgroup --output /data/events.json
```

`--privileged` (or the explicit capability set: CAP_BPF, CAP_NET_ADMIN, CAP_PERFMON, CAP_SYS_RESOURCE) and `--net=host` are required — the probe attaches TC classifiers to host interfaces and kprobes to the host kernel. Mount the host's cgroup v2 filesystem and pass `--cgroup-root` or container/pod attribution resolves against the container's own (useless) cgroup view.

## SELinux

On RHEL/Fedora with SELinux enforcing, install the policy under `selinux/` (`make -C selinux && make -C selinux install`) or run in permissive mode for testing. The policy covers BPF program/map operations, perf-event probe attachment, TC via netlink, and read access to cgroupfs for container attribution.

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
