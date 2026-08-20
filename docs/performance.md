# Performance baseline

Overhead of the tls-probe TC classifier, measured attached vs detached on
loopback. Produced by `contrib/bench/run_bench.sh`. This is a committed
baseline for tracking regressions by hand — **not a CI gate yet**. Re-run the
bench and update this file when the datapath changes.

## Method

Both benches run via the committed dev container — see
[docs/dev-container.md](dev-container.md) for one-time setup:

```sh
make container-bench
# or, for more runs: contrib/dev/run.sh bench -- --iperf-runs 5 --storm-runs 5
```

1. **Throughput** — iperf3 TCP client/server over `lo`, 3 × 5 s runs per mode,
   median reported. Measures raw per-packet cost of the TC classifier on
   traffic it inspects and discards (iperf3 traffic is not TLS).
2. **Handshake storm** — `openssl s_server` (P-256 cert, TLS 1.3) plus a
   Python client running 1000 sequential handshakes, 3 runs per mode, median
   handshakes/s. Measures end-to-end cost on the traffic the probe actually
   captures, and exercises the ringbuf → userspace pipeline. The probe's
   final `counters:` line is recorded to show ringbuf behavior under storm.

**Caveat:** numbers come from an aarch64 Fedora podman VM (kernel 6.12,
7 vCPUs) on an Apple Silicon macOS host. Loopback throughput and absolute
handshake rates are not representative of production NICs or x86 servers —
treat the deltas as indicative, the absolutes as environment-specific.

## Results (2026-08-06)

### Throughput (iperf3, loopback TCP, median of 3 × 5 s)

| Mode | Gbit/s (median) | Individual runs |
|------|-----------------|-----------------|
| Detached | 90.44 | 89.97, 92.88, 90.44 |
| Attached | 86.16 | 86.07, 86.16, 87.42 |
| **Delta** | **-4.7%** | |

Probe counters after the iperf phase were all zero
(`emitted=0 dropped=0 kernel_lost=0`) — the classifier inspects and ignores
non-TLS traffic without emitting events, so the -4.7% is pure per-packet
classifier cost at ~90 Gbit/s loopback rates (an adversarial case: production
NIC line rates are far lower).

### Handshake storm (TLS 1.3, median of 3 × 1000 sequential handshakes)

| Mode | Handshakes/s (median) | Individual runs |
|------|-----------------------|-----------------|
| Detached | 1913 | 1819, 1928, 1913 |
| Attached | 1807 | 1493, 1822, 1807 |
| **Delta** | **-5.5%** | |

Counters after 3000 attached handshakes (~7200 events/s during runs):

```
counters: emitted=12000 dropped=0 kernel_lost=0 chunks_evicted=0
          correlator_sh_without_ch=0 alerts_dropped=0 certs_dropped_13=0
```

Exactly 4 events per handshake, zero kernel ringbuf loss, zero userspace
drops — the 512 KiB ringbuf has ample headroom at ~1800 handshakes/s.

## Sizing guidance

Current sizes (compile-time constants in `crates/tls-probe-ebpf/src/main.rs`
and `crates/tls-probe-cli/src/correlate.rs`):

| Structure | Size | Grow when |
|-----------|------|-----------|
| `TLS_EVENTS` ringbuf | 512 KiB | `kernel_lost > 0` in counters |
| `CONN_MAP` (LRU) | 8192 entries | concurrent TLS connections near 8k |
| `REASM_MAP` (LRU) | 1024 entries | >1k simultaneous fragmented handshakes |
| Correlator (userspace) | 8192 entries, 10 s TTL | `correlator_sh_without_ch > 0` |

### Ringbuf: 512 KiB

An event on the wire is an 88-byte fixed header plus a variable payload up to
4096 bytes (`RAW_PAYLOAD_SIZE`), plus the 8-byte BPF ringbuf record header —
roughly 100 B (minimal record) to ~4.2 KiB (full certificate fragment).

Headroom math: userspace drains continuously but the buffer must absorb
bursts. At the worst case (every event a full 4.2 KiB), 512 KiB holds ~125
events; at a typical handshake mix (~400 B average, as in the storm above) it
holds ~1300 events, i.e. more than 300 handshakes of burst. The measured
storm (~7200 events/s sustained) produced zero `kernel_lost`. Grow the
ringbuf if counters show `kernel_lost > 0` — expect that first on hosts with
very high handshake rates combined with large payloads (e.g. PQC ClientHellos
with ML-KEM key shares run ~1.7 KiB+, cutting per-event headroom ~4x versus
classical hellos).

### CONN_MAP: 8192 (LRU)

Tracks per-connection TLS state in the kernel. LRU means overflow evicts the
oldest entry rather than failing, so the symptom of undersizing is silent
mid-handshake state loss (missing continuation/fragment events), not an
error. 8192 covers thousands of concurrent handshaking connections; grow it
on hosts with sustained high connection rates or long-lived NAT fan-in where
many peers hold connections open through the same probe.

### REASM_MAP: 1024 (LRU)

Only handshake messages that span multiple TCP segments (large certificate
chains, oversized ClientHellos) occupy this map, and entries are short-lived
(userspace reassembly times out at 3 s). 1024 in-flight fragmented handshakes
is generous for most hosts; grow it alongside CONN_MAP if certificate-heavy
traffic (mTLS, long chains) dominates at high connection rates.

### Correlator: 8192 entries, 10 s TTL

Userspace map pairing ClientHellos with their ServerHellos. Sized as
handshake-rate × server-response-time: 8192 entries absorbs ~800 handshakes/s
against a slow 10 s tail, or ~8k/s against 1 s responses.
`correlator_sh_without_ch > 0` means ClientHellos aged out (or were evicted) before the
ServerHello arrived — grow entries or TTL when probing paths with slow
servers at high handshake rates.

## Not a CI gate

These numbers are a manual baseline. Loopback-in-a-VM deltas are stable
enough to spot gross regressions (a classifier change doubling per-packet
cost) but too noisy for tight thresholds. Before promoting to CI: pin the
runner hardware, raise run counts, and gate on the storm delta rather than
raw loopback Gbit/s.
