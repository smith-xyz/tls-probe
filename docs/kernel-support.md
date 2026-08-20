# Kernel support

Minimum kernel: **5.8**. Set by `BPF_MAP_TYPE_RINGBUF` — every other BPF
feature the probe uses landed earlier.

## Feature floor

| Feature | Used for | Kernel |
|---------|----------|--------|
| `BPF_MAP_TYPE_RINGBUF` | event stream to userspace (`TLS_EVENTS`) | **5.8** |
| `bpf_get_current_cgroup_id()` | container attribution | 4.18 |
| `BPF_MAP_TYPE_LRU_HASH` | `CONN_MAP`, `REASM_MAP` | 4.10 |
| `BPF_MAP_TYPE_PERCPU_ARRAY` | scratch space | 4.6 |
| TC `cls_bpf` direct-action classifier | packet capture on ingress/egress | 4.5 |
| kprobe / kretprobe programs | connect/accept attribution | ancient |

## Tested kernels

| Kernel | Coverage |
|--------|----------|
| 6.x (Ubuntu 22.04 GitHub Actions runner) | CI, every push: `smoke-test` (loopback TLS scenarios) + `container-attribution` (cgroup attribution against a real container) |
| 5.8–6.x (other) | best-effort — floor is derived from feature availability, not exercised in CI (waiver below) |

## Why no CI job for the 5.8 floor (waiver)

A vmtest-style job (qemu/KVM, e.g. `danobi/vmtest`) is mechanically possible
on GitHub runners — `/dev/kvm` is exposed and boot time is seconds. It was
waived because sourcing the kernel image is not cheap:

- 5.8 is non-LTS and EOL since 2020-11. No maintained prebuilt BPF test
  images exist for it (libbpf CI publishes LTS kernels only).
- A custom build needs non-default configs (`NET_CLS_BPF`,
  `NET_SCH_INGRESS`, kprobes, cgroups, virtio/9p) and 5.8 does not compile
  cleanly under GCC ≥ 11 without backported fixes — so CI would either
  rebuild a patched kernel every run or we maintain a hosted binary blob.
- The features above are API-stable at 5.8; a green boot-and-attach job adds
  little signal, while a flaky one is permanent noise. The one real
  portability risk is version-agnostic and canaried at runtime (next
  section).

Revisit if either happens: a maintained prebuilt 5.8-class BPF test image
becomes available, or attribution moves to CO-RE (then a multi-kernel matrix
is worth the infra).

## Fixed-offset caveat (applies to every kernel)

The attribution kprobes read `struct sock_common` at **hardcoded offsets**
(`crates/tls-probe-ebpf/src/process.rs`) — not CO-RE/BTF-relocated. Offsets
match the mainline layout; a kernel with a different layout breaks silently:
TLS events still flow, but `pid` / `process_name` / `container_id` are
missing or garbage.

Canary: the smoke test's `process_attribution` check
(`scripts/smoke_test.py`, `check_process_attribution`) asserts events carry a
`pid`. On a mismatched kernel it reports `0/N events attributed`. Run the
smoke test on any new target kernel before trusting attribution there.
