# Limitations

What tls-probe cannot see, by design or by current implementation. Passive,
stack-agnostic capture has hard boundaries — treat missing data as "not
visible", never as "not happening".

## TLS 1.3 encryption boundary

Everything after the ServerHello in TLS 1.3 is encrypted. Consequences:

- **No certificates on TLS 1.3 flows.** Certificate posture (expiry, key
  size, self-signed) is available for TLS 1.2 only. The kernel does capture
  1.3 encrypted-handshake records that look like Certificate messages;
  userspace filters them out (`certs_dropped_13` counter) rather than emit
  garbage.
- **No encrypted alerts.** See below.
- **ML-DSA adoption is unmeasurable passively.** The probe reports ML-DSA
  *readiness* — the client offered ML-DSA ids in `signature_algorithms` or
  `signature_algorithms_cert` — but actual negotiated certificate chains and
  CertificateVerify are encrypted. Readiness is the signal; adoption needs an
  active scanner or TLS-library instrumentation, both out of scope.

## Plaintext alerts only

Alert capture covers alerts sent before encryption starts — a server
rejecting a ClientHello (`protocol_version`, `handshake_failure`,
`unknown_ca` in TLS 1.2). Post-ServerHello alerts in TLS 1.3 are encrypted
and invisible. A flow with `outcome: "failed"` is a hard signal; a flow
without one is not proof of success.

## Process attribution coverage

- **Fixed `sock_common` offsets.** The connect kprobes and accept kretprobe
  read socket 4-tuples at fixed struct offsets (not CO-RE/BTF-relocated —
  aya's BTF support does not yet cover this usage). Offsets match mainline
  layouts on recent kernels (RHCOS 5.14+ verified) but can drift on patched
  or older kernels. **Mitigation:** at startup the probe runs a loopback
  self-test and logs a prominent warning if its own connection fails to
  attribute — silent `pid: null` forever is the failure mode the canary
  exists to catch. Disable with `--no-self-test` (e.g. hermetic environments
  where loopback is unavailable).
- **Connect-entry timing.** Outbound attribution records at `connect(2)`
  entry; connections established by other paths are not recorded.
- **TCP fast-open and pre-accept data.** Inbound attribution fires when
  `inet_csk_accept` returns. Handshakes completed by the kernel before the
  application calls `accept()` (TFO, aggressive backlogs) can produce events
  before the attribution entry exists → `pid: null` on those events.

## Container/pod attribution

- **cgroup v2 only.** Resolution walks the cgroup2 filesystem mapping inode →
  path. On pure cgroup-v1 hosts, `cgroup_id` is emitted but `container_id`
  and `pod_uid` are null.
- **Runtime path patterns.** Parsers cover CRI-O, containerd, Docker, and
  podman (libpod) systemd-scope layouts. Exotic cgroup layouts resolve to
  null container fields.
- **Containerized probe needs the host view.** Without mounting host cgroupfs
  and setting `--cgroup-root`, resolution runs against the probe container's
  own cgroup namespace and misses everything else.

## Packet and record handling

- **Multiple TLS records per packet.** The kernel captures the first TLS
  record in a packet. One packing is recovered in userspace: records trailing
  a TLS 1.2 ServerHello in the same packet (Certificate, CertificateRequest,
  ServerHelloDone — the standard 1.2 server flight). Any other
  multi-record packing is dropped after the first record.
- **IP fragmentation is not reassembled.** TCP segmentation is handled (see
  reassembly below); IP-layer fragments are not — a handshake record split
  across IP fragments is missed or truncated.
- **IPv6 extension headers.** Flows with extension headers between the IPv6
  header and TCP are not fully parsed and may be missed.

## Reassembly caps

Multi-packet records (segmented PQC hellos, 1.2 certificate flights) are
reassembled in userspace under hard bounds — a hostile peer must not turn
the probe into a flow recorder:

- 4 segments and 16 KB per flow, 3-second timeout, 1024 in-flight flows
  (LRU).
- Cap or timeout hit → the available prefix is parsed and the event is
  emitted with `truncated: true`. Certificate flights larger than the cap
  usually still yield the leaf certificate (it comes first).

## Scope (by design, not gaps)

- No TLS-library uprobes, no Kubernetes API calls, no active scanning.
- Per-event structured output only; aggregation is downstream.
- `pod_uid` → name/namespace enrichment is a downstream join.
