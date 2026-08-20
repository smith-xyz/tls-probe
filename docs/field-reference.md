# TLS Capture Event Field Reference

Generated from specs/capture-event.schema.json — do not edit by hand; regenerate with: `cargo test -p tls-probe -- --ignored generate_field_reference`

## Schema Versioning Policy

- **Schema version 1** is the initial stable release.
- **Additive changes** (new optional fields) do not require a version bump and remain compatible with existing consumers.
- **Breaking changes** (required field removal, type changes, required field additions) bump to schema version 2+.

## Fields

|Field|Type|Required|Description|
|-----|----|--------|-------------|
`alert_description`|string or null|no|Alert description (present only for alerts): named per RFC 8446, e.g. 'protocol_version(70)'
`alert_level`|string or null|no|Alert level (present only for alerts): 'warning', 'fatal', 'unknown(N)'
`certificate`|ref/union|no|Parsed leaf certificate (Certificate handshake events only)
`cgroup_id`|integer or null|no|cgroup v2 inode number for container attribution
`cipher_suites`|array|yes|
`container_id`|string or null|no|Container ID (from cgroup path); null if unresolvable
`dst`|string|yes|Destination address:port
`handshake_type`|string|yes|
`ja4`|string or null|no|JA4 client fingerprint (ClientHello events only); fingerprints TLS client behavior for identification and threat detection
`key_exchange_groups`|array|yes|
`key_share_group`|ref/union|no|
`negotiation`|ref/union|no|
`pid`|integer or null|no|
`pod_uid`|string or null|no|Pod UID (from cgroup path, Kubernetes only); null if not in a pod
`process_name`|string or null|no|
`reassembled`|boolean or null|no|
`resumption`|ref/union|no|Resumption/0-RTT signals; omitted if all flags are false
`schema_version`|string|yes|
`signature_algorithms`|array|yes|
`signature_algorithms_cert`|array or null|no|signature_algorithms_cert (0x0032) — what the client accepts in certificate chains; ML-DSA here signals PQC-cert readiness
`sni`|string or null|no|
`src`|string|yes|Source address:port
`timestamp`|string|yes|
`timestamp_ns`|integer|yes|Monotonic ktime from bpf_ktime_get_ns()
`tls_version`|string|yes|
`truncated`|boolean or null|no|
