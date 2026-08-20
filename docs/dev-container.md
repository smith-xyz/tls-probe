# Dev container

eBPF build/test/smoke/bench need a Linux kernel. This runs them in a
container so a macOS (or other non-Linux) host doesn't need a separate VM
per task — one image, one wrapper script (`contrib/dev/run.sh`).

Podman only. eBPF attach needs real root, so this needs a
privileged/rootful podman — rootless podman's `--privileged` cannot grant
the capabilities eBPF attach needs.

The image is Debian trixie (`contrib/dev/Containerfile`) for its
OpenSSL 3.5+, which the `netns_pqc` smoke scenario needs to generate a
real `X25519MLKEM768` ClientHello (`scripts/smoke_test.py` probes
`openssl list -kem-algorithms` and skips the scenario, without failing
the run, if it's absent — Ubuntu 22.04/24.04 both stop at OpenSSL 3.0.x,
so that scenario is silently skipped there).

This container does **not** need to match CI's `ubuntu-22.04` runner or
its `GLIBC_MAX=2.34` compatibility gate. That check verifies the actual
shipped release binary, built directly on GitHub's `ubuntu-22.04` runners
in the `build-cli` job — a job this container never runs. Binaries built
in here (`container-test`, `container-smoke`, `container-bench`) never
leave the container.

## macOS setup (one-time)

```sh
podman machine init                                   # if you don't have one
podman machine set --rootful podman-machine-default
podman machine start
```

## Linux

Rootless podman can't attach eBPF. Run `contrib/dev/run.sh` (or the
`make container-*` targets) under `sudo`, or point `PODMAN_CONNECTION` at
a rootful podman socket.

## Usage

```sh
make container-image   # build/rebuild the image (also happens automatically on first use)
make container-test    # build-ebpf + cargo test + clippy + fmt-check — mirrors CI's `test` job
make container-smoke   # release build + scripts/smoke_test.py — mirrors CI's `smoke-test` job
make container-bench   # release build + contrib/bench/run_bench.sh — see docs/performance.md
make container-shell   # interactive shell in the container
```

Or call the script directly for extra args, e.g. a longer bench run:

```sh
contrib/dev/run.sh bench -- --iperf-runs 5 --storm-runs 5
```

## Persistence

Two named podman volumes persist across runs so every invocation doesn't
re-download crates or rebuild from scratch:

- `tlsprobe-target` — mounted at `/work/target-linux` (`CARGO_TARGET_DIR`).
  Kept separate from the host's own `target/` so a Linux host running both
  natively and in-container doesn't have two toolchains fighting over one
  target dir. Gitignored (`/target-linux/` in `.gitignore`).
- `tlsprobe-cargo-registry` — mounted at `/usr/local/cargo/registry`.

Drop both to force a clean rebuild: `podman volume rm tlsprobe-target
tlsprobe-cargo-registry` (add `--connection podman-machine-default-root`
on macOS).

## What this does not cover

- `container-attribution` CI job (Docker workload attribution) — needs a
  Docker daemon reachable from inside the container (Docker-in-Podman);
  not wired up here.
- Multi-arch cross-compiled release artifacts — CI's `build-cli` matrix
  job. This container builds/tests for its own arch only.
