#!/usr/bin/env bash
# Run eBPF build/test/smoke/bench in a container instead of requiring a
# bare-metal Linux host. Podman only. eBPF attach needs real root, so this
# needs a privileged/rootful podman, not rootless.
#
# macOS setup (one-time):
#   podman machine init                                   # if you don't have one
#   podman machine set --rootful podman-machine-default
#   podman machine start
#
# Linux: rootless podman's --privileged can't grant the capabilities eBPF
# attach needs — run this script under sudo, or point PODMAN_CONNECTION at
# a rootful podman socket.
#
# Usage:
#   contrib/dev/run.sh image                 # build/rebuild the dev image
#   contrib/dev/run.sh test                  # build-ebpf + cargo test + clippy + fmt-check (mirrors CI `test` job)
#   contrib/dev/run.sh smoke                 # release build + scripts/smoke_test.py (mirrors CI `smoke-test` job)
#   contrib/dev/run.sh bench [-- bench args] # release build + contrib/bench/run_bench.sh
#   contrib/dev/run.sh shell                 # interactive shell in the container

set -euo pipefail

IMAGE="localhost/tls-probe-dev:trixie"
CONTAINERFILE="contrib/dev/Containerfile"
TARGET_VOLUME="tlsprobe-target"
CARGO_VOLUME="tlsprobe-cargo-registry"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

PODMAN=(podman)
if [[ "$(uname -s)" == "Darwin" ]]; then
    PODMAN=(podman --connection "${PODMAN_CONNECTION:-podman-machine-default-root}")
fi

ensure_volumes() {
    "${PODMAN[@]}" volume inspect "$TARGET_VOLUME" >/dev/null 2>&1 \
        || "${PODMAN[@]}" volume create "$TARGET_VOLUME" >/dev/null
    "${PODMAN[@]}" volume inspect "$CARGO_VOLUME" >/dev/null 2>&1 \
        || "${PODMAN[@]}" volume create "$CARGO_VOLUME" >/dev/null
}

build_image() {
    "${PODMAN[@]}" build -t "$IMAGE" -f "$CONTAINERFILE" "$repo_root"
}

ensure_image() {
    "${PODMAN[@]}" image exists "$IMAGE" || build_image
}

run_in_container() { # $1 = shell command to run inside /work
    ensure_volumes
    ensure_image
    "${PODMAN[@]}" run --rm --privileged \
        -v "$repo_root":/work \
        -v "$TARGET_VOLUME":/work/target-linux \
        -v "$CARGO_VOLUME":/usr/local/cargo/registry \
        -e CARGO_TARGET_DIR=/work/target-linux \
        -w /work \
        "$IMAGE" \
        bash -c "$1"
}

cmd="${1:-}"
[[ $# -gt 0 ]] && shift

case "$cmd" in
    image)
        build_image
        ;;
    test)
        run_in_container "
            cargo xtask build-ebpf --profile release &&
            cargo test -p tls-probe-common -p tls-probe-parser -p tls-probe &&
            cargo clippy -p tls-probe-common -p tls-probe-parser -p tls-probe -- -D warnings &&
            cargo fmt --all -- --check
        "
        ;;
    smoke)
        # --workdir is deliberately NOT under target-linux (the persistent
        # cache volume): smoke_test.py mints short-lived (1-day) test certs
        # and only regenerates them if the file is missing, so a workdir
        # that outlives a single run can serve stale, expired certs days
        # later (SSLCertVerificationError). /tmp is container-local and
        # wiped by --rm on every invocation.
        run_in_container "
            cargo xtask build-ebpf --profile release &&
            cargo build --release -p tls-probe &&
            python3 scripts/smoke_test.py \
                --probe target-linux/release/tls-probe \
                --ebpf target-linux/bpfel-unknown-none/release/tls-probe-ebpf \
                --schema specs/capture-event.schema.json \
                --workdir /tmp/tls-probe-smoke-run
        "
        ;;
    bench)
        [[ "${1:-}" == "--" ]] && shift
        bench_args=""
        [[ $# -gt 0 ]] && printf -v bench_args '%q ' "$@"
        run_in_container "
            cargo xtask build-ebpf --profile release &&
            cargo build --release -p tls-probe &&
            bash contrib/bench/run_bench.sh \
                --probe target-linux/release/tls-probe \
                --ebpf  target-linux/bpfel-unknown-none/release/tls-probe-ebpf \
                $bench_args
        "
        ;;
    shell)
        ensure_volumes
        ensure_image
        "${PODMAN[@]}" run --rm -it --privileged \
            -v "$repo_root":/work \
            -v "$TARGET_VOLUME":/work/target-linux \
            -v "$CARGO_VOLUME":/usr/local/cargo/registry \
            -e CARGO_TARGET_DIR=/work/target-linux \
            -w /work \
            "$IMAGE" bash
        ;;
    *)
        echo "usage: $0 {image|test|smoke|bench|shell}" >&2
        exit 2
        ;;
esac
