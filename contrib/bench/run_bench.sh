#!/usr/bin/env bash
# tls-probe stress check: does the probe lose data or crash under load.
#
# Two load phases, both on loopback, probe attached throughout:
#   1. Throughput  — iperf3 client/server (non-TLS; classifier should
#      inspect and ignore it without emitting anything).
#   2. Handshake storm — openssl s_server + python TLS client loop.
#
# The pass/fail gate is the probe's own counters (kernel_lost, dropped,
# chunks_evicted, correlator_sh_without_ch, emitted vs. JSONL lines written,
# clean exit) — exact integers, not timing. A detached baseline is also
# measured for Gbit/s and handshakes/s context, but on a shared/unpinned
# host those numbers and their delta vs. attached swing wildly run to run
# (observed: -16% to +109% for the same code) and are NOT part of the gate.
# Don't add a delta% threshold here without pinning CPU frequency, isolating
# cores, and running far more samples than 3.
#
# Requires root (eBPF attach), iperf3, openssl, python3.
# Emits a markdown-ready summary on stdout. Exit code reflects the stress
# checks only, not the throughput/handshake-rate deltas.
#
# Usage:
#   run_bench.sh --probe /path/to/tls-probe --ebpf /path/to/tls-probe-ebpf \
#                [--iperf-secs 5] [--iperf-runs 3] \
#                [--handshakes 1000] [--storm-runs 3] [--port 14433]

set -euo pipefail

PROBE=""
EBPF=""
IPERF_SECS=5
IPERF_RUNS=3
HANDSHAKES=1000
STORM_RUNS=3
TLS_PORT=14433
IPERF_PORT=15201

while [[ $# -gt 0 ]]; do
    case "$1" in
        --probe)      PROBE="$2"; shift 2 ;;
        --ebpf)       EBPF="$2"; shift 2 ;;
        --iperf-secs) IPERF_SECS="$2"; shift 2 ;;
        --iperf-runs) IPERF_RUNS="$2"; shift 2 ;;
        --handshakes) HANDSHAKES="$2"; shift 2 ;;
        --storm-runs) STORM_RUNS="$2"; shift 2 ;;
        --port)       TLS_PORT="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

[[ -x "$PROBE" ]] || { echo "error: --probe not executable: $PROBE" >&2; exit 2; }
[[ -f "$EBPF" ]]  || { echo "error: --ebpf not found: $EBPF" >&2; exit 2; }
command -v openssl >/dev/null || { echo "error: openssl not found" >&2; exit 2; }
command -v python3 >/dev/null || { echo "error: python3 not found" >&2; exit 2; }
HAVE_IPERF=1
command -v iperf3 >/dev/null || { HAVE_IPERF=0; echo "warn: iperf3 not found, skipping throughput bench" >&2; }

WORK="$(mktemp -d /tmp/tlsprobe-bench.XXXXXX)"
PROBE_PID=""
IPERF_SRV_PID=""
SSRV_PID=""

cleanup() {
    [[ -n "$PROBE_PID" ]] && kill -INT "$PROBE_PID" 2>/dev/null || true
    [[ -n "$IPERF_SRV_PID" ]] && kill "$IPERF_SRV_PID" 2>/dev/null || true
    [[ -n "$SSRV_PID" ]] && kill "$SSRV_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

# --- helpers -----------------------------------------------------------------

start_probe() { # $1 = log file, $2 = events file
    "$PROBE" capture --interface lo --ebpf "$EBPF" --output "$2" >"$1" 2>&1 &
    PROBE_PID=$!
    for _ in $(seq 1 50); do
        grep -q "Attached" "$1" 2>/dev/null && return 0
        kill -0 "$PROBE_PID" 2>/dev/null || { cat "$1" >&2; echo "error: probe exited during attach" >&2; exit 1; }
        sleep 0.2
    done
    cat "$1" >&2; echo "error: probe did not attach within 10s" >&2; exit 1
}

stop_probe() { # sets PROBE_EXIT to the probe's exit code
    kill -INT "$PROBE_PID" 2>/dev/null || true
    set +e
    wait "$PROBE_PID" 2>/dev/null
    PROBE_EXIT=$?
    set -e
    PROBE_PID=""
}

median() {
    printf '%s\n' "$@" | sort -n | awk '{a[NR]=$1} END{printf "%s", a[int((NR+1)/2)]}'
}

# --- stress checks -------------------------------------------------------------
# Exact-integer assertions on the probe's own counters. These are the actual
# gate; everything under "Bench summary" below is informational context.

FAILURES=()

counter_value() { # $1 = counters string, $2 = field name
    grep -oP "\b$2=\K[0-9]+" <<<"$1" | head -1
}

check_eq() { # $1 = label, $2 = actual, $3 = expected
    if [[ "$2" == "$3" ]]; then
        echo "  [PASS] $1: $2"
    else
        echo "  [FAIL] $1: got $2, expected $3"
        FAILURES+=("$1: got $2, expected $3")
    fi
}

wait_port() { # $1 = port
    python3 - "$1" <<'PY'
import socket, sys, time
port = int(sys.argv[1])
for _ in range(50):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=1).close()
        sys.exit(0)
    except OSError:
        time.sleep(0.2)
sys.exit(1)
PY
}

iperf_gbps() { # runs one iperf3 client, prints "gbps retransmits"
    iperf3 -c 127.0.0.1 -p "$IPERF_PORT" -t "$IPERF_SECS" -J >"$WORK/iperf.json"
    python3 - "$WORK/iperf.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
bps = d["end"]["sum_received"]["bits_per_second"]
retr = d["end"]["sum_sent"].get("retransmits", 0)
print(f"{bps/1e9:.2f} {retr}")
PY
}

storm_hps() { # runs one handshake storm, prints "ok elapsed_s hps"
    python3 - "$HANDSHAKES" "$TLS_PORT" <<'PY'
import socket, ssl, sys, time
n, port = int(sys.argv[1]), int(sys.argv[2])
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ok = 0
t0 = time.monotonic()
for i in range(n):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
            with ctx.wrap_socket(s, server_hostname="bench.local"):
                ok += 1
    except Exception as e:
        print(f"handshake {i} failed: {e}", file=sys.stderr)
dt = time.monotonic() - t0
print(f"{ok} {dt:.2f} {ok/dt:.0f}")
PY
}

# --- bench 1: iperf3 throughput ----------------------------------------------

IPERF_BASE="" IPERF_BASE_ALL="" IPERF_ATT="" IPERF_ATT_ALL=""
if [[ "$HAVE_IPERF" == 1 ]]; then
    echo "== bench 1: iperf3 loopback throughput (${IPERF_RUNS}x ${IPERF_SECS}s, median) ==" >&2
    iperf3 -s -p "$IPERF_PORT" >/dev/null 2>&1 &
    IPERF_SRV_PID=$!
    wait_port "$IPERF_PORT" || { echo "error: iperf3 server not up" >&2; exit 1; }

    vals=()
    for i in $(seq 1 "$IPERF_RUNS"); do
        read -r gbps retr <<<"$(iperf_gbps)"
        echo "  detached run $i: ${gbps} Gbit/s (retransmits ${retr})" >&2
        vals+=("$gbps")
    done
    IPERF_BASE="$(median "${vals[@]}")"
    IPERF_BASE_ALL="${vals[*]}"

    start_probe "$WORK/probe-iperf.log" "$WORK/events-iperf.jsonl"
    vals=()
    for i in $(seq 1 "$IPERF_RUNS"); do
        read -r gbps retr <<<"$(iperf_gbps)"
        echo "  attached run $i: ${gbps} Gbit/s (retransmits ${retr})" >&2
        vals+=("$gbps")
    done
    stop_probe
    IPERF_ATT="$(median "${vals[@]}")"
    IPERF_ATT_ALL="${vals[*]}"
    IPERF_COUNTERS="$(grep 'counters:' "$WORK/probe-iperf.log" | tail -1 | sed 's/^.*counters:/counters:/')"

    echo "-- stress checks: iperf phase (non-TLS traffic, probe should ignore it entirely) --" >&2
    check_eq "iperf probe exit code" "$PROBE_EXIT" "0" >&2
    check_eq "iperf emitted" "$(counter_value "$IPERF_COUNTERS" emitted)" "0" >&2
    check_eq "iperf dropped" "$(counter_value "$IPERF_COUNTERS" dropped)" "0" >&2
    check_eq "iperf kernel_lost" "$(counter_value "$IPERF_COUNTERS" kernel_lost)" "0" >&2

    kill "$IPERF_SRV_PID" 2>/dev/null || true
    wait "$IPERF_SRV_PID" 2>/dev/null || true
    IPERF_SRV_PID=""
fi

# --- bench 2: TLS handshake storm ----------------------------------------------

echo "== bench 2: TLS handshake storm (${STORM_RUNS}x ${HANDSHAKES} handshakes, median) ==" >&2

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$WORK/key.pem" -out "$WORK/cert.pem" -days 1 \
    -subj "/CN=bench.local" >/dev/null 2>&1
openssl s_server -accept "$TLS_PORT" -key "$WORK/key.pem" -cert "$WORK/cert.pem" \
    -www -quiet >/dev/null 2>&1 &
SSRV_PID=$!
wait_port "$TLS_PORT" || { echo "error: openssl s_server not up" >&2; exit 1; }

vals=()
for i in $(seq 1 "$STORM_RUNS"); do
    read -r ok dt hps <<<"$(storm_hps)"
    echo "  detached run $i: ${ok}/${HANDSHAKES} handshakes in ${dt}s (${hps}/s)" >&2
    vals+=("$hps")
done
STORM_BASE="$(median "${vals[@]}")"
STORM_BASE_ALL="${vals[*]}"

start_probe "$WORK/probe-storm.log" "$WORK/events-storm.jsonl"
vals=()
for i in $(seq 1 "$STORM_RUNS"); do
    read -r ok dt hps <<<"$(storm_hps)"
    echo "  attached run $i: ${ok}/${HANDSHAKES} handshakes in ${dt}s (${hps}/s)" >&2
    vals+=("$hps")
done
stop_probe
STORM_ATT="$(median "${vals[@]}")"
STORM_ATT_ALL="${vals[*]}"
STORM_COUNTERS="$(grep 'counters:' "$WORK/probe-storm.log" | tail -1 | sed 's/^.*counters:/counters:/')"
STORM_EVENTS="$(wc -l <"$WORK/events-storm.jsonl" | tr -d ' ')"

echo "-- stress checks: handshake storm ($((HANDSHAKES * STORM_RUNS)) handshakes attached) --" >&2
check_eq "storm probe exit code" "$PROBE_EXIT" "0" >&2
check_eq "storm dropped" "$(counter_value "$STORM_COUNTERS" dropped)" "0" >&2
check_eq "storm kernel_lost" "$(counter_value "$STORM_COUNTERS" kernel_lost)" "0" >&2
check_eq "storm chunks_evicted" "$(counter_value "$STORM_COUNTERS" chunks_evicted)" "0" >&2
check_eq "storm correlator_sh_without_ch" "$(counter_value "$STORM_COUNTERS" correlator_sh_without_ch)" "0" >&2
check_eq "storm emitted vs JSONL lines" "$(counter_value "$STORM_COUNTERS" emitted)" "$STORM_EVENTS" >&2

kill "$SSRV_PID" 2>/dev/null || true
wait "$SSRV_PID" 2>/dev/null || true
SSRV_PID=""

# --- summary -------------------------------------------------------------------

pct_delta() { # $1 = baseline, $2 = attached
    python3 -c "b, a = float('$1'), float('$2'); print(f'{(a-b)/b*100:+.1f}%')"
}

echo
echo "## Bench summary"
echo
echo "Environment: $(uname -srm), $(nproc) CPUs"
echo
echo "### Stress checks (the actual gate — exact counters, not timing)"
echo
if [[ "$HAVE_IPERF" == 1 ]]; then
    echo "Probe counters after iperf phase (non-TLS traffic): \`${IPERF_COUNTERS}\`"
fi
echo "Probe counters under storm ($((HANDSHAKES * STORM_RUNS)) handshakes attached): \`${STORM_COUNTERS}\`"
echo "Events written (JSONL lines): ${STORM_EVENTS}"
echo
if [[ ${#FAILURES[@]} -eq 0 ]]; then
    echo "**All stress checks passed** — no dropped/lost events, no reassembly evictions, no correlator aging, clean probe exit."
else
    echo "**${#FAILURES[@]} stress check(s) failed:**"
    for f in "${FAILURES[@]}"; do
        echo "- $f"
    done
fi
echo
echo "### Throughput/rate context (informational only — NOT the gate, NOT stable run to run)"
echo
echo "Shared/unpinned host: absolute numbers and their attached-vs-detached delta"
echo "vary run to run from environment noise (CPU frequency scaling, other VM"
echo "tenants), not code changes. Treat as rough context, not a regression signal."
echo
if [[ "$HAVE_IPERF" == 1 ]]; then
    echo "#### Throughput (iperf3, loopback, TCP, ${IPERF_SECS}s x ${IPERF_RUNS} runs, median)"
    echo
    echo "| Mode | Gbit/s (median) | Runs |"
    echo "|------|-----------------|------|"
    echo "| Detached | ${IPERF_BASE} | ${IPERF_BASE_ALL} |"
    echo "| Attached | ${IPERF_ATT} | ${IPERF_ATT_ALL} |"
    echo "| Delta | $(pct_delta "$IPERF_BASE" "$IPERF_ATT") | |"
    echo
fi
echo "#### Handshake storm (TLS 1.3, ${HANDSHAKES} sequential handshakes x ${STORM_RUNS} runs, median)"
echo
echo "| Mode | Handshakes/s (median) | Runs |"
echo "|------|-----------------------|------|"
echo "| Detached | ${STORM_BASE} | ${STORM_BASE_ALL} |"
echo "| Attached | ${STORM_ATT} | ${STORM_ATT_ALL} |"
echo "| Delta | $(pct_delta "$STORM_BASE" "$STORM_ATT") | |"

if [[ ${#FAILURES[@]} -gt 0 ]]; then
    exit 1
fi
