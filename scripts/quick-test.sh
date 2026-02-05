#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_FILE="/tmp/tls-probe-quick.json"

log() { echo "[test] $1"; }

find_binary() {
    local name=$1
    if [ -f "$SCRIPT_DIR/../../target/release/$name" ]; then
        echo "$SCRIPT_DIR/../../target/release/$name"
    elif [ -f "$SCRIPT_DIR/../../target/bpfel-unknown-none/release/$name" ]; then
        echo "$SCRIPT_DIR/../../target/bpfel-unknown-none/release/$name"
    elif [ -f "$SCRIPT_DIR/../../target/debug/$name" ]; then
        echo "$SCRIPT_DIR/../../target/debug/$name"
    elif [ -f "/app/$name" ]; then
        echo "/app/$name"
    else
        echo ""
    fi
}

INTERFACE="${1:-}"
if [ -z "$INTERFACE" ]; then
    INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    if [ -z "$INTERFACE" ]; then
        echo "Usage: $0 <interface>"
        echo "Could not auto-detect interface"
        exit 1
    fi
    log "Auto-detected interface: $INTERFACE"
fi

TLS_PROBE=$(find_binary "tls-probe")
EBPF_PATH=$(find_binary "tls-probe-ebpf")

[ -z "$TLS_PROBE" ] && { echo "tls-probe not found, run 'make release' first"; exit 1; }
[ -z "$EBPF_PATH" ] && { echo "tls-probe-ebpf not found, run 'make release' first"; exit 1; }

[ "$(id -u)" -ne 0 ] && { echo "Must run as root"; exit 1; }

rm -f "$OUTPUT_FILE"

log "Starting 5-second capture on $INTERFACE..."
$TLS_PROBE capture --ebpf "$EBPF_PATH" --interface "$INTERFACE" --output "$OUTPUT_FILE" --analyze --duration 5 &
PROBE_PID=$!
sleep 2

log "Making HTTPS connections..."
curl -s https://www.google.com > /dev/null 2>&1 &
curl -s https://www.github.com > /dev/null 2>&1 &
curl -s https://www.cloudflare.com > /dev/null 2>&1 &

wait $PROBE_PID 2>/dev/null || true

if [ ! -f "$OUTPUT_FILE" ]; then
    echo "[FAIL] No output file"
    exit 1
fi

log "Captured events:"
python3 << 'EOF'
import json
import sys

try:
    with open("/tmp/tls-probe-quick.json") as f:
        data = json.load(f)
except:
    print("No valid JSON output")
    sys.exit(1)

if not data:
    print("No events captured")
    sys.exit(1)

for event in data[:5]:
    ht = event.get("handshake_type", "?")
    ver = event.get("tls_version", "?")
    sni = event.get("sni", "")
    groups = event.get("key_exchange_groups", [])
    print(f"  {ht}: TLS {ver}, SNI={sni or '(none)'}, groups={groups[:3] if groups else '[]'}")

print(f"\nTotal: {len(data)} events")
EOF
