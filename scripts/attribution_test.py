#!/usr/bin/env python3
"""Local attribution test — validates that the probe populates process_name
and pid on captured ClientHello events.

Runs the probe in capture mode, makes two HTTPS requests with curl, then
checks that at least one ClientHello carries a non-null process_name and pid.

Requires root (CAP_BPF/CAP_NET_ADMIN) and Linux 5.8+.  Designed to run
inside the dev container via ``contrib/dev/run.sh attribution``.

    sudo python3 scripts/attribution_test.py \\
        --probe ./tls-probe --ebpf ./tls-probe-ebpf
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

READY_MARKER = "Probes attached:"
PROBE_TIMEOUT = 30  # seconds to wait for probe readiness
CAPTURE_DURATION = 15


def wait_for_ready(log_path: Path, timeout: int, proc: subprocess.Popen) -> bool:
    """Poll the probe log until the readiness marker appears."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            print(f"ERROR: probe exited early (rc={proc.returncode})", file=sys.stderr)
            print(log_path.read_text(), file=sys.stderr)
            return False
        if log_path.exists() and READY_MARKER in log_path.read_text():
            return True
        time.sleep(0.5)
    print("ERROR: probe did not attach in time", file=sys.stderr)
    if log_path.exists():
        print(log_path.read_text(), file=sys.stderr)
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", required=True, help="Path to tls-probe binary")
    parser.add_argument("--ebpf", required=True, help="Path to tls-probe-ebpf object")
    args = parser.parse_args()

    probe = Path(args.probe).resolve()
    ebpf = Path(args.ebpf).resolve()

    if os.geteuid() != 0:
        print("ERROR: must run as root", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory(prefix="attribution-") as workdir:
        wd = Path(workdir)
        events_path = wd / "events.jsonl"
        log_path = wd / "probe.log"

        # Start the probe
        with open(log_path, "w") as log_fh:
            probe_proc = subprocess.Popen(
                [
                    str(probe),
                    "--log-level",
                    "info",
                    "capture",
                    "--interface",
                    "all",
                    "--ebpf",
                    str(ebpf),
                    "--output",
                    str(events_path),
                    "--duration",
                    str(CAPTURE_DURATION),
                ],
                stdout=log_fh,
                stderr=subprocess.STDOUT,
            )

        try:
            if not wait_for_ready(log_path, PROBE_TIMEOUT, probe_proc):
                return 1

            print("Probe attached, making test requests...")
            # Two curl requests to public hosts
            for url in ["https://example.com", "https://example.com"]:
                subprocess.run(
                    ["curl", "-so", "/dev/null", "--max-time", "5", url],
                    timeout=10,
                    check=False,
                )
                time.sleep(0.5)

            print("Waiting for probe to finish...")
            probe_proc.wait(timeout=CAPTURE_DURATION + 10)
        except Exception:
            probe_proc.kill()
            probe_proc.wait()
            raise

        # Read and analyze events
        if not events_path.exists() or events_path.stat().st_size == 0:
            print("ERROR: no events captured", file=sys.stderr)
            print("--- probe log ---", file=sys.stderr)
            print(log_path.read_text(), file=sys.stderr)
            return 1

        lines = [line for line in events_path.read_text().splitlines() if line.strip()]
        events = [json.loads(line) for line in lines]

        client_hellos = [e for e in events if e.get("handshake_type") == "ClientHello"]
        attributed = [
            e
            for e in client_hellos
            if e.get("process_name") is not None and e.get("pid") is not None
        ]

        print("\nResults:")
        print(f"  Total events:            {len(events)}")
        print(f"  ClientHello events:      {len(client_hellos)}")
        print(f"  Attributed (pid != null): {len(attributed)}")

        if not client_hellos:
            print("\nERROR: no ClientHello events captured at all", file=sys.stderr)
            print("--- first 10 events ---")
            for line in lines[:10]:
                print(f"  {line}")
            return 1

        if not attributed:
            print("\nFAIL: no ClientHello event carried process attribution")
            print("--- ClientHello events (first 5) ---")
            for e in client_hellos[:5]:
                print(
                    f"  sni={e.get('sni')}  pid={e.get('pid')}  "
                    f"process_name={e.get('process_name')}  "
                    f"cgroup_id={e.get('cgroup_id')}"
                )
            print("\n--- probe log ---")
            print(log_path.read_text())
            return 1

        print("\nPASS: attribution working")
        for e in attributed[:3]:
            print(
                f"  sni={e.get('sni')}  pid={e.get('pid')}  "
                f"process_name={e.get('process_name')}  "
                f"cgroup_id={e.get('cgroup_id')}"
            )

        return 0


if __name__ == "__main__":
    sys.exit(main())
