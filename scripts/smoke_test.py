#!/usr/bin/env python3
"""Runtime smoke test for the tls-probe eBPF capture pipeline.

Boots the real probe, drives real TLS traffic past it, and asserts that the
emitted JSONL matches the committed schema *and* contains correctly parsed
handshake data.

Two scenarios:

  loopback  Hermetic. A local TLS server and client on 127.0.0.1 with a pinned
            SNI, captured on `lo`. Fully deterministic, so every check is a
            hard gate. This is what proves the eBPF header offsets, the
            variable-length ringbuf payload copy, the TLS parser and the
            address/port extraction all actually work at runtime.

  egress    Real TLS connections to public hosts captured on the default-route
            interface, proving the probe works on a real NIC. Reported as
            skipped (not failed) when the network is unreachable, and the
            checks that real-world peers make non-deterministic (GREASE, GSO,
            record coalescing) are downgraded to warnings.

Requires root (CAP_BPF/CAP_NET_ADMIN/CAP_PERFMON) and Linux 5.8+ (BPF ringbuf).

    sudo python3 scripts/smoke_test.py --probe ./tls-probe --ebpf ./tls-probe-ebpf
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import json
import os
import platform
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional, Sequence

# --- Tunables -----------------------------------------------------------------

#: Logged by the loader once TC programs are attached to every interface.
READY_MARKER = "Probes attached:"
READY_TIMEOUT_S = 45.0

#: Emitted every COUNTER_LOG_INTERVAL and once more at shutdown.
COUNTER_RE = re.compile(
    r"counters: emitted=(\d+) dropped=(\d+) kernel_lost=(\d+) chunks_evicted=(\d+)"
)
#: tracing formats levels as bare uppercase words; `--log-level info` hides DEBUG/TRACE.
PROBE_ERROR_RE = re.compile(r"\bERROR\b|panicked at")

#: Backstop only. Scenarios stop the probe with SIGTERM as soon as traffic is done.
PROBE_MAX_DURATION_S = 90
#: Let the ringbuf drain and the writer thread catch up before signalling.
DRAIN_SETTLE_S = 2.0
SHUTDOWN_TIMEOUT_S = 20.0

#: BPF ringbuf (used by the TLS_EVENTS map) landed in 5.8.
MIN_KERNEL = (5, 8)

SMOKE_SNI = "smoke.tls-probe.test"
EGRESS_HOSTS = ("example.com", "www.google.com", "github.com")
EGRESS_CONNECT_TIMEOUT_S = 8.0

KNOWN_TLS_VERSIONS = frozenset({"TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0", "SSL 3.0"})

IN_GITHUB_ACTIONS = os.environ.get("GITHUB_ACTIONS") == "true"


# --- Result model -------------------------------------------------------------


class Severity:
    ERROR = "error"
    WARN = "warning"


@dataclass(frozen=True)
class CheckResult:
    name: str
    passed: bool
    severity: str
    detail: str

    @property
    def fatal(self) -> bool:
        return not self.passed and self.severity == Severity.ERROR


@dataclass(frozen=True)
class Check:
    """A single named assertion over one scenario's observation."""

    name: str
    severity: str
    predicate: Callable[["Observation"], "tuple[bool, str]"]

    def run(self, observation: "Observation") -> CheckResult:
        try:
            passed, detail = self.predicate(observation)
        except Exception as exc:  # a check must never mask itself as a pass
            return CheckResult(self.name, False, self.severity, f"check raised: {exc!r}")
        return CheckResult(self.name, passed, self.severity, detail)


@dataclass(frozen=True)
class TrafficReport:
    """What the traffic generator actually managed to do."""

    attempted: int
    succeeded: int
    expected_snis: "tuple[str, ...]" = ()
    expected_endpoints: "tuple[str, ...]" = ()
    notes: "tuple[str, ...]" = ()


@dataclass(frozen=True)
class Counters:
    emitted: int = 0
    dropped: int = 0
    kernel_lost: int = 0
    chunks_evicted: int = 0
    found: bool = False


@dataclass
class Observation:
    """Everything a scenario's checks are allowed to look at."""

    events: "list[dict]"
    traffic: TrafficReport
    counters: Counters
    schema_errors: "list[str]"
    probe_log: str
    probe_exit_code: "Optional[int]" = None

    def by_type(self, handshake_type: str) -> "list[dict]":
        return [e for e in self.events if e.get("handshake_type") == handshake_type]

    @property
    def client_hellos(self) -> "list[dict]":
        return self.by_type("ClientHello")

    @property
    def server_hellos(self) -> "list[dict]":
        return self.by_type("ServerHello")

    @property
    def snis(self) -> "set[str]":
        return {e["sni"] for e in self.events if e.get("sni")}

    @property
    def endpoints(self) -> "set[str]":
        out = set()
        for event in self.events:
            for key in ("src", "dst"):
                if event.get(key):
                    out.add(event[key])
        return out


@dataclass
class ScenarioResult:
    name: str
    status: str  # "passed" | "failed" | "skipped"
    reason: str = ""
    checks: "list[CheckResult]" = field(default_factory=list)
    event_count: int = 0


@dataclass(frozen=True)
class Scenario:
    name: str
    description: str
    interface: str
    traffic: Callable[[Path], TrafficReport]
    checks: "tuple[Check, ...]"
    #: When False a scenario failure is reported but does not fail the run.
    required: bool = True


class SkipScenario(Exception):
    """Raised by a traffic generator when the scenario cannot run here."""


class SmokeFailure(Exception):
    """Fatal setup problem — distinct from an assertion failing."""


# --- Output -------------------------------------------------------------------


def log(message: str = "") -> None:
    print(message, flush=True)


@contextlib.contextmanager
def group(title: str):
    log(f"::group::{title}" if IN_GITHUB_ACTIONS else f"\n=== {title} ===")
    try:
        yield
    finally:
        if IN_GITHUB_ACTIONS:
            log("::endgroup::")


def annotate(severity: str, message: str) -> None:
    if IN_GITHUB_ACTIONS:
        log(f"::{severity}::{message}")
    else:
        log(f"[{severity.upper()}] {message}")


def write_step_summary(results: Sequence[ScenarioResult]) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    icon = {"passed": "✅", "failed": "❌", "skipped": "⏭️"}
    lines = ["## tls-probe smoke test", ""]
    for result in results:
        heading = f"### {icon.get(result.status, '')} `{result.name}` — {result.status}"
        lines += [heading + (f" ({result.reason})" if result.reason else ""), ""]
        if result.checks:
            lines += [f"{result.event_count} events captured.", "", "| | Check | Detail |", "|---|---|---|"]
            for check in result.checks:
                mark = "✅" if check.passed else ("❌" if check.severity == Severity.ERROR else "⚠️")
                detail = check.detail.replace("|", "\\|")
                lines.append(f"| {mark} | `{check.name}` | {detail} |")
            lines.append("")
    with open(path, "a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


# --- Schema validation --------------------------------------------------------


def load_schema(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SmokeFailure(f"cannot read schema {path}: {exc}") from exc


def _resolve(schema: dict, root: dict) -> dict:
    ref = schema.get("$ref")
    if not ref:
        return schema
    if not ref.startswith("#/"):
        raise SmokeFailure(f"unsupported $ref: {ref}")
    node = root
    for part in ref[2:].split("/"):
        node = node[part]
    return node


_JSON_TYPES = {"object": dict, "array": list, "string": str, "null": type(None)}


def _type_ok(instance: object, expected: str) -> bool:
    if expected == "integer":
        return isinstance(instance, int) and not isinstance(instance, bool)
    if expected == "number":
        return isinstance(instance, (int, float)) and not isinstance(instance, bool)
    if expected == "boolean":
        return isinstance(instance, bool)
    python_type = _JSON_TYPES.get(expected)
    if python_type is None:
        return True
    return isinstance(instance, python_type) and not isinstance(instance, bool)


def _validate(instance, schema: dict, root: dict, path: str, errors: "list[str]") -> None:
    """Minimal draft-07 subset covering the committed capture-event schema.

    Only used when the `jsonschema` package is unavailable, so the smoke test
    still runs on a bare node with no pip.
    """
    schema = _resolve(schema, root)

    if "anyOf" in schema:
        for option in schema["anyOf"]:
            branch: "list[str]" = []
            _validate(instance, option, root, path, branch)
            if not branch:
                return
        errors.append(f"{path or '<root>'}: matched no anyOf branch")
        return

    expected = schema.get("type")
    if expected is not None:
        options = expected if isinstance(expected, list) else [expected]
        if not any(_type_ok(instance, option) for option in options):
            errors.append(
                f"{path or '<root>'}: expected type {options}, got {type(instance).__name__}"
            )
            return

    if isinstance(instance, dict):
        for key in schema.get("required", []):
            if key not in instance:
                errors.append(f"{path or '<root>'}: missing required property '{key}'")
        for key, subschema in schema.get("properties", {}).items():
            if key in instance:
                _validate(instance[key], subschema, root, f"{path}.{key}", errors)

    if isinstance(instance, list) and isinstance(schema.get("items"), dict):
        for index, item in enumerate(instance):
            _validate(item, schema["items"], root, f"{path}[{index}]", errors)

    minimum = schema.get("minimum")
    if minimum is not None and isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if instance < minimum:
            errors.append(f"{path or '<root>'}: {instance} < minimum {minimum}")


def validate_events(events: Iterable[dict], schema: dict) -> "list[str]":
    errors: "list[str]" = []
    try:
        import jsonschema  # type: ignore

        validator = jsonschema.Draft7Validator(schema)
        for index, event in enumerate(events, start=1):
            for error in validator.iter_errors(event):
                location = "/".join(str(p) for p in error.absolute_path) or "<root>"
                errors.append(f"event {index}: {location}: {error.message}")
    except ImportError:
        for index, event in enumerate(events, start=1):
            local: "list[str]" = []
            _validate(event, schema, schema, "", local)
            errors.extend(f"event {index}: {message}" for message in local)
    return errors


# --- Preflight ----------------------------------------------------------------


def kernel_version() -> "tuple[int, int]":
    match = re.match(r"(\d+)\.(\d+)", platform.release())
    return (int(match.group(1)), int(match.group(2))) if match else (0, 0)


def preflight(probe: Path, ebpf: Path, schema: Path) -> None:
    problems: "list[str]" = []

    if sys.platform != "linux":
        problems.append(f"requires Linux, running on {sys.platform}")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        problems.append("must run as root (needs CAP_BPF, CAP_NET_ADMIN, CAP_PERFMON)")

    if kernel_version() < MIN_KERNEL:
        problems.append(
            f"kernel {platform.release()} is older than "
            f"{MIN_KERNEL[0]}.{MIN_KERNEL[1]} (BPF ringbuf required)"
        )

    for label, path in (("probe binary", probe), ("eBPF object", ebpf), ("schema", schema)):
        if not path.is_file():
            problems.append(f"{label} not found: {path}")
    if probe.is_file() and not os.access(probe, os.X_OK):
        problems.append(f"probe binary is not executable: {probe}")

    if shutil.which("openssl") is None:
        problems.append("openssl CLI not found (needed to mint the loopback test cert)")

    if problems:
        raise SmokeFailure("preflight failed:\n  - " + "\n  - ".join(problems))

    log(f"kernel      {platform.release()} ({platform.machine()})")
    log(f"probe       {probe}")
    log(f"ebpf        {ebpf}")
    log(f"schema      {schema}")
    try:
        import jsonschema  # type: ignore # noqa: F401

        log("validator   jsonschema")
    except ImportError:
        log("validator   builtin (install `jsonschema` for full draft-07 coverage)")


# --- Probe process ------------------------------------------------------------


class Probe:
    """Runs `tls-probe capture` and stops it deterministically with SIGTERM."""

    def __init__(self, binary: Path, ebpf: Path, interface: str, workdir: Path, name: str):
        self.binary = binary
        self.ebpf = ebpf
        self.interface = interface
        self.output = workdir / f"{name}.jsonl"
        self.log_path = workdir / f"{name}.probe.log"
        self._process: "Optional[subprocess.Popen]" = None
        self._log_handle = None
        #: Set once the process has been reaped; None while it is still running.
        self.exit_code: "Optional[int]" = None

    @property
    def argv(self) -> "list[str]":
        return [
            str(self.binary),
            "--log-level", "info",
            "capture",
            "--interface", self.interface,
            "--ebpf", str(self.ebpf),
            "--output", str(self.output),
            # Backstop only; stop() drives the actual shutdown via SIGTERM.
            "--duration", str(PROBE_MAX_DURATION_S),
        ]

    def read_log(self) -> str:
        try:
            return self.log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def start(self) -> None:
        with contextlib.suppress(FileNotFoundError):
            self.output.unlink()
        self._log_handle = open(self.log_path, "w", encoding="utf-8")
        log(f"$ {' '.join(self.argv)}")
        # New session so a wedged probe can be killed as a process group.
        self._process = subprocess.Popen(
            self.argv,
            stdout=self._log_handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

    def wait_ready(self) -> None:
        """Block until the loader reports every TC program attached."""
        assert self._process is not None
        deadline = time.monotonic() + READY_TIMEOUT_S
        while time.monotonic() < deadline:
            if READY_MARKER in self.read_log():
                log(f"probe ready on '{self.interface}'")
                return
            exit_code = self._process.poll()
            if exit_code is not None:
                raise SmokeFailure(
                    f"probe exited with code {exit_code} before attaching:\n{self.read_log()}"
                )
            time.sleep(0.1)
        raise SmokeFailure(f"probe did not attach within {READY_TIMEOUT_S:.0f}s:\n{self.read_log()}")

    def stop(self) -> None:
        """SIGTERM for a graceful flush, SIGKILL the group if it will not go."""
        process = self._process
        if process is None:
            return
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=SHUTDOWN_TIMEOUT_S)
            except subprocess.TimeoutExpired:
                annotate(Severity.WARN, "probe ignored SIGTERM; killing process group")
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                with contextlib.suppress(subprocess.TimeoutExpired):
                    process.wait(timeout=5)
        self.exit_code = process.poll()

    def __enter__(self) -> "Probe":
        self.start()
        try:
            self.wait_ready()
        except Exception:
            self.stop()
            self._close_log()
            raise
        return self

    def __exit__(self, *_exc) -> None:
        self.stop()
        self._close_log()

    def _close_log(self) -> None:
        if self._log_handle is not None:
            self._log_handle.close()
            self._log_handle = None

    def read_events(self) -> "list[dict]":
        if not self.output.exists():
            return []
        events: "list[dict]" = []
        with open(self.output, encoding="utf-8") as handle:
            for number, line in enumerate(handle, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise SmokeFailure(f"{self.output}:{number}: malformed JSONL: {exc}") from exc
        return events

    def read_counters(self) -> Counters:
        matches = COUNTER_RE.findall(self.read_log())
        if not matches:
            return Counters()
        emitted, dropped, kernel_lost, evicted = matches[-1]
        return Counters(int(emitted), int(dropped), int(kernel_lost), int(evicted), found=True)


# --- Traffic generators -------------------------------------------------------


def mint_certificate(workdir: Path) -> "tuple[Path, Path]":
    cert, key = workdir / "smoke-cert.pem", workdir / "smoke-key.pem"
    if cert.exists() and key.exists():
        return cert, key
    result = subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256",
            "-days", "1", "-nodes",
            "-keyout", str(key), "-out", str(cert),
            "-subj", f"/CN={SMOKE_SNI}",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise SmokeFailure(f"openssl failed to mint the test certificate: {result.stderr.strip()}")
    return cert, key


class LocalTlsServer:
    """TLS acceptor on 127.0.0.1, used as the hermetic capture target."""

    def __init__(self, cert: Path, key: Path):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=str(cert), keyfile=str(key))
        self._context = context
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind(("127.0.0.1", 0))
        self._socket.listen(8)
        self._socket.settimeout(0.5)
        self.port = self._socket.getsockname()[1]
        self.errors: "list[str]" = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    @property
    def endpoint(self) -> str:
        return f"127.0.0.1:{self.port}"

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                raw, _ = self._socket.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            # Never swallow a fixture failure: a client-visible "connection
            # reset" here would otherwise masquerade as a probe bug.
            try:
                raw.settimeout(5.0)
                with self._context.wrap_socket(raw, server_side=True) as tls:
                    tls.recv(64)
                    tls.sendall(b"pong")
            except Exception as exc:
                self.errors.append(f"server: {type(exc).__name__}: {exc}")
            finally:
                with contextlib.suppress(OSError):
                    raw.close()

    def __enter__(self) -> "LocalTlsServer":
        self._thread.start()
        return self

    def __exit__(self, *_exc) -> None:
        self._stop.set()
        with contextlib.suppress(OSError):
            self._socket.close()
        self._thread.join(timeout=5)


def loopback_traffic(workdir: Path) -> TrafficReport:
    """Hermetic handshakes against a local server, captured on `lo`."""
    cert, key = mint_certificate(workdir)
    notes: "list[str]" = []
    succeeded = 0
    attempts = 3

    with LocalTlsServer(cert, key) as server:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        # The cert is self-signed and the SNI is synthetic; we only care that a
        # full handshake crosses `lo`, not that it is trustworthy.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        for attempt in range(attempts):
            try:
                with socket.create_connection(("127.0.0.1", server.port), timeout=5) as raw:
                    # server_hostname drives the SNI extension even with verification off.
                    with context.wrap_socket(raw, server_hostname=SMOKE_SNI) as tls:
                        version = tls.version()
                        if version is None:
                            raise SmokeFailure("handshake completed without negotiating a version")
                        tls.sendall(b"ping")
                        tls.recv(16)
                        if attempt == 0:
                            notes.append(f"{server.endpoint} negotiated {version}")
                succeeded += 1
            except (OSError, ssl.SSLError, SmokeFailure) as exc:
                notes.append(f"attempt {attempt + 1} failed: {exc}")
            time.sleep(0.2)

        notes.extend(server.errors)

    if succeeded == 0:
        raise SmokeFailure(
            "local TLS handshake never succeeded, so a probe bug cannot be told "
            "apart from a broken host: " + "; ".join(notes)
        )

    return TrafficReport(
        attempted=attempts,
        succeeded=succeeded,
        expected_snis=(SMOKE_SNI,),
        expected_endpoints=(server.endpoint,),
        notes=tuple(notes),
    )


def egress_traffic(_workdir: Path) -> TrafficReport:
    """Real handshakes to public hosts over the default-route interface."""
    context = ssl.create_default_context()
    notes: "list[str]" = []
    reached: "list[str]" = []

    for host in EGRESS_HOSTS:
        try:
            with socket.create_connection((host, 443), timeout=EGRESS_CONNECT_TIMEOUT_S) as raw:
                with context.wrap_socket(raw, server_hostname=host) as tls:
                    notes.append(f"{host}: {tls.version()}")
            reached.append(host)
        except OSError as exc:
            notes.append(f"{host}: unreachable ({exc})")
        time.sleep(0.2)

    if not reached:
        raise SkipScenario("no public host reachable: " + "; ".join(notes))

    return TrafficReport(
        attempted=len(EGRESS_HOSTS),
        succeeded=len(reached),
        expected_snis=tuple(reached),
        notes=tuple(notes),
    )


# --- Checks -------------------------------------------------------------------


def check_events_present(observation: Observation) -> "tuple[bool, str]":
    count = len(observation.events)
    return count > 0, f"{count} events from {observation.traffic.succeeded} handshakes"


def check_schema(observation: Observation) -> "tuple[bool, str]":
    errors = observation.schema_errors
    if errors:
        extra = len(errors) - 5
        return False, "; ".join(errors[:5]) + (f" (+{extra} more)" if extra > 0 else "")
    return True, f"all {len(observation.events)} events match the committed schema"


def check_client_hello(observation: Observation) -> "tuple[bool, str]":
    count = len(observation.client_hellos)
    return count > 0, f"{count} ClientHello events"


def check_server_hello(observation: Observation) -> "tuple[bool, str]":
    count = len(observation.server_hellos)
    return count > 0, f"{count} ServerHello events (exercises ingress and the src/dst swap)"


def check_expected_sni(observation: Observation) -> "tuple[bool, str]":
    expected = set(observation.traffic.expected_snis)
    if not expected:
        return True, "no SNI expectation for this scenario"
    seen = observation.snis
    return bool(expected & seen), f"expected any of {sorted(expected)}, captured {sorted(seen)}"


def check_expected_endpoint(observation: Observation) -> "tuple[bool, str]":
    expected = set(observation.traffic.expected_endpoints)
    if not expected:
        return True, "no endpoint expectation for this scenario"
    seen = observation.endpoints
    return bool(expected & seen), f"expected any of {sorted(expected)} in src/dst, captured {sorted(seen)}"


def _non_empty(events: Sequence[dict], key: str) -> int:
    return sum(1 for event in events if event.get(key))


def check_cipher_suites_parsed(observation: Observation) -> "tuple[bool, str]":
    hellos = observation.client_hellos
    count = _non_empty(hellos, "cipher_suites")
    return count > 0, (
        f"{count}/{len(hellos)} ClientHellos carry cipher suites; empty means the "
        "parser fell back, i.e. the payload copy or the header offsets are wrong"
    )


def check_key_exchange_parsed(observation: Observation) -> "tuple[bool, str]":
    hellos = observation.client_hellos
    return _non_empty(hellos, "key_exchange_groups") > 0, (
        f"{_non_empty(hellos, 'key_exchange_groups')}/{len(hellos)} ClientHellos carry supported_groups"
    )


def check_signature_algorithms_parsed(observation: Observation) -> "tuple[bool, str]":
    hellos = observation.client_hellos
    return _non_empty(hellos, "signature_algorithms") > 0, (
        f"{_non_empty(hellos, 'signature_algorithms')}/{len(hellos)} ClientHellos carry signature_algorithms"
    )


def check_key_share_parsed(observation: Observation) -> "tuple[bool, str]":
    hellos = observation.client_hellos
    return _non_empty(hellos, "key_share_group") > 0, (
        f"{_non_empty(hellos, 'key_share_group')}/{len(hellos)} ClientHellos carry a key_share group"
    )


def check_tls_versions_known(observation: Observation) -> "tuple[bool, str]":
    unknown = sorted(
        {
            str(event.get("tls_version"))
            for event in observation.events
            if event.get("tls_version") not in KNOWN_TLS_VERSIONS
        }
    )
    return not unknown, f"unrecognised tls_version values: {unknown}" if unknown else "all recognised"


def check_named_ids_resolved(observation: Observation) -> "tuple[bool, str]":
    """Every id we surface should map to a name, otherwise the lookup tables are stale."""
    unknown = set()
    for event in observation.events:
        for key in ("cipher_suites", "key_exchange_groups", "signature_algorithms"):
            for item in event.get(key) or []:
                if item.get("name") == "unknown":
                    unknown.add(f"{key}:0x{item.get('id', 0):04x}")
    return not unknown, f"unmapped ids: {sorted(unknown)}" if unknown else "all ids mapped to names"


def check_process_attribution(observation: Observation) -> "tuple[bool, str]":
    attributed = [event for event in observation.events if event.get("pid")]
    names = sorted({event.get("process_name") or "?" for event in attributed})
    return bool(attributed), (
        f"{len(attributed)}/{len(observation.events)} events attributed {names}; the connect "
        "kprobes read sock_common at hardcoded offsets, so this can silently regress per kernel"
    )


def check_no_drops(observation: Observation) -> "tuple[bool, str]":
    counters = observation.counters
    if not counters.found:
        return False, "probe never logged a counters line"
    return counters.dropped == 0 and counters.kernel_lost == 0, (
        f"emitted={counters.emitted} dropped={counters.dropped} "
        f"kernel_lost={counters.kernel_lost} chunks_evicted={counters.chunks_evicted}"
    )


def check_emitted_matches_output(observation: Observation) -> "tuple[bool, str]":
    counters = observation.counters
    if not counters.found:
        return False, "probe never logged a counters line"
    return counters.emitted == len(observation.events), (
        f"counter emitted={counters.emitted}, JSONL lines={len(observation.events)}"
    )


def check_traffic_complete(observation: Observation) -> "tuple[bool, str]":
    """A flaky fixture would otherwise be indistinguishable from a probe bug."""
    traffic = observation.traffic
    notes = "; ".join(traffic.notes) or "no notes"
    return traffic.succeeded == traffic.attempted, f"{traffic.succeeded}/{traffic.attempted} handshakes: {notes}"


def check_probe_exit(observation: Observation) -> "tuple[bool, str]":
    """A probe that dies mid-capture must not look like 'no traffic seen'."""
    code = observation.probe_exit_code
    if code is None:
        return False, "probe was never reaped"
    if code < 0:
        return False, f"probe was killed by signal {-code} (it did not honour SIGTERM)"
    return code == 0, f"probe exited with code {code}"


def check_no_probe_errors(observation: Observation) -> "tuple[bool, str]":
    offenders = [line.strip() for line in observation.probe_log.splitlines() if PROBE_ERROR_RE.search(line)]
    return not offenders, f"probe logged errors: {offenders[:3]}" if offenders else "no errors logged"


#: Assertions that must hold wherever the probe runs.
BASE_CHECKS: "tuple[Check, ...]" = (
    Check("events_present", Severity.ERROR, check_events_present),
    Check("schema_conformance", Severity.ERROR, check_schema),
    Check("client_hello_captured", Severity.ERROR, check_client_hello),
    Check("expected_sni_captured", Severity.ERROR, check_expected_sni),
    Check("cipher_suites_parsed", Severity.ERROR, check_cipher_suites_parsed),
    Check("key_exchange_groups_parsed", Severity.ERROR, check_key_exchange_parsed),
    Check("signature_algorithms_parsed", Severity.ERROR, check_signature_algorithms_parsed),
    Check("emitted_matches_output", Severity.ERROR, check_emitted_matches_output),
    Check("probe_exited_cleanly", Severity.ERROR, check_probe_exit),
    Check("no_probe_errors", Severity.ERROR, check_no_probe_errors),
)


SCENARIOS: "tuple[Scenario, ...]" = (
    Scenario(
        name="loopback",
        description="hermetic local TLS server captured on lo",
        interface="lo",
        traffic=loopback_traffic,
        checks=BASE_CHECKS
        + (
            # We own both peers here, so everything is deterministic and hard-gated.
            Check("server_hello_captured", Severity.ERROR, check_server_hello),
            Check("expected_endpoint_captured", Severity.ERROR, check_expected_endpoint),
            Check("key_share_parsed", Severity.ERROR, check_key_share_parsed),
            Check("tls_versions_known", Severity.ERROR, check_tls_versions_known),
            Check("no_event_drops", Severity.ERROR, check_no_drops),
            Check("traffic_fixture_healthy", Severity.WARN, check_traffic_complete),
            Check("named_ids_resolved", Severity.WARN, check_named_ids_resolved),
            Check("process_attribution", Severity.WARN, check_process_attribution),
        ),
    ),
    Scenario(
        name="egress",
        description="public TLS hosts captured on the default-route interface",
        interface="auto",
        traffic=egress_traffic,
        checks=BASE_CHECKS
        + (
            # Real peers bring GREASE, GSO and record coalescing: advisory only.
            Check("server_hello_captured", Severity.WARN, check_server_hello),
            Check("key_share_parsed", Severity.WARN, check_key_share_parsed),
            Check("tls_versions_known", Severity.WARN, check_tls_versions_known),
            Check("no_event_drops", Severity.WARN, check_no_drops),
            Check("named_ids_resolved", Severity.WARN, check_named_ids_resolved),
            Check("process_attribution", Severity.WARN, check_process_attribution),
        ),
    ),
)


# --- Driver -------------------------------------------------------------------


def run_scenario(
    scenario: Scenario, probe_bin: Path, ebpf: Path, schema: dict, workdir: Path
) -> ScenarioResult:
    with group(f"Scenario: {scenario.name} — {scenario.description}"):
        probe = Probe(probe_bin, ebpf, scenario.interface, workdir, scenario.name)
        try:
            with probe:
                traffic = scenario.traffic(workdir)
                for note in traffic.notes:
                    log(f"  traffic: {note}")
                log(f"  {traffic.succeeded}/{traffic.attempted} handshakes completed")
                time.sleep(DRAIN_SETTLE_S)
        except SkipScenario as exc:
            annotate(Severity.WARN, f"scenario '{scenario.name}' skipped: {exc}")
            return ScenarioResult(scenario.name, "skipped", str(exc))
        except SmokeFailure as exc:
            annotate(Severity.ERROR, f"scenario '{scenario.name}' could not run: {exc}")
            return ScenarioResult(scenario.name, "failed", str(exc))

        events = probe.read_events()
        observation = Observation(
            events=events,
            traffic=traffic,
            counters=probe.read_counters(),
            schema_errors=validate_events(events, schema),
            probe_log=probe.read_log(),
            probe_exit_code=probe.exit_code,
        )

        results = [check.run(observation) for check in scenario.checks]
        for result in results:
            mark = "PASS" if result.passed else ("FAIL" if result.severity == Severity.ERROR else "WARN")
            log(f"  [{mark}] {result.name}: {result.detail}")
            if not result.passed:
                annotate(result.severity, f"{scenario.name}/{result.name}: {result.detail}")

        status = "failed" if any(r.fatal for r in results) else "passed"
        return ScenarioResult(scenario.name, status, "", results, len(events))


def parse_args(argv: "Optional[Sequence[str]]" = None) -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--probe", type=Path, required=True, help="path to the tls-probe binary")
    parser.add_argument("--ebpf", type=Path, required=True, help="path to the compiled eBPF object")
    parser.add_argument(
        "--schema",
        type=Path,
        default=repo_root / "specs" / "capture-event.schema.json",
        help="JSON Schema the emitted events must satisfy",
    )
    parser.add_argument(
        "--workdir",
        type=Path,
        default=Path("smoke-run"),
        help="directory for capture output, probe logs and the JSON report",
    )
    parser.add_argument(
        "--scenario",
        action="append",
        choices=[s.name for s in SCENARIOS],
        help="run only the named scenario (repeatable; default: all)",
    )
    return parser.parse_args(argv)


def main(argv: "Optional[Sequence[str]]" = None) -> int:
    args = parse_args(argv)
    probe_bin, ebpf, schema_path = args.probe.resolve(), args.ebpf.resolve(), args.schema.resolve()
    workdir = args.workdir
    workdir.mkdir(parents=True, exist_ok=True)

    with group("Preflight"):
        try:
            preflight(probe_bin, ebpf, schema_path)
            schema = load_schema(schema_path)
        except SmokeFailure as exc:
            annotate(Severity.ERROR, str(exc))
            return 2

    selected = [s for s in SCENARIOS if not args.scenario or s.name in args.scenario]
    results = [run_scenario(s, probe_bin, ebpf, schema, workdir) for s in selected]

    with group("Summary"):
        for result in results:
            warnings = sum(1 for c in result.checks if not c.passed and c.severity == Severity.WARN)
            log(
                f"  {result.name:10s} {result.status:8s} events={result.event_count} "
                f"warnings={warnings}" + (f"  ({result.reason})" if result.reason else "")
            )

    report_path = workdir / "report.json"
    report_path.write_text(
        json.dumps([dataclasses.asdict(r) for r in results], indent=2), encoding="utf-8"
    )
    log(f"\nreport: {report_path}")
    write_step_summary(results)

    required = {s.name for s in selected if s.required}
    failed = [r for r in results if r.status == "failed" and r.name in required]
    if failed:
        annotate(Severity.ERROR, f"smoke test failed: {', '.join(r.name for r in failed)}")
        return 1
    log("\nsmoke test passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
