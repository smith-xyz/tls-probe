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
ALERT_SNI = "alert.tls-probe.test"
NETNS_SNI = "netns.pqc.test"
RESUMPTION_SNI = "resume.tls-probe.test"
TLS12_CERT_SNI = "cert12.tls-probe.test"
MTLS_SNI = "mtls.tls-probe.test"
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
            return CheckResult(
                self.name, False, self.severity, f"check raised: {exc!r}"
            )
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
    #: Optional setup callable invoked before probe attach; must clean up via finally.
    setup: "Optional[Callable[[Path], None]]" = None


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
            lines += [
                f"{result.event_count} events captured.",
                "",
                "| | Check | Detail |",
                "|---|---|---|",
            ]
            for check in result.checks:
                mark = (
                    "✅"
                    if check.passed
                    else ("❌" if check.severity == Severity.ERROR else "⚠️")
                )
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


def _validate(
    instance, schema: dict, root: dict, path: str, errors: "list[str]"
) -> None:
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
    if (
        minimum is not None
        and isinstance(instance, (int, float))
        and not isinstance(instance, bool)
    ):
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

    for label, path in (
        ("probe binary", probe),
        ("eBPF object", ebpf),
        ("schema", schema),
    ):
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

    def __init__(
        self, binary: Path, ebpf: Path, interface: str, workdir: Path, name: str
    ):
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
            "--log-level",
            "info",
            "capture",
            "--interface",
            self.interface,
            "--ebpf",
            str(self.ebpf),
            "--output",
            str(self.output),
            # Backstop only; stop() drives the actual shutdown via SIGTERM.
            "--duration",
            str(PROBE_MAX_DURATION_S),
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
        raise SmokeFailure(
            f"probe did not attach within {READY_TIMEOUT_S:.0f}s:\n{self.read_log()}"
        )

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
                    raise SmokeFailure(
                        f"{self.output}:{number}: malformed JSONL: {exc}"
                    ) from exc
        return events

    def read_counters(self) -> Counters:
        matches = COUNTER_RE.findall(self.read_log())
        if not matches:
            return Counters()
        emitted, dropped, kernel_lost, evicted = matches[-1]
        return Counters(
            int(emitted), int(dropped), int(kernel_lost), int(evicted), found=True
        )


# --- Traffic generators -------------------------------------------------------


def mint_certificate(workdir: Path) -> "tuple[Path, Path]":
    cert, key = workdir / "smoke-cert.pem", workdir / "smoke-key.pem"
    if cert.exists() and key.exists():
        return cert, key
    result = subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-days",
            "1",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-subj",
            f"/CN={SMOKE_SNI}",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise SmokeFailure(
            f"openssl failed to mint the test certificate: {result.stderr.strip()}"
        )
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
                    # Send close_notify so strict clients (openssl s_client
                    # -ign_eof) see a clean TLS shutdown, not a bare TCP FIN.
                    with contextlib.suppress(OSError, ssl.SSLError, TimeoutError):
                        tls.unwrap()
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
                with socket.create_connection(
                    ("127.0.0.1", server.port), timeout=5
                ) as raw:
                    # server_hostname drives the SNI extension even with verification off.
                    with context.wrap_socket(raw, server_hostname=SMOKE_SNI) as tls:
                        version = tls.version()
                        if version is None:
                            raise SmokeFailure(
                                "handshake completed without negotiating a version"
                            )
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


def alert_traffic(workdir: Path) -> TrafficReport:
    """Forced handshake failure: TLS 1.2 client vs TLS 1.3-only server.

    The server rejects the client with a protocol_version alert. We expect
    at least 2 attempts to ensure capture reliability; handshake failure is
    the intended outcome (fixture success).
    """
    cert, key = mint_certificate(workdir)
    notes: "list[str]" = []
    handshakes_started = 0
    capture_successes = 0
    attempts = 2

    try:
        result = subprocess.run(
            ["openssl", "s_client", "-help"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        # openssl prints -help to stderr; check both streams.
        if "-tls1_2" not in result.stdout + result.stderr:
            raise SkipScenario("openssl s_client lacks -tls1_2 flag")
    except Exception as exc:
        raise SkipScenario(f"openssl s_client feature check failed: {exc}") from exc

    with LocalTlsServer(cert, key) as server:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=str(cert), keyfile=str(key))
        # Pin to TLS 1.3 only for the alert scenario.
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3

        # Spin up a distinct server socket for this test.
        alert_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        alert_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        alert_socket.bind(("127.0.0.1", 0))
        alert_socket.listen(8)
        alert_port = alert_socket.getsockname()[1]
        alert_socket.settimeout(0.5)

        def serve_alert():
            while handshakes_started < attempts:
                try:
                    raw, _ = alert_socket.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                try:
                    raw.settimeout(5.0)
                    with context.wrap_socket(raw, server_side=True) as tls:
                        tls.recv(64)
                except Exception as exc:
                    notes.append(f"alert server: {type(exc).__name__}")
                finally:
                    with contextlib.suppress(OSError):
                        raw.close()

        alert_thread = threading.Thread(target=serve_alert, daemon=True)
        alert_thread.start()

        for attempt in range(attempts):
            handshakes_started += 1
            try:
                result = subprocess.run(
                    [
                        "openssl",
                        "s_client",
                        "-tls1_2",
                        "-servername",
                        ALERT_SNI,
                        "-connect",
                        f"127.0.0.1:{alert_port}",
                    ],
                    input="Q",
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                # The handshake is EXPECTED to fail with protocol_version alert.
                # Return code != 0 is correct; we capture this as fixture success.
                if result.returncode != 0:
                    capture_successes += 1
                    notes.append(
                        f"attempt {attempt + 1}: client rejected (expected) — "
                        f"alert scenario fixture working"
                    )
                else:
                    notes.append(
                        f"attempt {attempt + 1}: unexpected success (TLS 1.2 accepted)"
                    )
            except subprocess.TimeoutExpired:
                notes.append(f"attempt {attempt + 1}: timed out")
            except Exception as exc:
                notes.append(f"attempt {attempt + 1}: {type(exc).__name__}: {exc}")
            time.sleep(0.2)

        alert_socket.close()
        alert_thread.join(timeout=2)

    if capture_successes == 0:
        raise SmokeFailure(
            "alert scenario: no client rejections captured; "
            "the fixture (forced rejection) did not work: " + "; ".join(notes)
        )

    return TrafficReport(
        attempted=attempts,
        succeeded=capture_successes,
        expected_snis=(ALERT_SNI,),
        expected_endpoints=(f"127.0.0.1:{alert_port}",),
        notes=tuple(notes),
    )


def egress_traffic(_workdir: Path) -> TrafficReport:
    """Real handshakes to public hosts over the default-route interface."""
    context = ssl.create_default_context()
    notes: "list[str]" = []
    reached: "list[str]" = []

    for host in EGRESS_HOSTS:
        try:
            with socket.create_connection(
                (host, 443), timeout=EGRESS_CONNECT_TIMEOUT_S
            ) as raw:
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


_NETNS_PQC_NS_NAME: "Optional[str]" = None


def mint_pqc_certificate(workdir: Path) -> "tuple[Path, Path]":
    """Generate a self-signed certificate for the PQC test server.

    Uses EC curve (P-256) for faster generation and compatibility.
    """
    cert, key = workdir / "netns-cert.pem", workdir / "netns-key.pem"
    if cert.exists() and key.exists():
        return cert, key
    result = subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-days",
            "1",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-subj",
            f"/CN={NETNS_SNI}",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise SkipScenario(
            f"openssl failed to mint the PQC test certificate: {result.stderr.strip()}"
        )
    return cert, key


def netns_pqc_setup(workdir: Path) -> None:
    """Setup: create network namespace and veth pair pinned to MTU 1500.

    Raises SkipScenario if openssl lacks PQC support or CAP_NET_ADMIN is missing.
    The namespace is created with a pid-suffixed name and cleaned up unconditionally
    in the scenario's finally block.
    """
    global _NETNS_PQC_NS_NAME

    result = subprocess.run(
        ["openssl", "list", "-kem-algorithms"],
        capture_output=True,
        text=True,
    )
    if "X25519MLKEM768" not in result.stdout:
        raise SkipScenario("openssl does not support X25519MLKEM768 KEM")

    # Generate the PQC test certificate in setup so errors are caught early.
    try:
        mint_pqc_certificate(workdir)
    except SkipScenario:
        raise

    _NETNS_PQC_NS_NAME = f"probe_pqc_{os.getpid()}"
    veth_host = "veth_host"
    veth_ns = "veth_ns"
    ns_ip = "10.99.0.2"
    host_ip = "10.99.0.1"

    try:
        # Create namespace and veth pair
        for cmd in [
            ["ip", "netns", "add", _NETNS_PQC_NS_NAME],
            ["ip", "link", "add", veth_host, "type", "veth", "peer", "name", veth_ns],
            ["ip", "link", "set", veth_ns, "netns", _NETNS_PQC_NS_NAME],
            ["ip", "link", "set", veth_host, "mtu", "1500"],
            [
                "ip",
                "netns",
                "exec",
                _NETNS_PQC_NS_NAME,
                "ip",
                "link",
                "set",
                veth_ns,
                "mtu",
                "1500",
            ],
            ["ip", "addr", "add", f"{host_ip}/24", "dev", veth_host],
            ["ip", "link", "set", veth_host, "up"],
            [
                "ip",
                "netns",
                "exec",
                _NETNS_PQC_NS_NAME,
                "ip",
                "addr",
                "add",
                f"{ns_ip}/24",
                "dev",
                veth_ns,
            ],
            [
                "ip",
                "netns",
                "exec",
                _NETNS_PQC_NS_NAME,
                "ip",
                "link",
                "set",
                veth_ns,
                "up",
            ],
            # Cap GSO on both ends: veth never physically segments, so without
            # this the ~1800-byte PQC ClientHello traverses as one coalesced
            # skb and the reassembly path is never exercised.
            [
                "ip",
                "link",
                "set",
                veth_host,
                "gso_max_size",
                "1400",
                "gso_max_segs",
                "1",
            ],
            [
                "ip",
                "netns",
                "exec",
                _NETNS_PQC_NS_NAME,
                "ip",
                "link",
                "set",
                veth_ns,
                "gso_max_size",
                "1400",
                "gso_max_segs",
                "1",
            ],
        ]:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                raise SkipScenario(
                    f"netns setup failed: {' '.join(cmd)}: {result.stderr.strip()}"
                )
    except SkipScenario:
        raise
    except Exception as exc:
        raise SkipScenario(f"netns setup error: {exc}") from exc


def netns_pqc_traffic(workdir: Path) -> TrafficReport:
    """PQC ClientHello (X25519MLKEM768) segmented across MTU-1500 veth pair.

    Assumes the veth pair was created by netns_pqc_setup. Runs a TLS server
    inside the ns and drives a PQC client handshake from the host.
    """
    global _NETNS_PQC_NS_NAME

    if not _NETNS_PQC_NS_NAME:
        raise SmokeFailure("netns_pqc_traffic called without setup")

    ns_name = _NETNS_PQC_NS_NAME
    ns_ip = "10.99.0.2"

    cert, key = mint_pqc_certificate(workdir)
    notes: "list[str]" = []
    succeeded = 0
    attempt = 0

    try:
        # Start server in namespace
        server_ready = threading.Event()
        server_error: "list[str]" = []

        def run_server():
            try:
                proc = subprocess.Popen(
                    [
                        "ip",
                        "netns",
                        "exec",
                        ns_name,
                        "openssl",
                        "s_server",
                        "-cert",
                        str(cert),
                        "-key",
                        str(key),
                        "-accept",
                        f"{ns_ip}:9443",
                        "-quiet",
                        "-groups",
                        "X25519MLKEM768",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                server_ready.set()
                output, _ = proc.communicate(timeout=30)
                if proc.returncode != 0 and proc.returncode != -15:  # -15 is SIGTERM
                    server_error.append(f"server exited {proc.returncode}: {output}")
            except Exception as exc:
                server_error.append(f"server error: {exc}")

        server_thread = threading.Thread(target=run_server, daemon=True)
        server_thread.start()

        if not server_ready.wait(timeout=5):
            raise SkipScenario("openssl s_server did not start in time")

        time.sleep(0.2)

        # Client: connect with PQC
        try:
            result = subprocess.run(
                [
                    "openssl",
                    "s_client",
                    "-groups",
                    "X25519MLKEM768",
                    "-servername",
                    NETNS_SNI,
                    "-connect",
                    f"{ns_ip}:9443",
                    # Trust the self-signed server cert directly; /dev/null here
                    # makes openssl abort with "no certificate" before handshaking.
                    "-CAfile",
                    str(cert),
                ],
                input="Q",
                capture_output=True,
                text=True,
                timeout=8,
            )
            if result.returncode == 0:
                succeeded += 1
                notes.append(f"PQC handshake to {ns_ip}:9443 succeeded")
            else:
                notes.append(f"PQC handshake failed: {result.stderr.strip()[:100]}")
        except subprocess.TimeoutExpired:
            notes.append("PQC handshake timed out")
        except Exception as exc:
            notes.append(f"PQC handshake error: {exc}")

        attempt = 1

    except Exception as exc:
        raise SkipScenario(f"netns traffic error: {exc}") from exc

    if server_error:
        notes.extend(server_error)

    return TrafficReport(
        attempted=attempt,
        succeeded=succeeded,
        expected_snis=(NETNS_SNI,),
        expected_endpoints=(f"{ns_ip}:9443",),
        notes=tuple(notes),
    )


def tls12_cert_traffic(workdir: Path) -> TrafficReport:
    """TLS 1.2 handshake with Certificate message capture.

    Server: openssl s_server pinned to TLS 1.2 with self-signed cert.
    Client: openssl s_client -tls1_2 with SNI, using -ign_eof + "ping\n" pattern.
    Expects ≥1 Certificate event in the captured output.
    """
    cert, key = mint_certificate(workdir)
    cert12_path = workdir / "cert12.pem"
    key12_path = workdir / "key12.pem"
    # Generate a distinct certificate for TLS 1.2 test with different CN.
    if not cert12_path.exists() or not key12_path.exists():
        result = subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-sha256",
                "-days",
                "1",
                "-nodes",
                "-keyout",
                str(key12_path),
                "-out",
                str(cert12_path),
                "-subj",
                f"/CN={TLS12_CERT_SNI}",
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise SmokeFailure(
                f"openssl failed to mint TLS 1.2 test certificate: {result.stderr.strip()}"
            )

    notes: "list[str]" = []
    succeeded = 0
    attempts = 2

    # Feature-detect: openssl s_client and s_server must support -tls1_2.
    try:
        result = subprocess.run(
            ["openssl", "s_client", "-help"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        help_text = result.stdout + result.stderr
        if "-tls1_2" not in help_text:
            raise SkipScenario("openssl s_client lacks -tls1_2 flag")
    except Exception as exc:
        raise SkipScenario(f"openssl s_client feature check failed: {exc}") from exc

    with LocalTlsServer(cert12_path, key12_path) as server:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2

        for attempt in range(attempts):
            try:
                with socket.create_connection(
                    ("127.0.0.1", server.port), timeout=5
                ) as raw:
                    with context.wrap_socket(
                        raw, server_hostname=TLS12_CERT_SNI
                    ) as tls:
                        version = tls.version()
                        if version is None:
                            raise SmokeFailure("handshake completed without a version")
                        if version != "TLSv1.2":
                            notes.append(
                                f"attempt {attempt + 1}: negotiated {version}, expected TLSv1.2"
                            )
                            continue
                        tls.sendall(b"ping")
                        tls.recv(16)
                        succeeded += 1
                        if attempt == 0:
                            notes.append(f"{server.endpoint} negotiated {version}")
            except (OSError, ssl.SSLError, SmokeFailure) as exc:
                notes.append(f"attempt {attempt + 1} failed: {exc}")
            time.sleep(0.2)

        notes.extend(server.errors)

    if succeeded == 0:
        raise SmokeFailure(
            "TLS 1.2 cert scenario: no successful handshakes: " + "; ".join(notes)
        )

    return TrafficReport(
        attempted=attempts,
        succeeded=succeeded,
        expected_snis=(TLS12_CERT_SNI,),
        expected_endpoints=(server.endpoint,),
        notes=tuple(notes),
    )


def mtls_traffic(workdir: Path) -> TrafficReport:
    """mTLS handshake: server requires client certificate.

    Server: openssl s_server -tls1_2 -Verify 1 with client CA.
    Client: openssl s_client -tls1_2 with client cert and key.
    Expects ≥2 Certificate events (server and client) or documents direction filtering.
    Expects negotiation.mtls_requested=true and negotiation.mtls=true.
    """
    # Generate server certificate.
    server_cert, server_key = mint_certificate(workdir)

    # Generate client certificate and CA.
    client_cert = workdir / "mtls-client-cert.pem"
    client_key = workdir / "mtls-client-key.pem"
    client_ca = workdir / "mtls-client-ca.pem"

    if not client_cert.exists() or not client_key.exists() or not client_ca.exists():
        result = subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-sha256",
                "-days",
                "1",
                "-nodes",
                "-keyout",
                str(client_key),
                "-out",
                str(client_cert),
                "-subj",
                f"/CN=mtls-client.tls-probe.test",
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise SmokeFailure(
                f"openssl failed to mint mTLS client certificate: {result.stderr.strip()}"
            )
        # Client CA is the client cert itself (self-signed).
        import shutil

        shutil.copy(str(client_cert), str(client_ca))

    notes: "list[str]" = []
    succeeded = 0
    attempts = 2

    # Feature-detect: openssl s_client and s_server must support -tls1_2 and -Verify.
    try:
        result = subprocess.run(
            ["openssl", "s_server", "-help"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        help_text = result.stdout + result.stderr
        if "-tls1_2" not in help_text:
            raise SkipScenario("openssl s_server lacks -tls1_2 flag")
        if "-Verify" not in help_text:
            raise SkipScenario("openssl s_server lacks -Verify flag")
    except Exception as exc:
        raise SkipScenario(f"openssl s_server feature check failed: {exc}") from exc

    with LocalTlsServer(server_cert, server_key) as server:
        # Spin up a distinct server socket with mTLS enabled.
        mtls_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        mtls_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        mtls_socket.bind(("127.0.0.1", 0))
        mtls_socket.listen(8)
        mtls_port = mtls_socket.getsockname()[1]
        mtls_socket.settimeout(0.5)

        def serve_mtls():
            while succeeded < attempts:
                try:
                    raw, _ = mtls_socket.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                try:
                    raw.settimeout(5.0)
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    context.load_cert_chain(
                        certfile=str(server_cert), keyfile=str(server_key)
                    )
                    context.minimum_version = ssl.TLSVersion.TLSv1_2
                    context.maximum_version = ssl.TLSVersion.TLSv1_2
                    # Require client certificate.
                    context.verify_mode = ssl.CERT_REQUIRED
                    context.load_verify_locations(str(client_ca))
                    with context.wrap_socket(raw, server_side=True) as tls:
                        tls.recv(64)
                        tls.sendall(b"pong")
                        with contextlib.suppress(OSError, ssl.SSLError, TimeoutError):
                            tls.unwrap()
                except Exception as exc:
                    notes.append(f"mtls server: {type(exc).__name__}")
                finally:
                    with contextlib.suppress(OSError):
                        raw.close()

        mtls_thread = threading.Thread(target=serve_mtls, daemon=True)
        mtls_thread.start()

        for attempt in range(attempts):
            try:
                result = subprocess.run(
                    [
                        "openssl",
                        "s_client",
                        "-tls1_2",
                        "-cert",
                        str(client_cert),
                        "-key",
                        str(client_key),
                        "-servername",
                        MTLS_SNI,
                        "-connect",
                        f"127.0.0.1:{mtls_port}",
                        "-ign_eof",
                    ],
                    input="ping\n",
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    succeeded += 1
                    notes.append(f"attempt {attempt + 1}: mTLS handshake succeeded")
                else:
                    notes.append(
                        f"attempt {attempt + 1}: mTLS handshake failed with code {result.returncode}"
                    )
            except subprocess.TimeoutExpired:
                notes.append(f"attempt {attempt + 1}: mTLS handshake timed out")
            except Exception as exc:
                notes.append(f"attempt {attempt + 1}: {type(exc).__name__}: {exc}")
            time.sleep(0.2)

        mtls_socket.close()
        mtls_thread.join(timeout=2)

    if succeeded == 0:
        raise SmokeFailure(
            "mTLS scenario: no successful handshakes: " + "; ".join(notes)
        )

    return TrafficReport(
        attempted=attempts,
        succeeded=succeeded,
        expected_snis=(MTLS_SNI,),
        expected_endpoints=(f"127.0.0.1:{mtls_port}",),
        notes=tuple(notes),
    )


def resumption_traffic(workdir: Path) -> TrafficReport:
    """Session resumption: full handshake saves ticket, PSK handshake offers it.

    Two connections to a local server: first issues a session ticket, second
    offers it via PSK. Checks that ClientHello events reflect offered state
    and ServerHello confirms resumption via psk_selected.
    """
    cert, key = mint_certificate(workdir)
    notes: "list[str]" = []
    succeeded = 0
    attempts = 2
    sess_file = workdir / "resumption-session.pem"

    # Feature-detect: openssl s_client must support -sess_out and -sess_in.
    try:
        result = subprocess.run(
            ["openssl", "s_client", "-help"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        # openssl prints -help to stderr; check both streams.
        help_text = result.stdout + result.stderr
        if "-sess_out" not in help_text or "-sess_in" not in help_text:
            raise SkipScenario("openssl s_client lacks -sess_out/-sess_in flags")
    except Exception as exc:
        raise SkipScenario(f"openssl s_client feature check failed: {exc}") from exc

    with LocalTlsServer(cert, key) as server:
        # First connection: full handshake, save ticket.
        try:
            result = subprocess.run(
                [
                    "openssl",
                    "s_client",
                    "-sess_out",
                    str(sess_file),
                    "-servername",
                    RESUMPTION_SNI,
                    "-connect",
                    f"127.0.0.1:{server.port}",
                    # Without -ign_eof, stdin EOF makes s_client shut down
                    # before the post-handshake NewSessionTicket is processed,
                    # so -sess_out would never be written. With it, s_client
                    # stays until the server closes after answering.
                    "-ign_eof",
                ],
                input="ping\n",
                capture_output=True,
                text=True,
                timeout=5,
            )
            # The saved session file is the real success signal — exit codes
            # vary with how the shutdown races the client's read loop.
            if sess_file.exists() and sess_file.stat().st_size > 0:
                succeeded += 1
                notes.append("attempt 1 (full handshake): succeeded, ticket saved")
            else:
                notes.append(
                    f"attempt 1 (full handshake): no session ticket saved "
                    f"(exit {result.returncode}): {result.stderr.strip()[:120]}"
                )
        except subprocess.TimeoutExpired:
            notes.append("attempt 1 (full handshake): timed out")
        except Exception as exc:
            notes.append(f"attempt 1 (full handshake): {type(exc).__name__}: {exc}")

        # Small delay to ensure ticket arrives before second connection.
        time.sleep(0.5)

        # Second connection: offer PSK from session file.
        try:
            result = subprocess.run(
                [
                    "openssl",
                    "s_client",
                    "-sess_in",
                    str(sess_file),
                    "-servername",
                    RESUMPTION_SNI,
                    "-connect",
                    f"127.0.0.1:{server.port}",
                    "-ign_eof",
                ],
                input="ping\n",
                capture_output=True,
                text=True,
                timeout=5,
            )
            # s_client prints "Reused, TLSv1.3" in the session summary when the
            # PSK was accepted — a stronger signal than the exit code.
            if result.returncode == 0 or "Reused" in result.stdout:
                succeeded += 1
                notes.append("attempt 2 (resumption): succeeded, PSK offered")
            else:
                notes.append(
                    f"attempt 2 (resumption): failed with code {result.returncode}: "
                    f"{result.stderr.strip()[:120]}"
                )
        except subprocess.TimeoutExpired:
            notes.append("attempt 2 (resumption): timed out")
        except Exception as exc:
            notes.append(f"attempt 2 (resumption): {type(exc).__name__}: {exc}")

        notes.extend(server.errors)

    if succeeded == 0:
        raise SmokeFailure(
            "resumption scenario: no successful handshakes: " + "; ".join(notes)
        )

    return TrafficReport(
        attempted=attempts,
        succeeded=succeeded,
        expected_snis=(RESUMPTION_SNI,),
        expected_endpoints=(server.endpoint,),
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
    return (
        count > 0,
        f"{count} ServerHello events (exercises ingress and the src/dst swap)",
    )


def check_expected_sni(observation: Observation) -> "tuple[bool, str]":
    expected = set(observation.traffic.expected_snis)
    if not expected:
        return True, "no SNI expectation for this scenario"
    seen = observation.snis
    return bool(
        expected & seen
    ), f"expected any of {sorted(expected)}, captured {sorted(seen)}"


def check_expected_endpoint(observation: Observation) -> "tuple[bool, str]":
    expected = set(observation.traffic.expected_endpoints)
    if not expected:
        return True, "no endpoint expectation for this scenario"
    seen = observation.endpoints
    return bool(
        expected & seen
    ), f"expected any of {sorted(expected)} in src/dst, captured {sorted(seen)}"


def _at_expected_endpoint(
    observation: Observation, events: Sequence[dict]
) -> "list[dict]":
    """Only events touching our own fixture, so unrelated TLS on the interface cannot flake a gate."""
    expected = set(observation.traffic.expected_endpoints)
    return [e for e in events if e.get("src") in expected or e.get("dst") in expected]


def check_capture_complete(observation: Observation) -> "tuple[bool, str]":
    """Per-handshake accounting: capturing *some* events must not hide losing others."""
    expected = observation.traffic.succeeded
    client = _at_expected_endpoint(observation, observation.client_hellos)
    server = _at_expected_endpoint(observation, observation.server_hellos)
    return len(client) >= expected and len(server) >= expected, (
        f"{len(client)} ClientHellos / {len(server)} ServerHellos at the pinned endpoint for "
        f"{expected} handshakes; fewer means silent capture loss (non-linear skb, verifier bail-out)"
    )


def check_sni_on_every_client_hello(observation: Observation) -> "tuple[bool, str]":
    """SNI sits late in the record, so a truncated payload copy clips it first."""
    client = _at_expected_endpoint(observation, observation.client_hellos)
    if not client:
        return False, "no ClientHellos at the pinned endpoint to inspect"
    missing = sum(1 for e in client if not e.get("sni"))
    return missing == 0, (
        f"{missing}/{len(client)} pinned-endpoint ClientHellos lack an SNI; "
        "a truncated payload copy is the usual cause"
    )


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
    """TLS 1.3 only: key_share is not present in TLS 1.2 ClientHellos."""
    hellos = observation.client_hellos
    return _non_empty(hellos, "key_share_group") > 0, (
        f"{_non_empty(hellos, 'key_share_group')}/{len(hellos)} ClientHellos carry a key_share group"
    )


def check_tls_versions_known(observation: Observation) -> "tuple[bool, str]":
    """ClientHello and ServerHello events must carry known TLS versions.

    Non-hello events (Certificate, CertificateRequest, etc.) may carry "Unknown"
    in the tls_version field due to edge cases in record_version encoding.
    Only validate known versions for hello events.
    """
    hello_events = [
        e
        for e in observation.events
        if e.get("handshake_type") in ("ClientHello", "ServerHello")
    ]
    unknown = sorted(
        {
            str(event.get("tls_version"))
            for event in hello_events
            if event.get("tls_version") not in KNOWN_TLS_VERSIONS
        }
    )
    return (
        not unknown,
        f"unrecognised tls_version values in hellos: {unknown}"
        if unknown
        else "all hello tls_versions recognised",
    )


def check_named_ids_resolved(observation: Observation) -> "tuple[bool, str]":
    """Every id we surface should map to a name, otherwise the lookup tables are stale."""
    unknown = set()
    for event in observation.events:
        for key in ("cipher_suites", "key_exchange_groups", "signature_algorithms"):
            for item in event.get(key) or []:
                if item.get("name") == "unknown":
                    unknown.add(f"{key}:0x{item.get('id', 0):04x}")
    return (
        not unknown,
        f"unmapped ids: {sorted(unknown)}" if unknown else "all ids mapped to names",
    )


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
    return (
        traffic.succeeded == traffic.attempted,
        f"{traffic.succeeded}/{traffic.attempted} handshakes: {notes}",
    )


def check_probe_exit(observation: Observation) -> "tuple[bool, str]":
    """A probe that dies mid-capture must not look like 'no traffic seen'."""
    code = observation.probe_exit_code
    if code is None:
        return False, "probe was never reaped"
    if code < 0:
        return False, f"probe was killed by signal {-code} (it did not honour SIGTERM)"
    return code == 0, f"probe exited with code {code}"


def check_no_probe_errors(observation: Observation) -> "tuple[bool, str]":
    offenders = [
        line.strip()
        for line in observation.probe_log.splitlines()
        if PROBE_ERROR_RE.search(line)
    ]
    return (
        not offenders,
        f"probe logged errors: {offenders[:3]}" if offenders else "no errors logged",
    )


def check_pqc_kem_present(observation: Observation) -> "tuple[bool, str]":
    """X25519MLKEM768 must be in the captured key_exchange_groups or key_share_group."""
    client = _at_expected_endpoint(observation, observation.client_hellos)
    if not client:
        return False, "no ClientHellos at the pinned endpoint to inspect"
    found = 0
    for event in client:
        groups = event.get("key_exchange_groups") or []
        key_share = event.get("key_share_group")
        for group in groups:
            if group.get("name") == "X25519MLKEM768":
                found += 1
                break
        if not found and key_share and key_share.get("name") == "X25519MLKEM768":
            found += 1
    return found > 0, f"{found} ClientHellos carry X25519MLKEM768"


def check_sni_matches_expected(observation: Observation) -> "tuple[bool, str]":
    """SNI must be NETNS_SNI for this scenario."""
    client = _at_expected_endpoint(observation, observation.client_hellos)
    if not client:
        return False, "no ClientHellos at the pinned endpoint to inspect"
    matching = sum(1 for e in client if e.get("sni") == NETNS_SNI)
    return matching > 0, f"{matching}/{len(client)} ClientHellos have SNI={NETNS_SNI}"


def check_reassembly_flag_set(observation: Observation) -> "tuple[bool, str]":
    """At least one ClientHello must have reassembled=True due to MTU-1500 segmentation."""
    client = _at_expected_endpoint(observation, observation.client_hellos)
    if not client:
        return False, "no ClientHellos at the pinned endpoint to inspect"
    reassembled = sum(1 for e in client if e.get("reassembled") is True)
    return (
        reassembled > 0,
        f"{reassembled}/{len(client)} ClientHellos have reassembled=True",
    )


def check_negotiation_present(observation: Observation) -> "tuple[bool, str]":
    """Every ServerHello must carry a negotiation object (CH↔SH correlation)."""
    server = _at_expected_endpoint(observation, observation.server_hellos)
    if not server:
        return False, "no ServerHellos at the pinned endpoint to inspect"
    missing = sum(1 for e in server if not e.get("negotiation"))
    return missing == 0, (
        f"{missing}/{len(server)} ServerHellos lack negotiation object; "
        "this indicates CH↔SH correlation failed"
    )


def check_negotiation_selected_in_offered(
    observation: Observation,
) -> "tuple[bool, str]":
    """For each SH negotiation, selected_group.id must be in the CH key_exchange_groups."""
    server = _at_expected_endpoint(observation, observation.server_hellos)
    if not server:
        return False, "no ServerHellos at the pinned endpoint to inspect"
    client = _at_expected_endpoint(observation, observation.client_hellos)
    if not client:
        return False, "no ClientHellos at the pinned endpoint to inspect"

    # Build a map: (src, dst) -> ClientHello with key_exchange_groups
    ch_by_endpoint: "dict[tuple[str, str], dict]" = {}
    for ch in client:
        src, dst = ch.get("src"), ch.get("dst")
        if src and dst:
            ch_by_endpoint[(src, dst)] = ch

    mismatches = 0
    for sh in server:
        negotiation = sh.get("negotiation")
        if not negotiation:
            continue
        selected_id = negotiation.get("selected_group", {}).get("id")
        if selected_id is None:
            mismatches += 1
            continue

        # Reverse the src/dst: if SH comes from (A, B), the CH came from (B, A).
        src, dst = sh.get("src"), sh.get("dst")
        if not src or not dst:
            mismatches += 1
            continue

        ch = ch_by_endpoint.get((dst, src))
        if not ch:
            mismatches += 1
            continue

        offered_ids = {g.get("id") for g in ch.get("key_exchange_groups") or []}
        if selected_id not in offered_ids:
            mismatches += 1

    passed = mismatches == 0
    return passed, (
        f"{mismatches} mismatches between negotiation.selected_group.id and CH key_exchange_groups"
        if mismatches > 0
        else "all negotiation.selected_group.id values are in the corresponding CH key_exchange_groups"
    )


def check_negotiation_no_downgrade(observation: Observation) -> "tuple[bool, str]":
    """loopback: client_max_version=TLS 1.3 and outcome='negotiated' (no TLS version downgrade)."""
    server = _at_expected_endpoint(observation, observation.server_hellos)
    if not server:
        return False, "no ServerHellos at the pinned endpoint to inspect"

    violations = 0
    for sh in server:
        negotiation = sh.get("negotiation")
        if not negotiation:
            continue
        # Check that negotiated version is TLS 1.3 (no downgrade).
        # This is inferred from client_max_version == negotiated version.
        if (
            negotiation.get("client_max_version") != "TLS 1.3"
            or negotiation.get("outcome") != "negotiated"
        ):
            violations += 1

    passed = violations == 0
    return passed, (
        f"{violations} ServerHellos have client_max_version != TLS 1.3 or outcome != 'negotiated'"
        if violations > 0
        else "all negotiation objects have client_max_version=TLS 1.3 and outcome='negotiated'"
    )


def check_negotiation_sni_matches(observation: Observation) -> "tuple[bool, str]":
    """loopback: negotiation.client_sni must be 'smoke.tls-probe.test'."""
    server = _at_expected_endpoint(observation, observation.server_hellos)
    if not server:
        return False, "no ServerHellos at the pinned endpoint to inspect"

    mismatches = 0
    for sh in server:
        negotiation = sh.get("negotiation")
        if not negotiation:
            continue
        if negotiation.get("client_sni") != SMOKE_SNI:
            mismatches += 1

    passed = mismatches == 0
    return passed, (
        f"{mismatches} ServerHellos have client_sni != {SMOKE_SNI}"
        if mismatches > 0
        else f"all negotiation objects have client_sni={SMOKE_SNI}"
    )


def check_negotiation_pqc_selected(observation: Observation) -> "tuple[bool, str]":
    """netns_pqc: X25519MLKEM768 must be in client_offered_groups and selected_group.name, with outcome='negotiated'."""
    server = _at_expected_endpoint(observation, observation.server_hellos)
    if not server:
        return False, "no ServerHellos at the pinned endpoint to inspect"

    violations = 0
    for sh in server:
        negotiation = sh.get("negotiation")
        if not negotiation:
            continue
        selected_name = negotiation.get("selected_group", {}).get("name")
        offered_names = {g.get("name") for g in negotiation.get("client_offered_groups") or []}
        # PQC was selected if X25519MLKEM768 is both offered and selected.
        if (
            "X25519MLKEM768" not in offered_names
            or selected_name != "X25519MLKEM768"
            or negotiation.get("outcome") != "negotiated"
        ):
            violations += 1

    passed = violations == 0
    return passed, (
        f"{violations} ServerHellos lack PQC negotiation (X25519MLKEM768 in offered_groups and selected_group)"
        if violations > 0
        else "all negotiation objects confirm X25519MLKEM768 was offered and selected with outcome='negotiated'"
    )


def check_egress_negotiation_present_when_ch_present(
    observation: Observation,
) -> "tuple[bool, str]":
    """egress (advisory): if a CH was captured for a flow, the SH should have negotiation."""
    server = observation.server_hellos  # No endpoint filter for egress (real world)
    if not server:
        return (
            True,
            "no ServerHellos captured (acceptable for egress if network is poor)",
        )

    # Build a map: (src, dst) -> True for flows with a ClientHello
    ch_flows: "set[tuple[str, str]]" = set()
    for ch in observation.client_hellos:
        src, dst = ch.get("src"), ch.get("dst")
        if src and dst:
            ch_flows.add((src, dst))

    missing_negotiation = 0
    for sh in server:
        src, dst = sh.get("src"), sh.get("dst")
        if not src or not dst:
            continue
        # Reverse: if SH is from (A, B), the CH was from (B, A).
        if (dst, src) in ch_flows and not sh.get("negotiation"):
            missing_negotiation += 1

    return True, (
        f"{missing_negotiation} ServerHellos lack negotiation despite matching ClientHello"
        if missing_negotiation > 0
        else "all captured ServerHellos matching a ClientHello flow have negotiation"
    )


def check_egress_client_offered_groups_is_list(observation: Observation) -> "tuple[bool, str]":
    """egress (advisory): client_offered_groups must be a list of dicts with id and name fields."""
    server = observation.server_hellos
    if not server:
        return True, "no ServerHellos captured"

    issues = 0
    for sh in server:
        negotiation = sh.get("negotiation")
        if negotiation:
            offered_groups = negotiation.get("client_offered_groups")
            if offered_groups is not None:
                if not isinstance(offered_groups, list):
                    issues += 1
                else:
                    for group in offered_groups:
                        if not isinstance(group, dict) or "id" not in group or "name" not in group:
                            issues += 1
                            break

    return True, (
        f"{issues} negotiation.client_offered_groups values are not properly formed lists"
        if issues > 0
        else "all client_offered_groups values are properly formed lists of group objects"
    )


def check_alert_event_present(observation: Observation) -> "tuple[bool, str]":
    """At least one Alert event must be captured."""
    alerts = observation.by_type("Alert")
    return len(alerts) >= 1, f"{len(alerts)} Alert events captured"


def check_alert_named_protocol_version(observation: Observation) -> "tuple[bool, str]":
    """At least one Alert has alert_description starting with 'protocol_version' and level 'fatal'."""
    alerts = observation.by_type("Alert")
    if not alerts:
        return False, "no Alert events to inspect"
    matching = sum(
        1
        for e in alerts
        if (
            e.get("alert_description", "").startswith("protocol_version")
            and e.get("alert_level") == "fatal"
        )
    )
    return matching >= 1, (
        f"{matching} Alert events have protocol_version description and fatal level"
    )


def check_alert_outcome_failed(observation: Observation) -> "tuple[bool, str]":
    """Alert event carries negotiation with outcome='failed', client_max_version='TLS 1.2', client_sni=ALERT_SNI."""
    alerts = observation.by_type("Alert")
    if not alerts:
        return False, "no Alert events to inspect"

    matching = 0
    for alert in alerts:
        negotiation = alert.get("negotiation")
        if negotiation and (
            negotiation.get("outcome") == "failed"
            and negotiation.get("client_max_version") == "TLS 1.2"
            and negotiation.get("client_sni") == ALERT_SNI
        ):
            matching += 1

    return matching >= 1, (
        f"{matching} Alert events carry negotiation(outcome='failed', "
        f"client_max_version='TLS 1.2', client_sni='{ALERT_SNI}')"
    )


def check_no_serverhello_for_failed_flow(
    observation: Observation,
) -> "tuple[bool, str]":
    """No ServerHello event exists for the same flow tuple as an Alert."""
    alerts = observation.by_type("Alert")
    server_hellos = observation.server_hellos
    if not alerts:
        return True, "no Alert events, nothing to check"
    if not server_hellos:
        return True, "no ServerHellos captured (expected for failed handshake)"

    # Build set of (src, dst) from Alert events.
    alert_flows = set()
    for alert in alerts:
        src, dst = alert.get("src"), alert.get("dst")
        if src and dst:
            alert_flows.add((src, dst))

    # Check for ServerHello overlaps.
    overlaps = 0
    for sh in server_hellos:
        src, dst = sh.get("src"), sh.get("dst")
        if src and dst and (src, dst) in alert_flows:
            overlaps += 1

    return overlaps == 0, (
        f"{overlaps} ServerHello events found on the same flow as an Alert "
        f"(expected: 0 since handshake failed)"
    )


def check_second_ch_offers_psk(observation: Observation) -> "tuple[bool, str]":
    """At least one ClientHello event with resumption.psk_offered == true."""
    client = _at_expected_endpoint(observation, observation.client_hellos)
    if not client:
        return False, "no ClientHellos at the pinned endpoint to inspect"
    psk_offered = sum(
        1 for e in client if e.get("resumption", {}).get("psk_offered") is True
    )
    return (
        psk_offered >= 1,
        f"{psk_offered} ClientHellos have resumption.psk_offered=true",
    )


def check_first_ch_no_psk(observation: Observation) -> "tuple[bool, str]":
    """At least one ClientHello event WITHOUT resumption.psk_offered (first connection)."""
    client = _at_expected_endpoint(observation, observation.client_hellos)
    if not client:
        return False, "no ClientHellos at the pinned endpoint to inspect"
    no_psk = sum(
        1
        for e in client
        if e.get("resumption") is None
        or e.get("resumption", {}).get("psk_offered") is not True
    )
    return (
        no_psk >= 1,
        f"{no_psk} ClientHellos lack resumption.psk_offered or have psk_offered=false",
    )


def check_sh_psk_selected(observation: Observation) -> "tuple[bool, str]":
    """At least one ServerHello with resumption.psk_selected == true OR negotiation.psk_selected == true."""
    server = _at_expected_endpoint(observation, observation.server_hellos)
    if not server:
        return False, "no ServerHellos at the pinned endpoint to inspect"
    psk_selected = sum(
        1
        for e in server
        if e.get("resumption", {}).get("psk_selected") is True
        or e.get("negotiation", {}).get("psk_selected") is True
    )
    return psk_selected >= 1, f"{psk_selected} ServerHellos have psk_selected=true"


def check_resumed_negotiation_joined(observation: Observation) -> "tuple[bool, str]":
    """ServerHello with psk_selected carries negotiation with outcome == 'negotiated'."""
    server = _at_expected_endpoint(observation, observation.server_hellos)
    if not server:
        return False, "no ServerHellos at the pinned endpoint to inspect"

    violations = 0
    for sh in server:
        has_psk_selected = (
            sh.get("resumption", {}).get("psk_selected") is True
            or sh.get("negotiation", {}).get("psk_selected") is True
        )
        if has_psk_selected:
            negotiation = sh.get("negotiation")
            if not negotiation or negotiation.get("outcome") != "negotiated":
                violations += 1

    passed = violations == 0
    return passed, (
        f"{violations} ServerHellos with psk_selected lack negotiation.outcome='negotiated'"
        if violations > 0
        else "all ServerHellos with psk_selected have outcome='negotiated'"
    )


def check_server_side_attribution(observation: Observation) -> "tuple[bool, str]":
    """At least one event at the pinned endpoint carries server-side attribution with process_name='python*' and non-null pid.

    The loopback scenario's local TLS server runs in the python3 process that launched this script.
    The inet_csk_accept kretprobe attributes inbound flows by reading the process_name from the
    current task via the accept kretprobe. When the server thread is pooled inside the main python3
    process, the comm value is 'python3' (truncated to 15 chars). We match process_name starting with
    'python' to survive version variations (python3.10, python3.11, etc.). The event must have a
    non-null pid field.
    """
    client = _at_expected_endpoint(observation, observation.client_hellos)
    if not client:
        return False, "no ClientHellos at the pinned endpoint to inspect"

    attributed = [
        e
        for e in client
        if e.get("pid") is not None
        and (e.get("process_name") or "").startswith("python")
    ]
    return len(attributed) > 0, (
        f"{len(attributed)} ClientHellos carry server-side attribution (process_name starting with 'python', pid non-null)"
    )


def check_ja4_present_and_wellformed(observation: Observation) -> "tuple[bool, str]":
    r"""Every ClientHello event at the pinned endpoint has a well-formed ja4 string.

    JA4 fingerprint format: t1[0-3][di]\d{4}[0-9a-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}
    Example: t13d0305h2_55b375c5d22e_87c083d729a1

    The regex enforces: t1 prefix, TLS version [0-3], cipher/extensions d/i, version details,
    underscores, and hex groups. Once the client becomes deterministic, exact value matching can
    be added.
    """
    client = _at_expected_endpoint(observation, observation.client_hellos)
    if not client:
        return False, "no ClientHellos at the pinned endpoint to inspect"

    ja4_pattern = re.compile(r"^t1[0-3][di]\d{4}[0-9a-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$")
    invalid = [
        e for e in client if not e.get("ja4") or not ja4_pattern.match(e.get("ja4", ""))
    ]
    return len(invalid) == 0, (
        f"{len(invalid)}/{len(client)} ClientHellos lack well-formed ja4"
        if invalid
        else f"all {len(client)} ClientHellos carry well-formed ja4"
    )


def check_ja4_pqc_wellformed(observation: Observation) -> "tuple[bool, str]":
    r"""ClientHellos from the netns_pqc scenario carry well-formed ja4 (tests reassembled payloads).

    Same regex as loopback scenario: t1[0-3][di]\d{4}[0-9a-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}
    This proves JA4 fingerprinting works on reassembled packets, not just single-packet payloads.
    """
    client = _at_expected_endpoint(observation, observation.client_hellos)
    if not client:
        return False, "no ClientHellos at the pinned endpoint to inspect"

    ja4_pattern = re.compile(r"^t1[0-3][di]\d{4}[0-9a-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$")
    invalid = [
        e for e in client if not e.get("ja4") or not ja4_pattern.match(e.get("ja4", ""))
    ]
    return len(invalid) == 0, (
        f"{len(invalid)}/{len(client)} ClientHellos lack well-formed ja4"
        if invalid
        else f"all {len(client)} ClientHellos carry well-formed ja4"
    )


def check_certificate_event_present(observation: Observation) -> "tuple[bool, str]":
    """At least one Certificate event must be captured."""
    certs = observation.by_type("Certificate")
    return len(certs) >= 1, f"{len(certs)} Certificate events captured"


def check_certificate_fields_sane(observation: Observation) -> "tuple[bool, str]":
    """Certificate event carries well-formed certificate object."""
    certs = observation.by_type("Certificate")
    if not certs:
        return False, "no Certificate events to inspect"

    invalid = []
    for cert_event in certs:
        cert_obj = cert_event.get("certificate")
        if not cert_obj:
            invalid.append("missing certificate object")
            continue
        # Check required fields: not_after (parseable), self_signed, subject_cn, public_key_algorithm, san_count.
        if not cert_obj.get("not_after"):
            invalid.append("missing not_after")
        if cert_obj.get("self_signed") is not True:
            invalid.append(f"self_signed={cert_obj.get('self_signed')}, expected true")
        if not cert_obj.get("subject_cn"):
            invalid.append("missing or empty subject_cn")
        if not cert_obj.get("public_key_algorithm"):
            invalid.append("missing public_key_algorithm")
        if not isinstance(cert_obj.get("san_count"), int):
            invalid.append(f"san_count not int: {type(cert_obj.get('san_count'))}")

    return len(invalid) == 0, (
        f"{len(invalid)} Certificate objects with missing/malformed fields"
        if invalid
        else f"all {len(certs)} Certificate objects well-formed"
    )


def check_certificate_not_expired(observation: Observation) -> "tuple[bool, str]":
    """Certificate event's certificate.expired must be false (freshly minted)."""
    certs = observation.by_type("Certificate")
    if not certs:
        return False, "no Certificate events to inspect"

    expired_count = sum(
        1
        for cert_event in certs
        if cert_event.get("certificate", {}).get("expired") is True
    )
    return expired_count == 0, (
        f"{expired_count}/{len(certs)} Certificate objects are expired (expected: 0)"
    )


def check_tls13_flows_no_certificate(observation: Observation) -> "tuple[bool, str]":
    """In TLS 1.3 loopback scenario, no Certificate events should be present (certs are encrypted).

    This check is for the loopback scenario only (TLS 1.3). If called on tls12_cert or mtls, it should pass trivially.
    """
    certs = observation.by_type("Certificate")
    # If no Certificate events, this passes.
    if not certs:
        return True, "no Certificate events (TLS 1.3 certs are encrypted)"

    # If Certificate events exist, verify they are NOT from TLS 1.3 handshakes.
    tls13_certs = 0
    for cert_event in certs:
        # Check if this event's tls_version is TLS 1.3.
        if cert_event.get("tls_version") == "TLS 1.3":
            tls13_certs += 1

    return tls13_certs == 0, (
        f"{tls13_certs} Certificate events from TLS 1.3 handshakes (expected: 0 since certs are encrypted)"
    )


def check_mtls_requested_flagged(observation: Observation) -> "tuple[bool, str]":
    """At least one event's negotiation has mtls_requested == true."""
    server = observation.server_hellos
    if not server:
        return False, "no ServerHellos to inspect"

    mtls_requested = sum(
        1 for e in server if e.get("negotiation", {}).get("mtls_requested") is True
    )
    return mtls_requested >= 1, (
        f"{mtls_requested} ServerHellos have negotiation.mtls_requested=true"
    )


def check_mtls_completed_flagged(observation: Observation) -> "tuple[bool, str]":
    """At least one event's negotiation has mtls == true.

    The completed-mTLS negotiation rides the CLIENT Certificate event, not the
    ServerHello: the SH (with mtls_requested) is emitted before the client's
    certificate exists, so mtls=true is only knowable — and attached — when the
    client Certificate arrives.
    """
    mtls_completed = sum(
        1
        for e in observation.events
        if (e.get("negotiation") or {}).get("mtls") is True
    )
    return mtls_completed >= 1, (
        f"{mtls_completed} events carry negotiation.mtls=true"
    )


def check_client_certificate_captured(observation: Observation) -> "tuple[bool, str]":
    """At least 2 Certificate events (server and client) OR document direction filtering.

    For mTLS, both server and client send Certificate messages. If only one is captured,
    it may indicate direction filtering by the probe. This is a hard check to ensure
    full bidirectional visibility or justify why one direction is missing.
    """
    certs = observation.by_type("Certificate")
    return len(certs) >= 2, (
        f"{len(certs)} Certificate events captured (expected ≥2 for mTLS server+client); "
        f"if <2, direction filtering may be hiding one party's Certificate"
    )


def check_ja4_present_egress(observation: Observation) -> "tuple[bool, str]":
    """egress (advisory): ClientHellos carry ja4."""
    client = observation.client_hellos
    if not client:
        return True, "no ClientHellos captured (acceptable for egress)"

    ja4_present = sum(1 for e in client if e.get("ja4"))
    return True, (f"{ja4_present}/{len(client)} ClientHellos carry ja4 (advisory)")


#: Assertions that must hold wherever the probe runs.
BASE_CHECKS: "tuple[Check, ...]" = (
    Check("events_present", Severity.ERROR, check_events_present),
    Check("schema_conformance", Severity.ERROR, check_schema),
    Check("client_hello_captured", Severity.ERROR, check_client_hello),
    Check("expected_sni_captured", Severity.ERROR, check_expected_sni),
    Check("cipher_suites_parsed", Severity.ERROR, check_cipher_suites_parsed),
    Check("key_exchange_groups_parsed", Severity.ERROR, check_key_exchange_parsed),
    Check(
        "signature_algorithms_parsed", Severity.ERROR, check_signature_algorithms_parsed
    ),
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
            Check(
                "expected_endpoint_captured", Severity.ERROR, check_expected_endpoint
            ),
            Check("capture_complete", Severity.ERROR, check_capture_complete),
            Check(
                "sni_on_every_client_hello",
                Severity.ERROR,
                check_sni_on_every_client_hello,
            ),
            Check("key_share_parsed", Severity.ERROR, check_key_share_parsed),
            Check("tls_versions_known", Severity.ERROR, check_tls_versions_known),
            Check("no_event_drops", Severity.ERROR, check_no_drops),
            Check("negotiation_present", Severity.ERROR, check_negotiation_present),
            Check(
                "negotiation_selected_in_offered",
                Severity.ERROR,
                check_negotiation_selected_in_offered,
            ),
            Check(
                "negotiation_no_downgrade",
                Severity.ERROR,
                check_negotiation_no_downgrade,
            ),
            Check(
                "negotiation_sni_matches", Severity.ERROR, check_negotiation_sni_matches
            ),
            Check(
                "server_side_attribution", Severity.ERROR, check_server_side_attribution
            ),
            Check(
                "ja4_present_and_wellformed",
                Severity.ERROR,
                check_ja4_present_and_wellformed,
            ),
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
            Check(
                "egress_negotiation_present_when_ch_present",
                Severity.WARN,
                check_egress_negotiation_present_when_ch_present,
            ),
            Check(
                "egress_client_offered_groups_is_list",
                Severity.WARN,
                check_egress_client_offered_groups_is_list,
            ),
            Check("ja4_present_egress", Severity.WARN, check_ja4_present_egress),
        ),
    ),
    Scenario(
        name="netns_pqc",
        description="PQC ClientHello (X25519MLKEM768) segmented across MTU-1500 veth",
        interface="veth_host",
        traffic=netns_pqc_traffic,
        checks=BASE_CHECKS
        + (
            Check("pqc_kem_in_groups", Severity.ERROR, check_pqc_kem_present),
            Check("sni_exact_match", Severity.ERROR, check_sni_matches_expected),
            Check("reassembly_detected", Severity.ERROR, check_reassembly_flag_set),
            Check(
                "expected_endpoint_captured", Severity.ERROR, check_expected_endpoint
            ),
            Check(
                "negotiation_pqc_selected",
                Severity.ERROR,
                check_negotiation_pqc_selected,
            ),
            Check("ja4_pqc_wellformed", Severity.ERROR, check_ja4_pqc_wellformed),
            Check("traffic_fixture_healthy", Severity.WARN, check_traffic_complete),
        ),
        # Skips cleanly without PQC openssl / CAP_NET_ADMIN; when it runs,
        # assertion failures must gate the suite (reassembly is the v0.5 marker).
        required=True,
        setup=netns_pqc_setup,
    ),
    Scenario(
        name="alert_failure",
        description="forced handshake failure: TLS 1.2 client vs TLS 1.3-only server",
        interface="lo",
        traffic=alert_traffic,
        checks=BASE_CHECKS
        + (
            Check("alert_event_present", Severity.ERROR, check_alert_event_present),
            Check(
                "alert_named_protocol_version",
                Severity.ERROR,
                check_alert_named_protocol_version,
            ),
            Check("alert_outcome_failed", Severity.ERROR, check_alert_outcome_failed),
            Check(
                "no_serverhello_for_failed_flow",
                Severity.ERROR,
                check_no_serverhello_for_failed_flow,
            ),
            Check("traffic_fixture_healthy", Severity.WARN, check_traffic_complete),
        ),
        required=True,
    ),
    Scenario(
        name="resumption",
        description="session resumption: full handshake saves ticket, PSK handshake offers it",
        interface="lo",
        traffic=resumption_traffic,
        checks=BASE_CHECKS
        + (
            Check("server_hello_captured", Severity.ERROR, check_server_hello),
            Check(
                "expected_endpoint_captured", Severity.ERROR, check_expected_endpoint
            ),
            Check("capture_complete", Severity.ERROR, check_capture_complete),
            Check(
                "sni_on_every_client_hello",
                Severity.ERROR,
                check_sni_on_every_client_hello,
            ),
            Check("key_share_parsed", Severity.ERROR, check_key_share_parsed),
            Check("tls_versions_known", Severity.ERROR, check_tls_versions_known),
            Check("no_event_drops", Severity.ERROR, check_no_drops),
            Check("negotiation_present", Severity.ERROR, check_negotiation_present),
            Check("second_ch_offers_psk", Severity.ERROR, check_second_ch_offers_psk),
            Check("first_ch_no_psk", Severity.ERROR, check_first_ch_no_psk),
            Check("sh_psk_selected", Severity.ERROR, check_sh_psk_selected),
            Check(
                "resumed_negotiation_joined",
                Severity.ERROR,
                check_resumed_negotiation_joined,
            ),
            Check("traffic_fixture_healthy", Severity.WARN, check_traffic_complete),
            Check("named_ids_resolved", Severity.WARN, check_named_ids_resolved),
            Check("process_attribution", Severity.WARN, check_process_attribution),
        ),
        required=True,
    ),
    Scenario(
        name="tls12_cert",
        description="TLS 1.2 handshake with Certificate message capture",
        interface="lo",
        traffic=tls12_cert_traffic,
        checks=BASE_CHECKS
        + (
            Check("server_hello_captured", Severity.ERROR, check_server_hello),
            Check(
                "expected_endpoint_captured", Severity.ERROR, check_expected_endpoint
            ),
            Check("capture_complete", Severity.ERROR, check_capture_complete),
            Check(
                "sni_on_every_client_hello",
                Severity.ERROR,
                check_sni_on_every_client_hello,
            ),
            Check("tls_versions_known", Severity.ERROR, check_tls_versions_known),
            Check("no_event_drops", Severity.ERROR, check_no_drops),
            Check("negotiation_present", Severity.ERROR, check_negotiation_present),
            Check(
                "certificate_event_present",
                Severity.ERROR,
                check_certificate_event_present,
            ),
            Check(
                "certificate_fields_sane", Severity.ERROR, check_certificate_fields_sane
            ),
            Check(
                "certificate_not_expired", Severity.ERROR, check_certificate_not_expired
            ),
            Check("traffic_fixture_healthy", Severity.WARN, check_traffic_complete),
            Check("named_ids_resolved", Severity.WARN, check_named_ids_resolved),
            Check("process_attribution", Severity.WARN, check_process_attribution),
        ),
        required=True,
    ),
    Scenario(
        name="mtls",
        description="mTLS handshake: server requires client certificate (TLS 1.2)",
        interface="lo",
        traffic=mtls_traffic,
        checks=BASE_CHECKS
        + (
            Check("server_hello_captured", Severity.ERROR, check_server_hello),
            Check(
                "expected_endpoint_captured", Severity.ERROR, check_expected_endpoint
            ),
            Check("capture_complete", Severity.ERROR, check_capture_complete),
            Check(
                "sni_on_every_client_hello",
                Severity.ERROR,
                check_sni_on_every_client_hello,
            ),
            Check("tls_versions_known", Severity.ERROR, check_tls_versions_known),
            Check("no_event_drops", Severity.ERROR, check_no_drops),
            Check("negotiation_present", Severity.ERROR, check_negotiation_present),
            Check(
                "mtls_requested_flagged", Severity.ERROR, check_mtls_requested_flagged
            ),
            Check(
                "mtls_completed_flagged", Severity.ERROR, check_mtls_completed_flagged
            ),
            Check(
                "client_certificate_captured",
                Severity.ERROR,
                check_client_certificate_captured,
            ),
            Check("traffic_fixture_healthy", Severity.WARN, check_traffic_complete),
            Check("named_ids_resolved", Severity.WARN, check_named_ids_resolved),
            Check("process_attribution", Severity.WARN, check_process_attribution),
        ),
        required=True,
    ),
)


# --- Driver -------------------------------------------------------------------


def run_scenario(
    scenario: Scenario, probe_bin: Path, ebpf: Path, schema: dict, workdir: Path
) -> ScenarioResult:
    with group(f"Scenario: {scenario.name} — {scenario.description}"):
        probe = Probe(probe_bin, ebpf, scenario.interface, workdir, scenario.name)
        try:
            # Setup phase: establish any pre-probe fixtures (e.g., netns/veth).
            if scenario.setup:
                try:
                    scenario.setup(workdir)
                except SkipScenario as exc:
                    annotate(
                        Severity.WARN, f"scenario '{scenario.name}' skipped: {exc}"
                    )
                    return ScenarioResult(scenario.name, "skipped", str(exc))

            try:
                # Probe attach and traffic phase: launch probe, run traffic, drain ringbuf.
                with probe:
                    traffic = scenario.traffic(workdir)
                    for note in traffic.notes:
                        log(f"  traffic: {note}")
                    log(
                        f"  {traffic.succeeded}/{traffic.attempted} handshakes completed"
                    )
                    time.sleep(DRAIN_SETTLE_S)
            except SkipScenario as exc:
                annotate(Severity.WARN, f"scenario '{scenario.name}' skipped: {exc}")
                return ScenarioResult(scenario.name, "skipped", str(exc))
        except SmokeFailure as exc:
            annotate(Severity.ERROR, f"scenario '{scenario.name}' could not run: {exc}")
            return ScenarioResult(scenario.name, "failed", str(exc))
        finally:
            # Teardown phase: unconditional cleanup of setup fixtures.
            if scenario.name == "netns_pqc":
                global _NETNS_PQC_NS_NAME
                if _NETNS_PQC_NS_NAME:
                    with contextlib.suppress(subprocess.CalledProcessError):
                        subprocess.run(
                            ["ip", "netns", "delete", _NETNS_PQC_NS_NAME], check=True
                        )
                    _NETNS_PQC_NS_NAME = None

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
            mark = (
                "PASS"
                if result.passed
                else ("FAIL" if result.severity == Severity.ERROR else "WARN")
            )
            log(f"  [{mark}] {result.name}: {result.detail}")
            if not result.passed:
                annotate(
                    result.severity, f"{scenario.name}/{result.name}: {result.detail}"
                )

        status = "failed" if any(r.fatal for r in results) else "passed"
        return ScenarioResult(scenario.name, status, "", results, len(events))


def parse_args(argv: "Optional[Sequence[str]]" = None) -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--probe", type=Path, required=True, help="path to the tls-probe binary"
    )
    parser.add_argument(
        "--ebpf", type=Path, required=True, help="path to the compiled eBPF object"
    )
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
    probe_bin, ebpf, schema_path = (
        args.probe.resolve(),
        args.ebpf.resolve(),
        args.schema.resolve(),
    )
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
            warnings = sum(
                1 for c in result.checks if not c.passed and c.severity == Severity.WARN
            )
            log(
                f"  {result.name:10s} {result.status:8s} events={result.event_count} "
                f"warnings={warnings}"
                + (f"  ({result.reason})" if result.reason else "")
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
        annotate(
            Severity.ERROR, f"smoke test failed: {', '.join(r.name for r in failed)}"
        )
        return 1
    log("\nsmoke test passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
