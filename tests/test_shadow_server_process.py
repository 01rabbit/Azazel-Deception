"""Real-subprocess regression for the shadow/replay HTTP path (loopback only).

The one-shot ``request_id`` ledger lives in the on-disk state root, so a
replayed envelope must still be rejected after the serving process has been
stopped and restarted against the same state root.
"""

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from tests.test_shadow_server import (
    COMPOSE,
    EDGE_ID,
    KEY,
    NODE_ID,
    PACKAGE,
    _assert_signed_response,
    _envelope,
)

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src"
STARTUP_TIMEOUT = 30.0
STARTUP_POLL_INTERVAL = 0.05
REQUEST_TIMEOUT = 10.0
SHUTDOWN_TIMEOUT = 10.0
# Test-child only: keep the freshness window far larger than any CI scheduling
# delay so the request always reaches the replay ledger. The signed request
# bytes are unchanged; only the server-side age bound differs.
TEST_MAX_REQUEST_AGE_SECONDS = 600.0

# Loopback requests must never be routed through environment proxies.
_NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

# Child hosts the same ShadowReplayService/HTTP server as the dev launcher,
# with the deterministic synthetic capability provider and a fixed test key.
# It binds 127.0.0.1 on an OS-chosen port and, only after server.start(),
# atomically writes "<port>\n" to the READY file given in argv[2]. It serves
# until its stdin reaches EOF (parent closes it) so it cannot outlive the test.
# stdout and stderr both go to a per-child log file (never an undrained PIPE).
_CHILD = """
import os
import sys
from azazel_deception.runtime.shadow_server import ShadowReplayHTTPServer, ShadowReplayService
from tests.test_shadow_server import COMPOSE, EDGE_ID, KEY, NODE_ID, PACKAGE, _synthetic_capabilities

state_root = sys.argv[1]
ready_path = sys.argv[2]
service = ShadowReplayService(
    node_id=NODE_ID,
    transport_key=KEY,
    allowed_edge_ids=[EDGE_ID],
    package_path=PACKAGE,
    state_root=state_root,
    compose_file=COMPOSE,
    max_request_age_seconds=%r,
    capability_provider=_synthetic_capabilities,
)
server = ShadowReplayHTTPServer(service, host="127.0.0.1", port=0)
server.start()
tmp_path = ready_path + ".tmp"
with open(tmp_path, "w", encoding="utf-8") as fh:
    fh.write("%%d\\n" %% server.address[1])
    fh.flush()
    os.fsync(fh.fileno())
os.replace(tmp_path, ready_path)
try:
    sys.stdin.read()
finally:
    server.stop()
""" % (TEST_MAX_REQUEST_AGE_SECONDS,)


def _read_stderr(stderr_log):
    """Return everything the child has written to its log so far (non-destructive)."""
    stderr_log.flush()
    stderr_log.seek(0)
    return stderr_log.read()


def _stop_child(proc, stderr_log):
    """Close stdin, bound the wait (kill on timeout), and return (returncode, log text)."""
    try:
        if proc.poll() is None:
            if proc.stdin is not None:
                try:
                    proc.stdin.close()
                except BrokenPipeError:
                    pass
            try:
                proc.wait(timeout=SHUTDOWN_TIMEOUT)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=SHUTDOWN_TIMEOUT)
    finally:
        if proc.stdin is not None:
            proc.stdin.close()
    returncode = proc.returncode
    stderr_text = _read_stderr(stderr_log)
    stderr_log.close()
    return returncode, stderr_text


def _start_child(tmp_path, state_root, label):
    """Start a child serving process; return (proc, port, stderr_log).

    Readiness is signalled through a per-child READY file written only after
    server.start(). The parent polls it against a monotonic deadline and fails
    fast if the child exits during startup.
    """
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        p for p in (str(SRC), str(REPO), env.get("PYTHONPATH", "")) if p
    )
    ready_path = Path(tmp_path) / f"ready-{label}.txt"
    # Per-child log file receives both stdout and stderr: never an undrained PIPE.
    log = tempfile.TemporaryFile(mode="w+", encoding="utf-8")
    proc = subprocess.Popen(
        [sys.executable, "-c", _CHILD, str(state_root), str(ready_path)],
        cwd=str(REPO),
        env=env,
        stdin=subprocess.PIPE,
        stdout=log,
        stderr=log,
        text=True,
    )
    try:
        deadline = time.monotonic() + STARTUP_TIMEOUT
        port = None
        while port is None:
            if ready_path.exists():
                text = ready_path.read_text(encoding="utf-8")
                if text.endswith("\n"):
                    port = int(text.strip())
                    break
            if proc.poll() is not None:
                raise AssertionError(
                    f"shadow child exited during startup: returncode={proc.returncode}"
                )
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"shadow child did not report READY within {STARTUP_TIMEOUT}s"
                )
            time.sleep(STARTUP_POLL_INTERVAL)
    except BaseException as exc:
        _, stderr_text = _stop_child(proc, log)
        if isinstance(exc, AssertionError):
            raise AssertionError(f"{exc}; child output:\n{stderr_text}") from None
        raise
    return proc, port, log


def _post(port, body: bytes, stderr_log):
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/shadow",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with _NO_PROXY_OPENER.open(request, timeout=REQUEST_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        child_output = _read_stderr(stderr_log)
        raise AssertionError(
            f"POST /shadow to 127.0.0.1:{port} failed: {exc!r}; "
            f"child output:\n{child_output}"
        ) from exc


def test_replayed_capabilities_envelope_rejected_after_process_restart(tmp_path):
    state_root = tmp_path / "state"
    envelope = _envelope("capabilities")
    body = json.dumps(envelope).encode("utf-8")

    proc, port, stderr_log = _start_child(tmp_path, state_root, "first")
    first_pid = proc.pid
    try:
        first = _post(port, body, stderr_log)
    finally:
        first_rc, first_stderr = _stop_child(proc, stderr_log)
    assert first_rc == 0, (
        f"first shadow child (pid {first_pid}) did not exit cleanly: "
        f"returncode={first_rc}; child output:\n{first_stderr}"
    )
    assert first["status"] == "ok", f"first response status: {first!r}"
    assert first["authority"] == "descriptive_only", f"first response: {first!r}"
    assert first["enforcement_applied"] is False, f"first response: {first!r}"
    _assert_signed_response(first)

    proc, port, stderr_log = _start_child(tmp_path, state_root, "second")
    second_pid = proc.pid
    try:
        replay = _post(port, body, stderr_log)
    finally:
        second_rc, second_stderr = _stop_child(proc, stderr_log)
    assert second_rc == 0, (
        f"second shadow child (pid {second_pid}) did not exit cleanly: "
        f"returncode={second_rc}; child output:\n{second_stderr}"
    )
    assert first_pid != second_pid, (
        f"restart reused the same process pid {first_pid}; expected a new process"
    )
    assert replay["status"] == "rejected", f"replay response: {replay!r}"
    assert replay["reason_codes"] == ["replayed_request"], f"replay response: {replay!r}"
    assert replay["authority"] == "descriptive_only", f"replay response: {replay!r}"
    assert replay["enforcement_applied"] is False, f"replay response: {replay!r}"
    _assert_signed_response(replay)
