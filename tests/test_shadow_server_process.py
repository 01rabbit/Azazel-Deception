"""Real-subprocess regression for the shadow/replay HTTP path (loopback only).

The one-shot ``request_id`` ledger lives in the on-disk state root, so a
replayed envelope must still be rejected after the serving process has been
stopped and restarted against the same state root.
"""

import json
import os
import select
import subprocess
import sys
import tempfile
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
REQUEST_TIMEOUT = 10.0
SHUTDOWN_TIMEOUT = 10.0

# Loopback requests must never be routed through environment proxies.
_NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

# Child hosts the same ShadowReplayService/HTTP server as the dev launcher,
# with the deterministic synthetic capability provider and a fixed test key.
# It binds 127.0.0.1 on an OS-chosen port, reports it on stdout, and serves
# until its stdin reaches EOF (parent closes it) so it cannot outlive the test.
_CHILD = """
import sys
from azazel_deception.runtime.shadow_server import ShadowReplayHTTPServer, ShadowReplayService
from tests.test_shadow_server import COMPOSE, EDGE_ID, KEY, NODE_ID, PACKAGE, _synthetic_capabilities

state_root = sys.argv[1]
service = ShadowReplayService(
    node_id=NODE_ID,
    transport_key=KEY,
    allowed_edge_ids=[EDGE_ID],
    package_path=PACKAGE,
    state_root=state_root,
    compose_file=COMPOSE,
    capability_provider=_synthetic_capabilities,
)
server = ShadowReplayHTTPServer(service, host="127.0.0.1", port=0)
server.start()
print("READY %d" % server.address[1], flush=True)
try:
    sys.stdin.read()
finally:
    server.stop()
"""


def _stop_child(proc, stderr_log):
    """Close stdin, bound the wait (kill on timeout), and return (returncode, stderr text)."""
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
        for stream in (proc.stdin, proc.stdout):
            if stream is not None:
                stream.close()
    returncode = proc.returncode
    stderr_log.seek(0)
    stderr_text = stderr_log.read()
    stderr_log.close()
    return returncode, stderr_text


def _start_child(state_root):
    """Start a child serving process; return (proc, port, stderr_log)."""
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        p for p in (str(SRC), str(REPO), env.get("PYTHONPATH", "")) if p
    )
    # Per-process stderr file: never an undrained PIPE, read only after exit.
    stderr_log = tempfile.TemporaryFile(mode="w+", encoding="utf-8")
    proc = subprocess.Popen(
        [sys.executable, "-c", _CHILD, str(state_root)],
        cwd=str(REPO),
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=stderr_log,
        text=True,
    )
    try:
        ready, _, _ = select.select([proc.stdout], [], [], STARTUP_TIMEOUT)
        if not ready:
            raise AssertionError("shadow child did not report READY within timeout")
        line = proc.stdout.readline().strip()
        if not line.startswith("READY "):
            raise AssertionError(f"shadow child failed to start: {line!r}")
        port = int(line.split()[1])
    except BaseException as exc:
        _, stderr_text = _stop_child(proc, stderr_log)
        if isinstance(exc, AssertionError):
            raise AssertionError(f"{exc}; child stderr:\n{stderr_text}") from None
        raise
    return proc, port, stderr_log


def _post(port, body: bytes):
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/shadow",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with _NO_PROXY_OPENER.open(request, timeout=REQUEST_TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))


def test_replayed_capabilities_envelope_rejected_after_process_restart(tmp_path):
    state_root = tmp_path / "state"
    envelope = _envelope("capabilities")
    body = json.dumps(envelope).encode("utf-8")

    proc, port, stderr_log = _start_child(state_root)
    first_pid = proc.pid
    try:
        first = _post(port, body)
    finally:
        first_rc, first_stderr = _stop_child(proc, stderr_log)
    assert first_rc == 0, (
        f"first shadow child (pid {first_pid}) did not exit cleanly: "
        f"returncode={first_rc}; child stderr:\n{first_stderr}"
    )
    assert first["status"] == "ok", f"first response status: {first!r}"
    assert first["authority"] == "descriptive_only", f"first response: {first!r}"
    assert first["enforcement_applied"] is False, f"first response: {first!r}"
    _assert_signed_response(first)

    proc, port, stderr_log = _start_child(state_root)
    second_pid = proc.pid
    try:
        replay = _post(port, body)
    finally:
        second_rc, second_stderr = _stop_child(proc, stderr_log)
    assert second_rc == 0, (
        f"second shadow child (pid {second_pid}) did not exit cleanly: "
        f"returncode={second_rc}; child stderr:\n{second_stderr}"
    )
    assert first_pid != second_pid, (
        f"restart reused the same process pid {first_pid}; expected a new process"
    )
    assert replay["status"] == "rejected", f"replay response: {replay!r}"
    assert replay["reason_codes"] == ["replayed_request"], f"replay response: {replay!r}"
    assert replay["authority"] == "descriptive_only", f"replay response: {replay!r}"
    assert replay["enforcement_applied"] is False, f"replay response: {replay!r}"
    _assert_signed_response(replay)
