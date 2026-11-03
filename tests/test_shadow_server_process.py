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


def _stop_child(proc):
    try:
        if proc.poll() is None:
            if proc.stdin is not None:
                proc.stdin.close()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)
    finally:
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            if stream is not None:
                stream.close()


def _start_child(state_root):
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        p for p in (str(SRC), str(REPO), env.get("PYTHONPATH", "")) if p
    )
    proc = subprocess.Popen(
        [sys.executable, "-c", _CHILD, str(state_root)],
        cwd=str(REPO),
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        ready, _, _ = select.select([proc.stdout], [], [], STARTUP_TIMEOUT)
        if not ready:
            raise AssertionError("shadow child did not report READY within timeout")
        line = proc.stdout.readline().strip()
        if not line.startswith("READY "):
            stderr = proc.stderr.read() if proc.poll() is not None else ""
            raise AssertionError(f"shadow child failed to start: {line!r} {stderr}")
        port = int(line.split()[1])
    except BaseException:
        _stop_child(proc)
        raise
    return proc, port


def _post(port, body: bytes):
    import urllib.request

    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/shadow",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))


def test_replayed_capabilities_envelope_rejected_after_process_restart(tmp_path):
    state_root = tmp_path / "state"
    envelope = _envelope("capabilities")
    body = json.dumps(envelope).encode("utf-8")

    proc, port = _start_child(state_root)
    try:
        first = _post(port, body)
    finally:
        _stop_child(proc)
    assert first["status"] == "ok"
    assert first["authority"] == "descriptive_only"
    assert first["enforcement_applied"] is False
    _assert_signed_response(first)

    proc, port = _start_child(state_root)
    try:
        replay = _post(port, body)
    finally:
        _stop_child(proc)
    assert replay["status"] == "rejected"
    assert replay["reason_codes"] == ["replayed_request"]
    assert replay["authority"] == "descriptive_only"
    assert replay["enforcement_applied"] is False
    _assert_signed_response(replay)
