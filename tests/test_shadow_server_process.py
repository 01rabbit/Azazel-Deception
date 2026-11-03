"""Real-subprocess regression for the shadow/replay HTTP path (loopback only).

The one-shot ``request_id`` ledger lives in the on-disk state root, so a
replayed envelope must still be rejected after the serving process has been
stopped and restarted against the same state root.
"""

import json
import os
import subprocess
import sys
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
# Generous bound: this runs after the full suite on constrained macOS CI.
STARTUP_TIMEOUT = 120.0
STARTUP_POLL_INTERVAL = 0.05
REQUEST_TIMEOUT = 10.0
SHUTDOWN_TIMEOUT = 10.0
NO_STAGE_REPORTED = "<no stage reported>"
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
# argv[3] is a per-child STAGE file: the child atomically overwrites it with
# its progress marker at each milestone so a startup timeout can report how
# far the child got. stdout and stderr both go to a per-child log file (never
# an undrained PIPE).
_CHILD = """
import os
import sys

stage_path = sys.argv[3]


def _stage(name):
    tmp = stage_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(name + "\\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, stage_path)


_stage("pre-imports")

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
_stage("imports-done-service-created")
server = ShadowReplayHTTPServer(service, host="127.0.0.1", port=0)
server.start()
tmp_path = ready_path + ".tmp"
with open(tmp_path, "w", encoding="utf-8") as fh:
    fh.write("%%d\\n" %% server.address[1])
    fh.flush()
    os.fsync(fh.fileno())
os.replace(tmp_path, ready_path)
_stage("server-started-ready-written")
try:
    sys.stdin.read()
finally:
    server.stop()
""" % (TEST_MAX_REQUEST_AGE_SECONDS,)


def _read_log(log_path):
    """Return everything the child has written to its log so far.

    Opens an independent file handle on every call. The parent never holds the
    writer's file description, so reads cannot share an offset with the child.
    """
    with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _read_stage(stage_path):
    """Return the last stage the child reported, or a marker if none yet."""
    try:
        text = Path(stage_path).read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return NO_STAGE_REPORTED
    return text or NO_STAGE_REPORTED


def _stop_child(proc, log_path):
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
    return returncode, _read_log(log_path)


def _start_child(tmp_path, state_root, label):
    """Start a child serving process; return (proc, port, log_path).

    Readiness is signalled through a per-child READY file written only after
    server.start(). The parent polls it against a monotonic deadline and fails
    fast if the child exits during startup. On timeout the error names the
    last stage the child completed.
    """
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        p for p in (str(SRC), str(REPO), env.get("PYTHONPATH", "")) if p
    )
    ready_path = Path(tmp_path) / f"ready-{label}.txt"
    stage_path = Path(tmp_path) / f"stage-{label}.txt"
    # Named per-child log receives both stdout and stderr: never an undrained PIPE.
    log_path = Path(tmp_path) / f"child-{label}.log"
    # The parent closes its writer handle right after Popen; the child keeps the
    # inherited descriptor. All parent reads go through _read_log's own handle.
    with open(log_path, "w", encoding="utf-8") as log_out:
        proc = subprocess.Popen(
            [sys.executable, "-c", _CHILD, str(state_root), str(ready_path), str(stage_path)],
            cwd=str(REPO),
            env=env,
            stdin=subprocess.PIPE,
            stdout=log_out,
            stderr=log_out,
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
                    f"shadow child exited during startup: returncode={proc.returncode}; "
                    f"last stage: {_read_stage(stage_path)}"
                )
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"shadow child did not report READY within {STARTUP_TIMEOUT}s; "
                    f"last stage: {_read_stage(stage_path)}"
                )
            time.sleep(STARTUP_POLL_INTERVAL)
    except BaseException as exc:
        _, child_text = _stop_child(proc, log_path)
        if isinstance(exc, AssertionError):
            raise AssertionError(f"{exc}; child output:\n{child_text}") from None
        raise
    return proc, port, log_path


def _post(port, body: bytes, log_path):
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
        child_output = _read_log(log_path)
        raise AssertionError(
            f"POST /shadow to 127.0.0.1:{port} failed: {exc!r}; "
            f"child output:\n{child_output}"
        ) from exc


def test_replayed_capabilities_envelope_rejected_after_process_restart(tmp_path):
    state_root = tmp_path / "state"
    envelope = _envelope("capabilities")
    body = json.dumps(envelope).encode("utf-8")

    proc, port, log_path = _start_child(tmp_path, state_root, "first")
    first_pid = proc.pid
    try:
        first = _post(port, body, log_path)
    finally:
        first_rc, first_stderr = _stop_child(proc, log_path)
    assert first_rc == 0, (
        f"first shadow child (pid {first_pid}) did not exit cleanly: "
        f"returncode={first_rc}; child output:\n{first_stderr}"
    )
    assert first["status"] == "ok", f"first response status: {first!r}"
    assert first["authority"] == "descriptive_only", f"first response: {first!r}"
    assert first["enforcement_applied"] is False, f"first response: {first!r}"
    _assert_signed_response(first)

    proc, port, log_path = _start_child(tmp_path, state_root, "second")
    second_pid = proc.pid
    try:
        replay = _post(port, body, log_path)
    finally:
        second_rc, second_stderr = _stop_child(proc, log_path)
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
