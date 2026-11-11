"""Hardware-free process/canary/admission plumbing, NOT runtime isolation proof.

The child substitutes fixed loopback HTTP for Compose and synthetic verifiers
for supply-chain validation. The parent independently receives the actual HTTP
bytes and reopens the on-disk evidence; child state alone is insufficient.
"""
from __future__ import annotations

import json
import os
import select
import socket
import subprocess
import sys
import urllib.error
import urllib.request
from contextlib import contextmanager
from pathlib import Path

import pytest

from azazel_deception.runtime.observation_export import export_observations
from azazel_deception.runtime.state import RuntimeStateStore
from tests._static_canary_process import ENVIRONMENT

REPO = Path(__file__).resolve().parents[1]
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
TIMEOUT = 20


def receive(proc):
    readable, _, _ = select.select([proc.stdout], [], [], TIMEOUT)
    assert readable, "test process did not reply before deadline"
    line = proc.stdout.readline()
    assert line, f"test process closed output (exit={proc.poll()})"
    return json.loads(line)


def control(proc, action, **kwargs):
    proc.stdin.write(json.dumps({"action": action, **kwargs}) + "\n")
    proc.stdin.flush()
    return receive(proc)


@contextmanager
def child(tmp_path, *, mode="accepted", decision_id="edge-decision-1"):
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(REPO / "src"), str(REPO)])
    log = tmp_path / f"{decision_id}-{mode}.log"
    with log.open("w") as err:
        proc = subprocess.Popen(
            [sys.executable, "-m", "tests._static_canary_process", str(tmp_path / "state"), mode, decision_id],
            cwd=REPO, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=err, text=True,
        )
    try:
        yield proc, receive(proc)
    except BaseException as exc:
        raise AssertionError(f"{exc}; child log:\n{log.read_text()}") from exc
    finally:
        proc.stdin.close()
        try:
            proc.wait(timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=TIMEOUT)
            pytest.fail("test process failed to stop after stdin EOF")
        finally:
            proc.stdout.close()
        assert proc.returncode == 0, log.read_text()


def get(ready, path):
    assert ready["host"] == "127.0.0.1"
    try:
        with OPENER.open(f"http://127.0.0.1:{ready['port']}{path}", timeout=3) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def planted_path(ready):
    status, document = get(ready, "/openapi.json")
    assert status == 200
    document = json.loads(document)
    assert "servers" not in document
    path, = document["paths"]
    assert path.startswith("/__azazel_canary__/")
    return path


def assert_closed(port):
    with socket.socket() as probe:
        probe.settimeout(1)
        assert probe.connect_ex(("127.0.0.1", port)) != 0


@pytest.mark.parametrize("mode,reason", [
    ("unsigned", "failed authentication"),
    ("forged", "failed authentication"),
    ("expired", "expired"),
    ("wrong-package", "binding mismatch"),
    ("no-verifier", "verifier"),
])
def test_missing_or_invalid_admission_never_binds(tmp_path, mode, reason):
    with child(tmp_path, mode=mode) as (_, reply):
        assert reply["status"] == "refused"
        assert reply["error_type"] == "RuntimeGateError"
        assert reason in reply["reason"]
        assert reply["bind_count"] == 0
        assert reply["consumed"] is False
    assert RuntimeStateStore(tmp_path / "state").read(ENVIRONMENT) is None


def test_process_presentation_touch_export_reset_and_restart(tmp_path):
    state = RuntimeStateStore(tmp_path / "state")
    with child(tmp_path) as (proc, ready):
        assert ready["status"] == "ready" and ready["bind_count"] == 1
        assert state.read(ENVIRONMENT)["state"] == "active"
        assert ready["scope"]["surface_id"] == "intranet-web-http"
        assert control(proc, "reset-active")["error_type"] == "RuntimeGateError"
        path = planted_path(ready)  # real bytes observed by the parent process
        token = path.rsplit("/", 1)[1]
        assert get(ready, path)[0] == 204
        assert get(ready, "/__azazel_canary__/" + "x" * 43)[0] == 404
        exported = control(proc, "export")
        assert exported["chain_verified"] is True
        observations = export_observations(state, ENVIRONMENT)  # independent disk reader
        assert observations == exported["observations"] and len(observations) == 1
        assert observations[0]["metadata"]["interaction_kind"] == "follow_through_observed"
        assert "presentation:loopback" in observations[0]["evidence_refs"]
        assert token not in state.read_evidence_snapshot(ENVIRONMENT)
        assert control(proc, "reset")["listener_closed"] is True
        assert_closed(ready["port"])
        assert state.read(ENVIRONMENT) is None
        assert not control(proc, "probe", token=token)["accepted"]
        assert state.verify_evidence_chain(ENVIRONMENT)
        assert export_observations(state, ENVIRONMENT) == observations
    # Reset cannot reopen the existing one-shot activation decision ledger.
    with child(tmp_path) as (_, refused):
        assert refused["status"] == "refused" and refused["bind_count"] == 0
        assert "already consumed" in refused["reason"]
    with child(tmp_path, decision_id="edge-decision-2") as (proc, fresh):
        assert fresh["status"] == "ready"
        assert get(fresh, path)[0] == 404  # old session token is unavailable after restart
        assert planted_path(fresh) != path
        assert control(proc, "export")["observations"] == observations
        control(proc, "reset")


def test_expiry_rejects_touch_and_document_without_new_evidence(tmp_path):
    with child(tmp_path) as (proc, ready):
        path = planted_path(ready)
        assert control(proc, "expire")["clock_advanced_for_test"] is True
        assert get(ready, path)[0] == 404
        assert get(ready, "/openapi.json")[0] == 410
        assert control(proc, "export")["observations"] == []
        control(proc, "reset")


def test_parent_eof_closes_listener_without_claiming_runtime_reset(tmp_path):
    with child(tmp_path) as (_, ready):
        port = ready["port"]
        assert planted_path(ready)
    assert_closed(port)
    # EOF cleanup closes the fixture socket; it does not invent a reset event.
    state = RuntimeStateStore(tmp_path / "state")
    assert state.read(ENVIRONMENT)["state"] == "active"
    assert "reset_completed" not in state.read_evidence_snapshot(ENVIRONMENT)
