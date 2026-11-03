"""#55 real-consumer interop: pinned Azazel-MIO and Azazel-Knowledge.

Gated. These run only when `AZAZEL_DECEPTION_MIO_INTEROP=1` and the pieces
below are provided; a skip is *not* a pass (scripts/ci/assert_executed.py
rejects a report containing any). `scripts/dev/mio_feedback_interop.sh`
prepares everything and runs this file.

Environment
  AZAZEL_DECEPTION_MIO_INTEROP=1        enable (both suites)
  (azazel_mio must be importable: the script installs the pinned commit)
  AZAZEL_DECEPTION_KNOWLEDGE_PYTHON     python of a separate venv with Knowledge[api]
  AZAZEL_DECEPTION_KNOWLEDGE_SRC        extracted Knowledge source dir (config/, azctl)

The test process provisions, starts (127.0.0.1, free port), drains and stops its own
Knowledge server; pointing it at an already-running one is not supported because
the idempotence check reads the store.

Knowledge is private: nothing here prints its code or logs; only endpoint
names and counts are asserted.
"""

from __future__ import annotations

import copy
import json
import os
import re
import socket
import sqlite3
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from azazel_deception.runtime.effect_projection import accept_defensive_effect_ref
from azazel_deception.runtime.mio_feedback import (
    accept_mio_objective,
    admit_objective,
    bind_reference_chain,
    bound_observer,
    build_feedback_bundle,
    knowledge_ingest_payload,
    mio_deception_context,
    verify_feedback_bundle,
)
from tests._mio_feedback_support import (
    CANARY,
    INJECTION_TEXT,
    SURFACE,
    World,
    edge_effect_payload,
    objective_payload,
    utcnow,
)
from datetime import timedelta

pytestmark = pytest.mark.skipif(
    os.environ.get("AZAZEL_DECEPTION_MIO_INTEROP") != "1",
    reason="requires AZAZEL_DECEPTION_MIO_INTEROP=1 (see module docstring)",
)

EXPECTED = ("interaction_log", "process_events")
MAX_AGE = 300.0


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        pytest.fail(f"{name} must be set when AZAZEL_DECEPTION_MIO_INTEROP=1")
    return value


@pytest.fixture
def scenario(tmp_path, monkeypatch):
    """One static scenario run through the real gates; returns (world, chain, bundle)."""

    world = World(tmp_path, monkeypatch)
    decision_id, plan, signed = world.activate()
    now = utcnow()
    admitted = admit_objective(
        accept_mio_objective(objective_payload()), signed,
        authenticator=world.authenticator, now=now,
    )
    chain = bind_reference_chain(
        admitted=admitted, signed_activation_decision=signed,
        defensive_effect_ref=accept_defensive_effect_ref(edge_effect_payload(decision_id, now)),
        adapter=world.adapter, environment_id=world.environment_id, now=utcnow(),
    )
    observer = bound_observer(world.adapter, chain, world.package, plan)
    observer.record(observation_class="interaction", surface="service")
    observer.record(
        observation_class="reaction", surface="credential_lure",
        reaction_kind="authenticate", untrusted_text=INJECTION_TEXT,
    )
    bundle = build_feedback_bundle(
        world.adapter, chain, now=utcnow(), max_age=MAX_AGE,
        expected_telemetry=EXPECTED, observed_telemetry=EXPECTED, mechanism=None,
        isolation_assertion_refs=("isolation-net-none",), active_surface_refs=(SURFACE,),
    )
    return world, chain, bundle


# =========================== MIO (Azazel-MIO 7a35288) ======================


def test_mio_context_frame_and_no_model_handoff(scenario):
    from azazel_mio.contracts import MioDeceptionContext
    from azazel_mio.frame_builder import MioSituationFrameBuilder
    from azazel_mio.handoff import build_no_model_handoff

    world, chain, bundle = scenario
    context = MioDeceptionContext.coerce(mio_deception_context(bundle))
    assert context is not None, "MIO refused the Deception context (coerce -> None)"
    assert context.environment_id == world.environment_id
    assert context.node_id == chain.node_id
    assert context.package_id == chain.package_id
    assert context.lifecycle_state in {"active", "provisioning", "unknown"}

    builder = MioSituationFrameBuilder()
    frame = builder.build(
        events=[], noc_evaluation={}, soc_evaluation={},
        current_defensive_state="OBSERVE", mission="az06-conformance",
        trace_id="trace-55", frame_id="frame-55",
        created_at=utcnow().isoformat().replace("+00:00", "Z"),
        deception_context=context.to_dict(),
    )
    assert frame.deception_status == "available"

    # no model anywhere in this process: the handoff is built from the frame alone
    handoff = build_no_model_handoff(frame, reason="dependency_unavailable")
    payload = handoff.to_dict()
    assert payload["model_contribution"] == "none"
    assert payload["dependency_status"]["deception"] == "available"
    assert payload["dependency_status"]["knowledge"] != "available"  # Knowledge absent
    text = json.dumps(payload)
    assert CANARY not in text and "IGNORE PREVIOUS" not in text


def test_mio_frame_without_deception_context_still_hands_off(scenario):
    from azazel_mio.frame_builder import MioSituationFrameBuilder
    from azazel_mio.handoff import build_no_model_handoff

    frame = MioSituationFrameBuilder().build(
        events=[], noc_evaluation={}, soc_evaluation={},
        current_defensive_state="OBSERVE", mission="az06-conformance",
        trace_id="trace-55", frame_id="frame-56",
        created_at=utcnow().isoformat().replace("+00:00", "Z"),
    )
    payload = build_no_model_handoff(frame, reason="dependency_unavailable").to_dict()
    assert payload["dependency_status"]["deception"] != "available"
    assert payload["model_contribution"] == "none"


def test_mio_refuses_a_context_with_an_address_in_it(scenario):
    """MIO's own grammar is the second guard; a leaked IP must not coerce."""

    from azazel_mio.contracts import MioDeceptionContext

    _, _, bundle = scenario
    context = dict(mio_deception_context(bundle))
    context["node_id"] = "10.1.2.3"
    coerced = MioDeceptionContext.coerce(context)
    assert coerced is None or coerced.node_id == ""


# ====================== Knowledge (Azazel-Knowledge 6b590f3) ===============


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class KnowledgeServer:
    def __init__(self, workdir: Path) -> None:
        self.python = _required("AZAZEL_DECEPTION_KNOWLEDGE_PYTHON")
        self.src = Path(_required("AZAZEL_DECEPTION_KNOWLEDGE_SRC"))
        self.root = workdir / "knowledge-root"
        self.env = {
            **os.environ,
            "AZAZEL_ROOT": str(self.root),
            "AZAZEL_CONFIG_DIR": str(self.src / "config"),
            "PYTHONNOUSERSITE": "1",
        }
        for key in ("PYTHONPATH", "VIRTUAL_ENV"):
            self.env.pop(key, None)
        self.port = _free_port()
        self.proc: subprocess.Popen | None = None
        self.token = ""
        self.log = workdir / "knowledge-uvicorn.log"

    def _run(self, *args: str) -> str:
        done = subprocess.run(
            [self.python, *args], cwd=self.src, env=self.env,
            capture_output=True, text=True, timeout=120, check=False,
        )
        assert done.returncode == 0, f"knowledge helper failed rc={done.returncode}"
        return done.stdout

    def provision(self) -> None:
        self._run("azctl", "provision", "--root", str(self.root))
        out = self._run(
            "azctl", "client", "add", "--root", str(self.root),
            "--key-id", "dec55", "--scopes", "ingest,read",
        )
        match = re.search(r"token \(shown once\):\s*(\S+)", out)
        assert match, "could not obtain a client token"
        self.token = match.group(1)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> None:
        assert self.proc is None or self.proc.poll() is not None
        handle = self.log.open("ab")
        self.proc = subprocess.Popen(
            [self.python, "-m", "uvicorn", "azazel_knowledge.api.app:app",
             "--host", "127.0.0.1", "--port", str(self.port)],
            cwd=self.src, env=self.env, stdout=handle, stderr=handle,
        )
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            assert self.proc.poll() is None, "knowledge uvicorn exited during startup"
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.5).close()
                return
            except OSError:
                time.sleep(0.2)
        raise AssertionError("knowledge uvicorn did not start")

    def stop(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)

    def drain(self) -> None:
        self._run(
            "-m", "azazel_knowledge.worker", "--root", str(self.root),
            "--config-dir", str(self.src / "config"), "--once",
        )

    def row_count(self) -> int:
        conn = sqlite3.connect(self.root / "data" / "db" / "local.db")
        try:
            return conn.execute("SELECT COUNT(*) FROM deception_observation").fetchone()[0]
        finally:
            conn.close()

    def post(self, payload: dict) -> tuple[int, dict | None]:
        request = urllib.request.Request(
            f"{self.url}/v1/deception-observations",
            data=json.dumps(payload).encode(),
            headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, json.loads(response.read() or b"null")
        except urllib.error.HTTPError as exc:
            return exc.code, None


@pytest.fixture
def knowledge(tmp_path):
    server = KnowledgeServer(tmp_path)
    server.provision()
    server.start()
    try:
        yield server
    finally:
        server.stop()


def test_knowledge_accepts_ingests_and_is_idempotent_on_resend(scenario, knowledge):
    _, _, bundle = scenario
    payload = knowledge_ingest_payload(bundle)
    assert len(payload["items"]) == 2

    status, body = knowledge.post(payload)
    assert status == 202 and body and body.get("batch_id")
    knowledge.drain()
    assert knowledge.row_count() == 2

    # the same observations again: accepted at the door, not duplicated in the store
    status, _ = knowledge.post(copy.deepcopy(payload))
    assert status == 202
    knowledge.drain()
    assert knowledge.row_count() == 2

    # nothing the attacker typed reached the stored rows
    conn = sqlite3.connect(knowledge.root / "data" / "db" / "local.db")
    try:
        stored = json.dumps(conn.execute("SELECT * FROM deception_observation").fetchall())
    finally:
        conn.close()
    assert CANARY not in stored and "IGNORE PREVIOUS" not in stored


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p["items"][0].update({"deception_succeeded": True}),
        lambda p: p["items"][0].update({"observation_class": "success"}),
        lambda p: p["items"][0].update({"surface": "not-a-surface"}),
        lambda p: p["items"][0].pop("environment_id"),
        lambda p: p.update({"items": ["not-an-object"]}),
    ],
    ids=["verdict_field", "bad_class", "bad_surface", "missing_environment", "non_object_item"],
)
def test_knowledge_rejects_tampered_payload_with_422(scenario, knowledge, mutate):
    _, _, bundle = scenario
    payload = knowledge_ingest_payload(bundle)
    mutate(payload)
    status, _ = knowledge.post(payload)
    assert status == 422
    knowledge.drain()
    assert knowledge.row_count() == 0


def test_knowledge_unavailable_keeps_evidence_and_delivery_is_incomplete(scenario, knowledge):
    world, chain, bundle = scenario
    payload = knowledge_ingest_payload(bundle)
    knowledge.stop()

    delivered = True
    try:
        knowledge.post(payload)
    except (urllib.error.URLError, ConnectionError, OSError):
        delivered = False
    assert delivered is False, "delivery must be reported incomplete while Knowledge is down"

    # Deception's own evidence is untouched and still verifies
    assert world.adapter.verify_evidence(world.environment_id) is True
    again = build_feedback_bundle(
        world.adapter, chain, now=utcnow(), max_age=MAX_AGE,
        expected_telemetry=EXPECTED, observed_telemetry=EXPECTED, mechanism=None,
        isolation_assertion_refs=("isolation-net-none",), active_surface_refs=(SURFACE,),
    )
    verify_feedback_bundle(
        again, expected_chain=chain, state=world.adapter.state, now=utcnow(), max_age=MAX_AGE
    )
    assert knowledge_ingest_payload(again)["items"] == payload["items"]

    # once Knowledge returns, the retained evidence is deliverable exactly once
    knowledge.start()
    status, _ = knowledge.post(knowledge_ingest_payload(again))
    assert status == 202
    knowledge.drain()
    assert knowledge.row_count() == 2
