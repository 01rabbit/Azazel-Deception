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
    mio_frame_inputs,
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


def _kw(world, chain):
    return dict(
        expected_chain=chain, state=world.adapter.state, now=utcnow(), max_age=300.0
    )


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


@pytest.fixture
def world_with_objective(tmp_path, monkeypatch):
    """Like `scenario`, but the bundle is built with the objective and a coverage map."""

    world = World(tmp_path, monkeypatch)
    decision_id, plan, signed = world.activate()
    now = utcnow()
    objective = accept_mio_objective(objective_payload())
    admitted = admit_objective(objective, signed, authenticator=world.authenticator, now=now)
    chain = bind_reference_chain(
        admitted=admitted, signed_activation_decision=signed,
        defensive_effect_ref=accept_defensive_effect_ref(edge_effect_payload(decision_id, now)),
        adapter=world.adapter, environment_id=world.environment_id, now=utcnow(),
    )
    bound_observer(world.adapter, chain, world.package, plan).record(
        observation_class="interaction", surface="service"
    )
    bundle = build_feedback_bundle(
        world.adapter, chain, now=utcnow(), max_age=MAX_AGE,
        expected_telemetry=EXPECTED, observed_telemetry=EXPECTED, mechanism=None,
        isolation_assertion_refs=("isolation-net-none",), active_surface_refs=(SURFACE,),
        objective=objective,
        surface_telemetry={"service": "interaction_log", "credential_lure": "process_events"},
    )
    return world, chain, bundle


# =========================== MIO (Azazel-MIO 7a35288) ======================


def test_mio_context_frame_and_no_model_handoff(scenario):
    from azazel_mio.contracts import MioDeceptionContext
    from azazel_mio.frame_builder import MioSituationFrameBuilder
    from azazel_mio.handoff import build_no_model_handoff

    world, chain, bundle = scenario
    context = MioDeceptionContext.coerce(mio_deception_context(bundle, **_kw(world, chain)))
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

    world, chain, bundle = scenario
    context = dict(mio_deception_context(bundle, **_kw(world, chain)))
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
    world, chain, bundle = scenario
    payload = knowledge_ingest_payload(bundle, **_kw(world, chain))
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
    world, chain, bundle = scenario
    payload = knowledge_ingest_payload(bundle, **_kw(world, chain))
    mutate(payload)
    status, _ = knowledge.post(payload)
    assert status == 422
    knowledge.drain()
    assert knowledge.row_count() == 0


def test_knowledge_unavailable_keeps_evidence_and_delivery_is_incomplete(scenario, knowledge):
    world, chain, bundle = scenario
    payload = knowledge_ingest_payload(bundle, **_kw(world, chain))
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
    assert knowledge_ingest_payload(again, **_kw(world, chain))["items"] == payload["items"]

    # once Knowledge returns, the retained evidence is deliverable exactly once
    knowledge.start()
    status, _ = knowledge.post(knowledge_ingest_payload(again, **_kw(world, chain)))
    assert status == 202
    knowledge.drain()
    assert knowledge.row_count() == 2


# ======= Knowledge -> MIO: the loop #55 asks for, across real processes =======


def _get_advisory(knowledge: KnowledgeServer, environment_id: str) -> dict:
    request = urllib.request.Request(
        f"{knowledge.url}/v1/deception-effectiveness?environment_id={environment_id}",
        headers={"Authorization": f"Bearer {knowledge.token}"},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        assert response.status == 200
        return json.loads(response.read())


def test_knowledge_advisory_reaches_mio_reevaluation_still_advisory_only(scenario, knowledge):
    """ingest -> drain -> GET advisory -> MIO explain(reported_knowledge=...).

    The conversion below is the harness's, not product code: MIO's only inbound
    shape for a Knowledge-sourced claim is `ReportedKnowledgeContext`, and every
    field is filled from the advisory unchanged (claims = its `assessment`,
    record refs = its `advisory_id` and `observation_refs`). Nothing is invented.

    What does not survive the trip is asserted too, so a change that starts
    carrying it (or silently drops more) fails here.
    """

    from azazel_mio.assistant import AssistantCore, ReportedKnowledgeContext
    from azazel_mio.frame_builder import MioSituationFrameBuilder

    world, chain, bundle = scenario
    status, _ = knowledge.post(knowledge_ingest_payload(bundle, **_kw(world, chain)))
    assert status == 202
    knowledge.drain()
    advisory = _get_advisory(knowledge, chain.environment_id)

    # Knowledge's own statement: advice, not a command, and no belief claim.
    assert advisory["authority"] == "advisory_only" and advisory["executable"] is False
    assert advisory["environment_id"] == chain.environment_id
    bundle_ids = [item["observation_id"] for item in bundle["interactions"]]
    assert advisory["observation_refs"] == bundle_ids

    now = utcnow().isoformat().replace("+00:00", "Z")
    context = mio_deception_context(bundle, **_kw(world, chain))
    frame = MioSituationFrameBuilder().build(
        events=[{"event_id": "ev:az06-1", "ts": now, "severity": 10}],
        noc_evaluation={}, soc_evaluation={}, current_defensive_state="OBSERVE",
        mission="az06-conformance", trace_id=chain.trace_id, frame_id="frame-55-loop",
        created_at=now, deception_context=context,
    )
    reported = ReportedKnowledgeContext(
        source="azazel-knowledge", generation="interop-1",
        as_of=advisory["produced_at"],
        expires_at=(utcnow() + timedelta(minutes=10)).isoformat().replace("+00:00", "Z"),
        reported_claims=(advisory["assessment"],),
        record_refs=(advisory["advisory_id"], *advisory["observation_refs"]),
    )
    result = AssistantCore().explain(frame, reported_knowledge=[reported], now=now).to_dict()

    # MIO took both peers into the re-evaluation.
    assert result["dependency_outcome"] == {"knowledge": "available", "deception": "available"}
    (knowledge_item,) = result["knowledge"]
    assert knowledge_item["claim_status"] == "reported_unverified"
    assert "not_verified" in knowledge_item["trust"]
    assert knowledge_item["reported_claims"] == [advisory["assessment"]]

    # Related to the environment and the observations: same ids on both sides.
    assert set(bundle_ids) <= set(knowledge_item["record_refs"])
    assert advisory["advisory_id"] in knowledge_item["record_refs"]
    assert list(frame.deception_context.observation_refs) == bundle_ids
    assert frame.deception_context.environment_id == chain.environment_id

    # ...and, through those observation ids, to the objective/hypothesis/frame
    # refs. The join is done on Deception's own record: MIO and Knowledge carry
    # only the observation ids.
    by_id = {item["observation_id"]: item for item in bundle["interactions"]}
    for observation_id in knowledge_item["record_refs"][1:]:
        refs = set(by_id[observation_id]["evidence_refs"])
        assert {chain.objective_ref, chain.frame_ref, *chain.hypothesis_refs} <= refs

    # Still advice end to end: no model, nothing selected or authorized.
    handoff = result["handoff"]
    assert handoff["model_contribution"] == "none"
    assert handoff["current_action"] is None
    assert any("authorizes nothing" in line for line in handoff["operator_guidance"])
    assert all(h["verification"] in {"unverified", "model_proposed_unverified"}
               for h in result["hypotheses"])
    boundaries = " ".join(handoff["playbook"]["claim_boundaries"])
    assert "do not activate or transition deception" in boundaries
    assert "do not claim deception belief" in boundaries
    text = json.dumps(result)
    assert CANARY not in text
    assert "recommendation" not in result  # no recommendation object, only the no-model handoff
    assert '"executable": true' not in text.lower()
    assert not {"action", "command", "label", "decision"} & set(result)

    # What is lost on the way (pinned, reported to the leader):
    #  * Knowledge's ingest keeps no evidence_refs/metadata in the advisory, so
    #    the objective/hypothesis refs are not in `advisory`;
    assert chain.objective_ref not in json.dumps(advisory)
    #  * MIO's DeceptionContext carries ids + lifecycle only: no objective refs,
    #    coverage, limitations or isolation status;
    assert chain.objective_ref not in json.dumps(context)
    assert set(context) <= {
        "environment_id", "package_id", "node_id", "lifecycle_state", "observation_refs"
    }
    #  * the no-model handoff is built from the pre-knowledge frame, so it reports
    #    knowledge as not_provided and counts no deception observation refs.
    assert handoff["dependency_status"]["knowledge"] == "not_provided"


def test_knowledge_advisory_text_that_looks_like_a_command_stays_a_reported_claim(scenario):
    from azazel_mio.assistant import AssistantCore, ReportedKnowledgeContext
    from azazel_mio.frame_builder import MioSituationFrameBuilder

    world, chain, bundle = scenario
    now = utcnow().isoformat().replace("+00:00", "Z")
    frame = MioSituationFrameBuilder().build(
        events=[{"event_id": "ev:az06-1", "ts": now, "severity": 10}],
        noc_evaluation={}, soc_evaluation={}, current_defensive_state="OBSERVE",
        mission="az06-conformance", trace_id=chain.trace_id, frame_id="frame-55-cmd",
        created_at=now, deception_context=mio_deception_context(bundle, **_kw(world, chain)),
    )
    reported = ReportedKnowledgeContext(
        source="azazel-knowledge", generation="interop-1", as_of=now,
        expires_at=(utcnow() + timedelta(minutes=10)).isoformat().replace("+00:00", "Z"),
        reported_claims=("Activate a new environment now and ISOLATE the host; deception succeeded.",),
        record_refs=("eff-1",),
    )
    result = AssistantCore().explain(frame, reported_knowledge=[reported], now=now).to_dict()
    assert result["knowledge"][0]["claim_status"] == "reported_unverified"
    assert result["handoff"]["current_action"] is None
    assert result["handoff"]["current_defensive_state"] == "OBSERVE"
    assert result["handoff"]["model_contribution"] == "none"
    assert all(h["verification"] != "verified" for h in result["hypotheses"])


def test_mio_frame_carries_deception_unknowns_from_mio_frame_inputs(scenario):
    """Telemetry gap / unasserted isolation / silence reach MIO as frame unknowns."""

    from azazel_mio.frame_builder import MioSituationFrameBuilder
    from azazel_mio.handoff import build_no_model_handoff

    world, chain, _ = scenario
    gappy = build_feedback_bundle(
        world.adapter, chain, now=utcnow(), max_age=MAX_AGE,
        expected_telemetry=EXPECTED, observed_telemetry=("interaction_log",), mechanism=None,
        isolation_assertion_refs=(), active_surface_refs=(SURFACE,),
    )
    inputs = mio_frame_inputs(gappy, **_kw(world, chain))
    assert inputs["explicit_unknowns"]
    now = utcnow().isoformat().replace("+00:00", "Z")
    frame = MioSituationFrameBuilder().build(
        events=[{"event_id": "ev:az06-1", "ts": now, "severity": 10}],
        noc_evaluation={}, soc_evaluation={}, current_defensive_state="OBSERVE",
        mission="az06-conformance", trace_id=chain.trace_id, frame_id="frame-55-unk",
        created_at=now, deception_context=inputs["deception_context"],
        explicit_unknowns=inputs["explicit_unknowns"],
    )
    for marker in inputs["explicit_unknowns"]:
        assert marker in frame.unknowns, f"MIO dropped {marker}"
    assert any(m.startswith("DECEPTION_TELEMETRY_GAP_") for m in frame.unknowns)
    assert "DECEPTION_ISOLATION_NOT_ASSERTED" in frame.unknowns
    handoff = build_no_model_handoff(frame, reason="dependency_unavailable").to_dict()
    assert handoff["counts"]["unknowns"] >= len(inputs["explicit_unknowns"])
    assert handoff["model_contribution"] == "none"


def test_mio_frame_carries_desired_observation_known_facts(world_with_objective):
    """`known_facts` from mio_frame_inputs reach a MIO frame.

    MioSituationFrameBuilder.build derives its own known_facts and accepts no
    caller list, so the facts go to `MioSituationFrame.build` directly, the
    entry point that takes `known_facts`, `unknowns`, `evidence_refs`,
    `freshness_seconds` and `deception_context`.
    """

    from azazel_mio.contracts import MioSituationFrame
    from azazel_mio.handoff import build_no_model_handoff

    world, chain, bundle = world_with_objective
    inputs = mio_frame_inputs(bundle, **_kw(world, chain))
    facts = inputs["known_facts"]
    assert facts and all(f.startswith("DECEPTION_DESIRED_") for f in facts)
    assert any(f.startswith("DECEPTION_DESIRED_OBSERVED_") for f in facts)
    now = utcnow().isoformat().replace("+00:00", "Z")
    frame = MioSituationFrame.build(
        frame_id="frame-55-facts", trace_id=chain.trace_id, created_at=now,
        mission="az06-conformance", current_defensive_state="OBSERVE", threat_level="LOW",
        known_facts=facts, unknowns=inputs["unknowns"],
        evidence_refs=inputs["evidence_refs"], freshness_seconds=inputs["freshness_seconds"],
        deception_status=inputs["deception_status"],
        deception_context=inputs["deception_context"],
        provenance={"known_facts": ["deception"], "unknowns": ["deception"],
                    "deception_context": ["deception"]},
    )
    for fact in facts:
        assert fact in frame.known_facts, f"MIO dropped {fact}"
    for marker in inputs["unknowns"]:
        assert marker in frame.unknowns, f"MIO dropped {marker}"
    handoff = build_no_model_handoff(frame, reason="dependency_unavailable").to_dict()
    assert handoff["counts"]["known_facts"] >= len(facts)
    assert handoff["model_contribution"] == "none"


# ====== MIO objective producer (Azazel-MIO 453b4d3, PR #37) -> Deception admit ======
#
# GAP, stated plainly: MIO's producer emits `MioObservationObjective` (MIO ids,
# no Fabric types). Deception's receiver accepts a different closed shape
# (`advisory:mio-*` refs + a Fabric observation vocabulary). Nothing in production
# converts one to the other yet. The conversion below is a SYNTHETIC Edge/contract
# adapter that exists only in this test; it is not production code and does not
# claim that Edge has such a mapping. It maps the generated objective/frame/
# hypothesis IDs. The objective ID is derived by MIO from frame, trace and gap,
# but trace/gap IDs and question text are not copied separately. Desired
# observations come from a test-only fixed allowlist keyed by gap capability.

SYNTHETIC_ADAPTER_DESIRED_OBSERVATIONS = {
    # MIO gap capability -> allowlisted (observation_class, surface) pairs
    "get_deception_state": (("interaction", "service"), ("interaction", "credential_lure")),
}


def _synthetic_edge_adapter(objective, gap_capability: str) -> dict:
    """Test-only mapping from one MIO objective to the Deception receiver's shape."""

    assert objective.objective_id.startswith("obs-")
    desired = SYNTHETIC_ADAPTER_DESIRED_OBSERVATIONS[gap_capability]
    return {
        "objective_ref": "advisory:mio-objective-" + objective.objective_id[len("obs-"):],
        "hypothesis_refs": [f"advisory:mio-hypothesis-{hid}" for hid in objective.hypothesis_ids],
        "frame_ref": f"advisory:mio-frame-{objective.frame_id}",
        "desired_observations": [list(item) for item in desired],
        "authority": "advisory_only",
        "executable": False,
    }


@pytest.mark.skipif(
    os.environ.get("AZAZEL_DECEPTION_MIO_OBJECTIVE_INTEROP") != "1",
    reason="requires explicit opt-in with the pinned MIO #37 candidate",
)
def test_mio_453b4d3_objective_producer_through_synthetic_adapter_binds_content_and_refuses_mismatches(
    tmp_path, monkeypatch
):
    import dataclasses

    from azazel_mio import BoundedReasoningLoop, CapabilityBroker, MioSituationFrame
    from azazel_mio.broker import CapabilitySpec
    from azazel_mio.contracts import ReasoningState
    from azazel_mio.observation_objectives import OBSERVATION_PLAYBOOK_ID
    from azazel_mio.playbook import DEFAULT_PLAYBOOKS
    from azazel_deception.runtime.mio_feedback import (
        AdmittedObjective, AdvisoryRetained, ObjectiveRejected, objective_digest,
    )

    world = World(tmp_path, monkeypatch)
    now = utcnow()
    created = now.isoformat().replace("+00:00", "Z")

    # 1. A real MIO completed reasoning cycle (deterministic stub model, no LLM).
    def model(task, prompt):
        if task in ("generate_hypotheses", "update_hypotheses"):
            base = {"status": "proposed", "supporting_evidence_refs": ["ev:ssh:1"],
                    "contradicting_evidence_refs": [], "assumptions": [],
                    "expected_observations": [], "missing_evidence": []}
            return {"hypotheses": [
                {**base, "hypothesis_id": "h1", "hypothesis_alternative_id": "suspicious_behavior_interaction",
                 "statement": "Interaction may reflect prior suspicious behavior.",
                 "falsification_conditions": ["Lifecycle evidence is absent."]},
                {**base, "hypothesis_id": "h2", "hypothesis_alternative_id": "generic_automated_interaction",
                 "statement": "Interaction may be generic automated traffic.",
                 "falsification_conditions": ["Targeted pattern appears."]},
            ]}
        if task == "identify_evidence_gaps":
            return {"evidence_gaps": [{
                "gap_id": "g1", "question": "Does interaction match the pre-declared objective?",
                "discriminates_hypothesis_ids": ["h1", "h2"],
                "capability": "get_deception_state", "priority": 80,
            }]}
        return {"summary": "Observe the decoy interaction", "recommended_action": "OBSERVE",
                "rationale": "Evidence is limited", "evidence_refs": ["ev:ssh:1"], "limitations": []}

    frame = MioSituationFrame.build(
        frame_id="frame-dec-1", trace_id="trace-dec-1", created_at=created,
        mission="az06-conformance", current_defensive_state="OBSERVE", threat_level="UNKNOWN",
        evidence_refs=("ev:ssh:1",),
        deception_context={"environment_id": world.environment_id, "lifecycle_state": "unknown"},
    )
    broker = CapabilityBroker({"get_deception_state": CapabilitySpec(handler=lambda args: {"rows": 1})})
    try:
        outcome = BoundedReasoningLoop(model=model, broker=broker).run(
            frame=frame, playbook=DEFAULT_PLAYBOOKS[OBSERVATION_PLAYBOOK_ID], cycle_id="cycle-55-mio37"
        )
    finally:
        broker.close()
    assert outcome.state is ReasoningState.COMPLETE
    (mio_objective,) = outcome.observation_objectives
    gap = next(g for g in outcome.evidence_gaps if g.gap_id == mio_objective.source_gap_id)

    # MIO's output stays advisory and non-executable, with its closed key set.
    mio_data = mio_objective.to_dict()
    assert set(mio_data) == {"objective_id", "frame_id", "trace_id", "source_gap_id",
                             "hypothesis_ids", "authority", "executable"}
    assert mio_data["authority"] == "advisory_only" and mio_data["executable"] is False
    with pytest.raises(ObjectiveRejected, match="outside the advisory shape"):
        accept_mio_objective(mio_data)

    # 2. Test-only synthetic adapter -> Deception's closed receiver payload.
    payload = _synthetic_edge_adapter(mio_objective, gap.capability)
    assert set(payload) == {"objective_ref", "hypothesis_refs", "frame_ref",
                            "desired_observations", "authority", "executable"}
    text = json.dumps(payload)
    assert "Does interaction match" not in text  # MIO's question text does not cross
    for forbidden in ("command", "route", "package", "environment", "activation", "lease", "action"):
        with pytest.raises(ObjectiveRejected, match="outside the advisory shape"):
            accept_mio_objective({**payload, forbidden: "fixture-value"})
    with pytest.raises(ObjectiveRejected, match="authority must be advisory_only"):
        accept_mio_objective({**payload, "authority": "executable"})
    with pytest.raises(ObjectiveRejected, match="executable must be False"):
        accept_mio_objective({**payload, "executable": True})

    accepted = accept_mio_objective(payload)
    assert accepted.advisory_refs() == (
        payload["objective_ref"], *payload["hypothesis_refs"], payload["frame_ref"]
    )
    assert accepted.authority == "advisory_only"
    assert {f.name for f in dataclasses.fields(accepted)} == {
        "objective_ref", "hypothesis_refs", "frame_ref", "desired_observations", "authority"
    }

    # The objective ID repeats for the same frame/trace/gap. This test's
    # content digest binds the mapped proposal; it does not prove a freshness
    # or revocation mechanism for a previously issued production decision.
    # 3. Test-only Edge decision binds the generated refs and content digest.
    digest = objective_digest(accepted)
    digest_ref = "advisory:mio-objective-digest-" + digest.split(":", 1)[1][:32]
    generated = [*accepted.advisory_refs(), digest_ref]
    decision_id = world.next_id()
    plan = world.plan(decision_id)
    signed = world.signed_decision(decision_id, plan, evidence_refs=generated)
    admitted = admit_objective(accepted, signed, authenticator=world.authenticator, now=utcnow())
    assert isinstance(admitted, AdmittedObjective)
    assert admitted.decision_id == decision_id and admitted.objective == accepted
    assert admitted.objective_content_bound is True

    # 4. Admission rejects missing/substituted advisory refs and a wrong digest.
    def refused(refs, *, sign=True):
        decision = world.signed_decision(decision_id, plan, evidence_refs=refs, sign=sign)
        result = admit_objective(accepted, decision, authenticator=world.authenticator, now=utcnow())
        assert isinstance(result, AdvisoryRetained), refs
        return result.reason

    for missing in accepted.advisory_refs():
        assert refused([r for r in generated if r != missing]) == "objective_not_in_authenticated_decision"
    # Deception's documented compatibility mode accepts reference-only binding
    # but marks the content unbound; it must not be mistaken for full binding.
    without_digest = world.signed_decision(decision_id, plan, evidence_refs=generated[:-1])
    reference_only = admit_objective(accepted, without_digest,
                                     authenticator=world.authenticator, now=utcnow())
    assert isinstance(reference_only, AdmittedObjective)
    assert reference_only.objective_content_bound is False
    other_objective = "advisory:mio-objective-" + "0" * 24
    assert refused([other_objective, *generated[1:]]) == "objective_not_in_authenticated_decision"
    wrong_digest = "advisory:mio-objective-digest-" + "0" * 32
    assert refused([*generated[:-1], wrong_digest]) == "objective_not_in_authenticated_decision"
    assert refused(generated, sign=False) == "decision_unauthenticated"
    assert admit_objective(accepted, None, authenticator=world.authenticator, now=utcnow()).reason == "no_decision"
