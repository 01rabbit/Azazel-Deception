"""#55 MIO objective feedback: contract, refusals and in-process lifecycle.

Docker is not needed. The semantics under test (docs: DESIGN of #55):

* a MIO objective is advisory only; it starts, selects, extends and ends nothing
* an authenticated, one-shot, unexpired Edge decision is the only authority, and
  it names the objective in its signed `evidence_refs`
* decision / execution request / runtime materialization / observed mechanism /
  interaction / outcome / tactical assessment stay in separate keys
* silence is never evidence of safety; AZ-06 does not assess tactics
"""

from __future__ import annotations

import copy
import dataclasses
import json
import re
from datetime import datetime, timedelta, timezone

import pytest

from azazel_deception.runtime.compose import RuntimeGateError
from azazel_deception.runtime.isolation_drift import IsolationDriftObserver
from azazel_deception.runtime.mio_feedback import (
    AdmittedObjective,
    AdvisoryRetained,
    BindingRefused,
    ObjectiveRejected,
    accept_mio_objective,
    admit_objective,
    bind_reference_chain,
    bound_observer,
    build_feedback_bundle,
    knowledge_ingest_payload,
    mio_deception_context,
    mio_frame_inputs,
    objective_digest,
    reset_feedback,
    verify_feedback_bundle,
)
from azazel_deception.runtime.effect_projection import accept_defensive_effect_ref
from azazel_deception.runtime.transport import sign_decision
from azazel_deception.planner import build_placement_plan

from tests._mio_feedback_support import (
    CANARY,
    FRAME_REF,
    HYPOTHESIS_REF,
    INJECTION_TEXT,
    OBJECTIVE_REF,
    SURFACE,
    TEST_KEY,
    World,
    edge_effect_payload,
    objective_payload,
    utcnow,
)
from tests.test_runtime import _host

EXPECTED = ("interaction_log", "process_events")
MAX_AGE = 300.0


@pytest.fixture
def world(tmp_path, monkeypatch):
    return World(tmp_path, monkeypatch)


def _bind(world, *, decision_id=None, effect=None, **activate_kwargs):
    decision_id, plan, signed = world.activate(decision_id, **activate_kwargs)
    now = utcnow()
    objective = accept_mio_objective(objective_payload())
    admitted = admit_objective(
        objective, signed, authenticator=world.authenticator, now=now
    )
    assert isinstance(admitted, AdmittedObjective)
    effect = effect or accept_defensive_effect_ref(edge_effect_payload(decision_id, now))
    chain = bind_reference_chain(
        admitted=admitted,
        signed_activation_decision=signed,
        defensive_effect_ref=effect,
        adapter=world.adapter,
        environment_id=world.environment_id,
        now=utcnow(),
    )
    return decision_id, plan, signed, objective, admitted, chain


def _observer(world, chain, plan):
    package = world.package
    return bound_observer(world.adapter, chain, package, plan)


def _bundle(world, chain, **overrides):
    kwargs = dict(
        now=utcnow(),
        max_age=MAX_AGE,
        expected_telemetry=EXPECTED,
        observed_telemetry=EXPECTED,
        mechanism=None,
        isolation_assertion_refs=("isolation-net-none",),
        active_surface_refs=(SURFACE,),
    )
    kwargs.update(overrides)
    return build_feedback_bundle(world.adapter, chain, **kwargs)


def _kw(world, chain, **extra):
    return dict(
        expected_chain=chain, state=world.adapter.state, now=utcnow(), max_age=MAX_AGE, **extra
    )


def _all_text(*objects) -> str:
    return "\n".join(json.dumps(o, sort_keys=True, default=str) for o in objects)


# --- objective boundary ----------------------------------------------------


def test_valid_objective_is_accepted_as_advisory_only():
    objective = accept_mio_objective(objective_payload())
    assert objective.objective_ref == OBJECTIVE_REF
    assert objective.authority == "advisory_only"
    assert objective.hypothesis_refs == (HYPOTHESIS_REF,)
    assert objective.frame_ref == FRAME_REF
    assert ("interaction", "service") in objective.desired_observations


@pytest.mark.parametrize(
    "key,value",
    [
        ("activate", True),
        ("command", "docker run x"),
        ("shell", "sh -c id"),
        ("route", "10.0.0.0/8"),
        ("provider", "docker"),
        ("template", "municipal-linux-v1"),
        ("environment_id", "env-1"),
        ("environment_ref", "environment:env-1"),
        ("package_id", "municipal-linux-v1"),
        ("package_digest", "sha256:abc"),
        ("decision_id", "edge-activate-1"),
        ("decision_ref", "decision:edge-activate-1"),
        ("budget", {"cpu_cores": 1}),
        ("ttl", 600),
        ("extend", True),
        ("terminate", True),
    ],
)
def test_mio_payload_with_runtime_directive_is_rejected(key, value):
    with pytest.raises(ObjectiveRejected):
        accept_mio_objective(objective_payload(**{key: value}))


@pytest.mark.parametrize(
    "overrides",
    [
        {"authority": "decision"},
        {"executable": True},
        {"objective_ref": "decision:edge-activate-1"},
        {"hypothesis_refs": []},
        {"hypothesis_refs": [f"advisory:mio-hypothesis-h{i}" for i in range(9)]},
        {"desired_observations": []},
        {"desired_observations": [["interaction", "not-a-surface"]]},
        {"desired_observations": [["interaction", "service"]] * 17},
        {"frame_ref": "x" * 5000},
        {"hypothesis_refs": ["advisory:mio-hypothesis-AKIAABCDEFGHIJKLMNOP"]},
    ],
)
def test_malformed_or_oversized_objective_is_rejected(overrides):
    with pytest.raises(ObjectiveRejected):
        accept_mio_objective(objective_payload(**overrides))


def test_objective_missing_required_key_is_rejected():
    payload = objective_payload()
    del payload["frame_ref"]
    with pytest.raises(ObjectiveRejected):
        accept_mio_objective(payload)


# --- advisory retained: no decision, no activation ---------------------------


def test_mio_start_request_without_decision_is_retained_and_activates_nothing(world):
    objective = accept_mio_objective(objective_payload())
    result = admit_objective(objective, None, authenticator=world.authenticator, now=utcnow())
    assert isinstance(result, AdvisoryRetained)
    assert result.reason == "no_decision"
    assert result.exposure == "refused"
    assert result.authority == "advisory_only"
    assert result.objective == objective  # advice is kept, not discarded
    assert world.adapter.collect_status(world.environment_id)["state"] == "absent"
    assert world.adapter.state.consumed_decision_count() == 0


def test_unauthenticated_decision_is_retained(world):
    decision_id = world.next_id()
    plan = world.plan(decision_id)
    unsigned = world.signed_decision(decision_id, plan, sign=False)
    objective = accept_mio_objective(objective_payload())
    result = admit_objective(objective, unsigned, authenticator=world.authenticator, now=utcnow())
    assert isinstance(result, AdvisoryRetained)
    assert result.reason == "decision_unauthenticated"

    forged = sign_decision(unsigned, b"another-key")
    result = admit_objective(objective, forged, authenticator=world.authenticator, now=utcnow())
    assert isinstance(result, AdvisoryRetained)
    assert result.reason == "decision_unauthenticated"


def test_edited_after_signing_decision_is_retained(world):
    decision_id = world.next_id()
    signed = world.signed_decision(decision_id, world.plan(decision_id))
    signed["evidence_refs"] = signed["evidence_refs"] + ["advisory:mio-objective-other"]
    result = admit_objective(
        accept_mio_objective(objective_payload()),
        signed,
        authenticator=world.authenticator,
        now=utcnow(),
    )
    assert isinstance(result, AdvisoryRetained)
    assert result.reason == "decision_unauthenticated"


def test_expired_decision_is_retained(world):
    decision_id = world.next_id()
    signed = world.signed_decision(decision_id, world.plan(decision_id))
    later = utcnow() + timedelta(hours=1)
    result = admit_objective(
        accept_mio_objective(objective_payload()),
        signed,
        authenticator=world.authenticator,
        now=later,
    )
    assert isinstance(result, AdvisoryRetained)
    assert result.reason == "decision_expired"


def test_rejected_decision_status_is_retained(world):
    decision_id = world.next_id()
    signed = world.signed_decision(decision_id, world.plan(decision_id), status="rejected")
    result = admit_objective(
        accept_mio_objective(objective_payload()),
        signed,
        authenticator=world.authenticator,
        now=utcnow(),
    )
    assert isinstance(result, AdvisoryRetained)
    assert result.reason == "decision_not_accepted"


def test_decision_without_objective_ref_is_retained(world):
    decision_id = world.next_id()
    for refs in ([], [HYPOTHESIS_REF, FRAME_REF], ["advisory:mio-objective-someone-else"]):
        signed = world.signed_decision(decision_id, world.plan(decision_id), evidence_refs=refs)
        result = admit_objective(
            accept_mio_objective(objective_payload()),
            signed,
            authenticator=world.authenticator,
            now=utcnow(),
        )
        assert isinstance(result, AdvisoryRetained)
        assert result.reason == "objective_not_in_authenticated_decision"


def test_admit_does_not_consume_the_decision(world):
    decision_id = world.next_id()
    signed = world.signed_decision(decision_id, world.plan(decision_id))
    admitted = admit_objective(
        accept_mio_objective(objective_payload()),
        signed,
        authenticator=world.authenticator,
        now=utcnow(),
    )
    assert isinstance(admitted, AdmittedObjective)
    assert world.adapter.state.decision_consumed(decision_id) is False
    assert world.adapter.collect_status(world.environment_id)["state"] == "absent"


# --- the reference chain, end to end ----------------------------------------


def test_static_scenario_reference_chain_is_consistent_end_to_end(world):
    decision_id, plan, signed, objective, admitted, chain = _bind(world)

    assert chain.objective_ref == OBJECTIVE_REF
    assert chain.hypothesis_refs == (HYPOTHESIS_REF,)
    assert chain.frame_ref == FRAME_REF
    assert chain.decision_id == decision_id
    assert chain.environment_id == world.environment_id
    assert chain.package_id == world.package["package_id"]
    assert chain.package_digest == world.package["package_digest"]
    assert chain.node_id == plan["node_id"]
    assert chain.effect_ref == f"effect:{decision_id}"
    assert chain.lease_start == signed["effective_at"] or chain.lease_start is not None
    assert chain.lease_end > chain.lease_start
    refs = chain.evidence_refs()
    assert OBJECTIVE_REF in refs and HYPOTHESIS_REF in refs and FRAME_REF in refs
    assert f"decision:{decision_id}" in refs

    observer = _observer(world, chain, plan)
    first = observer.record(
        observation_class="interaction",
        surface="service",
        attempt_count=2,
    )
    assert set(refs) <= set(first.evidence_refs)

    bundle = _bundle(world, chain)
    verify_feedback_bundle(
        bundle, expected_chain=chain, state=world.adapter.state, now=utcnow(), max_age=MAX_AGE
    )

    # separate keys, never merged
    for key in (
        "reference_chain",
        "decision",
        "execution_request",
        "runtime_materialization",
        "observed_mechanism",
        "interactions",
        "outcome",
        "tactical_assessment",
        "freshness",
        "isolation",
        "limitations",
        "evidence",
    ):
        assert key in bundle, key
    assert bundle["schema"] == "az06-mio-feedback-bundle/v0-local"
    assert bundle["execution_request"]["kind"] == "edge_activation_decision"
    assert bundle["tactical_assessment"] == {"status": "not_assessed", "owner": "outside_az06"}
    assert bundle["observed_mechanism"] == {"status": "not_observed_by_az06"}
    assert bundle["evidence"]["chain_verified"] is True
    assert bundle["isolation"]["status"] == "asserted"
    assert bundle["freshness"]["fresh"] is True
    assert len(bundle["interactions"]) == 1
    outcome = bundle["outcome"]
    assert outcome["coverage_complete"] is True
    assert outcome["decision_ref"] == f"decision:{decision_id}"
    assert outcome["effect_ref"] == chain.effect_ref
    assert "redirection_does_not_imply_diversion" not in bundle["limitations"]  # no mechanism observed
    assert "virtual_or_local_evidence_not_hil" in bundle["limitations"]

    # downstream consumer shapes derive from the same bundle
    ingest = knowledge_ingest_payload(bundle, **_kw(world, chain))
    assert ingest["environment_id"] == world.environment_id
    assert len(ingest["items"]) == 1
    context = mio_deception_context(bundle, **_kw(world, chain))
    assert isinstance(context, dict)

    # terminate (Edge decision) and reset
    assert world.terminate()["status"] == "terminated"
    world.adapter.reset_environment(world.environment_id)
    result = reset_feedback(world.adapter, chain, now=utcnow())
    assert isinstance(result, dict)
    assert world.adapter.verify_evidence(world.environment_id) is True
    types = [e.get("event_type") for e in world.adapter.export_evidence(world.environment_id)]
    assert types.count("reset_completed") == 1
    assert types[0] == "activated" and "terminated" in types
    with pytest.raises(BindingRefused) as refused:
        _observer(world, chain, plan).record(observation_class="interaction", surface="service")
    assert refused.value.code == "session_reset"


def test_activation_cannot_reuse_the_decision(world):
    decision_id, plan, signed, *_ = _bind(world)
    world.terminate()
    with pytest.raises(RuntimeGateError, match="already consumed"):
        world.adapter.activate_environment(world.environment_id, world.package, plan, signed)


def test_bind_requires_a_prior_activation(world):
    decision_id = world.next_id()
    plan = world.plan(decision_id)
    signed = world.signed_decision(decision_id, plan)
    now = utcnow()
    admitted = admit_objective(
        accept_mio_objective(objective_payload()),
        signed,
        authenticator=world.authenticator,
        now=now,
    )
    with pytest.raises(BindingRefused) as refused:
        bind_reference_chain(
            admitted=admitted,
            signed_activation_decision=signed,
            defensive_effect_ref=accept_defensive_effect_ref(edge_effect_payload(decision_id, now)),
            adapter=world.adapter,
            environment_id=world.environment_id,
            now=now,
        )
    assert refused.value.code == "decision_not_consumed"


def test_bind_refuses_effect_with_other_decision(world):
    decision_id, plan, signed = world.activate()
    now = utcnow()
    admitted = admit_objective(
        accept_mio_objective(objective_payload()), signed,
        authenticator=world.authenticator, now=now,
    )
    effect = accept_defensive_effect_ref(
        edge_effect_payload(decision_id, now, decision_ref="decision:some-other-decision")
    )
    with pytest.raises(BindingRefused) as refused:
        bind_reference_chain(
            admitted=admitted, signed_activation_decision=signed,
            defensive_effect_ref=effect, adapter=world.adapter,
            environment_id=world.environment_id, now=now,
        )
    assert refused.value.code == "effect_decision_mismatch"


def test_bind_refuses_other_environment(world):
    decision_id, plan, signed = world.activate()
    now = utcnow()
    admitted = admit_objective(
        accept_mio_objective(objective_payload()), signed,
        authenticator=world.authenticator, now=now,
    )
    with pytest.raises(BindingRefused) as refused:
        bind_reference_chain(
            admitted=admitted, signed_activation_decision=signed,
            defensive_effect_ref=accept_defensive_effect_ref(edge_effect_payload(decision_id, now)),
            adapter=world.adapter, environment_id="env-other", now=now,
        )
    # the decision was consumed for env-55, not env-other; any refusal is correct,
    # environment_mismatch would be the most precise (reported to the leader)
    assert refused.value.code in {"environment_mismatch", "decision_not_consumed", "session_mismatch"}


def test_bind_refuses_decision_for_another_node(world):
    decision_id, plan, signed = world.activate()
    now = utcnow()
    other_plan = world.plan(decision_id, node_id="some-other-node")
    other = world.signed_decision(decision_id, other_plan, target_node_id="some-other-node")
    admitted = admit_objective(
        accept_mio_objective(objective_payload()), other,
        authenticator=world.authenticator, now=now,
    )
    with pytest.raises(BindingRefused) as refused:
        bind_reference_chain(
            admitted=admitted, signed_activation_decision=other,
            defensive_effect_ref=accept_defensive_effect_ref(edge_effect_payload(decision_id, now)),
            adapter=world.adapter, environment_id=world.environment_id, now=now,
        )
    assert refused.value.code in {"node_mismatch", "decision_mismatch"}


def test_bind_refuses_different_decision_than_the_one_activated(world):
    decision_id, plan, signed = world.activate()
    now = utcnow()
    other_id = world.next_id()
    other = world.signed_decision(other_id, world.plan(other_id))
    admitted = admit_objective(
        accept_mio_objective(objective_payload()), other,
        authenticator=world.authenticator, now=now,
    )
    with pytest.raises(BindingRefused) as refused:
        bind_reference_chain(
            admitted=admitted, signed_activation_decision=other,
            defensive_effect_ref=accept_defensive_effect_ref(edge_effect_payload(other_id, now)),
            adapter=world.adapter, environment_id=world.environment_id, now=now,
        )
    assert refused.value.code in {"decision_mismatch", "decision_not_consumed"}


def test_bind_after_lease_end_is_refused(world):
    decision_id, plan, signed = world.activate()
    now = utcnow()
    admitted = admit_objective(
        accept_mio_objective(objective_payload()), signed,
        authenticator=world.authenticator, now=now,
    )
    with pytest.raises(BindingRefused) as refused:
        bind_reference_chain(
            admitted=admitted, signed_activation_decision=signed,
            defensive_effect_ref=accept_defensive_effect_ref(edge_effect_payload(decision_id, now)),
            adapter=world.adapter, environment_id=world.environment_id,
            now=now + timedelta(hours=1),
        )
    assert refused.value.code == "lease_expired"


def test_observation_outside_lease_is_recorded_marked_and_reported(world):
    """M1: a late observation is a fact, recorded with a mark; it authorizes nothing."""

    decision_id, plan, signed, _, _, chain = _bind(world)
    late = chain.lease_end + timedelta(seconds=1)
    observer = bound_observer(world.adapter, chain, world.package, plan, now_fn=lambda: late)
    recorded = observer.record(observation_class="interaction", surface="service")
    assert recorded.metadata.get("outside_lease") is True

    bundle = _bundle(world, chain, now=late)
    assert "lease_expired" in bundle["limitations"]
    assert bundle["interactions"][0]["metadata"].get("outside_lease") is True
    observation = bundle["runtime_materialization"]["effect_observation"]
    assert observation["status"] == "failed"
    assert observation["termination_reason"] == "lease_expired_runtime_still_active"
    # nothing was withdrawn by reporting it
    assert world.adapter.collect_status(world.environment_id)["state"] == "active"
    # the honest bundle verifies; one that claims a live session after the lease does not
    verify_feedback_bundle(
        bundle, expected_chain=chain, state=world.adapter.state, now=late, max_age=MAX_AGE
    )
    forged = copy.deepcopy(bundle)
    forged["runtime_materialization"]["effect_observation"]["status"] = "active"
    forged["runtime_materialization"]["effect_observation"]["termination_reason"] = None
    with pytest.raises(BindingRefused) as refused:
        verify_feedback_bundle(
            forged, expected_chain=chain, state=world.adapter.state, now=late, max_age=MAX_AGE
        )
    assert refused.value.code in {"lease_expired", "evidence_tampered"}


def test_session_from_before_reset_cannot_be_adopted_after_new_activation(world):
    """A chain minted for generation 1 must not bind observations of generation 2."""

    _, plan1, _, _, _, chain1 = _bind(world)
    world.terminate()
    world.adapter.reset_environment(world.environment_id)
    reset_feedback(world.adapter, chain1, now=utcnow())

    _, plan2, _, _, _, chain2 = _bind(world)
    assert chain2.generation != chain1.generation or chain2.session_ref != chain1.session_ref
    with pytest.raises(BindingRefused) as refused:
        _observer(world, chain1, plan1).record(observation_class="interaction", surface="service")
    assert refused.value.code in {"session_mismatch", "session_reset"}

    fresh = _observer(world, chain2, plan2).record(observation_class="interaction", surface="service")
    assert chain2.session_ref in fresh.evidence_refs

    bundle = _bundle(world, chain2)
    with pytest.raises(BindingRefused) as refused:
        verify_feedback_bundle(
            bundle, expected_chain=chain1, state=world.adapter.state,
            now=utcnow(), max_age=MAX_AGE,
        )
    assert refused.value.code in {"session_mismatch", "decision_mismatch", "evidence_tampered"}


def test_bundle_for_other_environment_is_refused(world):
    _, plan, _, _, _, chain = _bind(world)
    _observer(world, chain, plan).record(observation_class="interaction", surface="service")
    bundle = _bundle(world, chain)
    forged = copy.deepcopy(bundle)
    forged["reference_chain"]["environment_id"] = "env-other"
    with pytest.raises(BindingRefused) as refused:
        verify_feedback_bundle(
            forged, expected_chain=chain, state=world.adapter.state,
            now=utcnow(), max_age=MAX_AGE,
        )
    assert refused.value.code == "environment_mismatch"


def test_bundle_for_other_node_is_refused(world):
    _, plan, _, _, _, chain = _bind(world)
    bundle = _bundle(world, chain)
    forged = copy.deepcopy(bundle)
    forged["reference_chain"]["node_id"] = "other-node"
    with pytest.raises(BindingRefused) as refused:
        verify_feedback_bundle(
            forged, expected_chain=chain, state=world.adapter.state,
            now=utcnow(), max_age=MAX_AGE,
        )
    assert refused.value.code == "node_mismatch"


def test_bundle_with_other_decision_is_refused(world):
    _, plan, _, _, _, chain = _bind(world)
    bundle = _bundle(world, chain)
    forged = copy.deepcopy(bundle)
    forged["reference_chain"]["decision_id"] = "edge-activate-other"
    with pytest.raises(BindingRefused) as refused:
        verify_feedback_bundle(
            forged, expected_chain=chain, state=world.adapter.state,
            now=utcnow(), max_age=MAX_AGE,
        )
    assert refused.value.code in {"decision_mismatch", "effect_decision_mismatch"}


def test_stale_bundle_is_refused_and_marked(world):
    _, plan, _, _, _, chain = _bind(world)
    bundle = _bundle(world, chain)
    with pytest.raises(BindingRefused) as refused:
        verify_feedback_bundle(
            bundle, expected_chain=chain, state=world.adapter.state,
            now=utcnow() + timedelta(hours=1), max_age=MAX_AGE,
        )
    assert refused.value.code in {"stale", "lease_expired"}


# --- evidence integrity -----------------------------------------------------


def test_tampered_evidence_is_detected(world):
    _, plan, _, _, _, chain = _bind(world)
    _observer(world, chain, plan).record(observation_class="interaction", surface="service")
    bundle = _bundle(world, chain)

    path = world.adapter.state.evidence_path(world.environment_id)
    lines = path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[-1])
    record["surface"] = "file"
    lines[-1] = json.dumps(record)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(BindingRefused) as refused:
        verify_feedback_bundle(
            bundle, expected_chain=chain, state=world.adapter.state,
            now=utcnow(), max_age=MAX_AGE,
        )
    assert refused.value.code == "evidence_tampered"

    with pytest.raises(BindingRefused) as refused:
        _bundle(world, chain)
    assert refused.value.code == "evidence_tampered"


def test_bundle_edit_that_breaks_head_hash_is_detected(world):
    _, plan, _, _, _, chain = _bind(world)
    bundle = _bundle(world, chain)
    forged = copy.deepcopy(bundle)
    forged["evidence"]["head_hash"] = "0" * 64
    with pytest.raises(BindingRefused) as refused:
        verify_feedback_bundle(
            forged, expected_chain=chain, state=world.adapter.state,
            now=utcnow(), max_age=MAX_AGE,
        )
    assert refused.value.code == "evidence_tampered"


# --- telemetry, isolation, honesty of claims ---------------------------------


def test_telemetry_gap_makes_coverage_incomplete_with_gaps_and_limitations(world):
    _, plan, _, _, _, chain = _bind(world)
    bundle = _bundle(world, chain, observed_telemetry=("interaction_log",))
    outcome = bundle["outcome"]
    assert outcome["coverage_complete"] is False
    assert "process_events" in json.dumps(outcome["telemetry_gaps"])
    assert any(item.startswith("telemetry_gap:") for item in bundle["limitations"])


def test_no_telemetry_at_all_is_a_gap_not_a_clean_bill(world):
    _, plan, _, _, _, chain = _bind(world)
    bundle = _bundle(world, chain, observed_telemetry=())
    assert bundle["outcome"]["coverage_complete"] is False
    assert bundle["outcome"]["telemetry_gaps"]


def test_unrequested_expected_telemetry_is_refused_or_incomplete(world):
    _, plan, _, _, _, chain = _bind(world)
    try:
        bundle = _bundle(world, chain, expected_telemetry=(), observed_telemetry=())
    except BindingRefused as exc:
        assert exc.code == "telemetry_missing"
    else:  # accepted only if it does not claim complete coverage of nothing
        assert bundle["outcome"]["coverage_complete"] is False or bundle["limitations"]


def test_isolation_drift_marks_failed_and_does_not_withdraw(world):
    _, plan, _, _, _, chain = _bind(world)
    before_state = copy.deepcopy(world.adapter.collect_status(world.environment_id))
    IsolationDriftObserver(
        world.adapter.state,
        environment_id=world.environment_id,
        package_id=chain.package_id,
        node_id=chain.node_id,
    ).observe(
        {"route_to_protected": ["net-x"], "published_port": [], "capability_regranted": []}
    )
    calls = []
    world.monkeypatch.setattr(world.adapter, "_compose", lambda *a, **k: calls.append(a))

    bundle = _bundle(world, chain)
    assert bundle["isolation"]["status"] == "drift_observed"
    assert bundle["isolation"]["drift_count"] >= 1
    observation = bundle["runtime_materialization"]["effect_observation"]
    assert observation["status"] == "failed"
    assert observation["termination_reason"] == "isolation_drift_observed"

    # AZ-06 reports; it does not withdraw, terminate, or call compose
    assert calls == []
    assert world.adapter.collect_status(world.environment_id) == before_state
    assert world.adapter.collect_status(world.environment_id)["state"] == "active"


def test_isolation_without_assertion_is_unknown(world):
    _, plan, _, _, _, chain = _bind(world)
    bundle = _bundle(world, chain, isolation_assertion_refs=())
    assert bundle["isolation"]["status"] == "unknown"


def test_silence_is_never_safety_and_carries_a_limitation(world):
    _, plan, _, _, _, chain = _bind(world)
    bundle = _bundle(world, chain)
    assert bundle["interactions"] == []
    assert "no_interaction_observed_is_not_evidence_of_safety" in bundle["limitations"]
    text = _all_text(bundle).lower()
    for word in ("safe", "secure", "clean", "harmless", "effective", "success", "deceived", "diverted"):
        # only allowed inside the explicit limitation tokens that negate the claim
        stripped = text.replace("not_evidence_of_safety", "").replace(
            "redirection_does_not_imply_diversion", ""
        )
        assert word not in stripped, word


def test_tactical_assessment_is_always_not_assessed(world):
    _, plan, _, _, _, chain = _bind(world)
    observer = _observer(world, chain, plan)
    for _ in range(3):
        observer.record(observation_class="interaction", surface="credential_lure", attempt_count=9)
    bundle = _bundle(world, chain)
    assert bundle["tactical_assessment"] == {"status": "not_assessed", "owner": "outside_az06"}
    assert "tactical_assessment" not in bundle["outcome"] or bundle["outcome"].get(
        "tactical_assessment"
    ) in (None, "not_assessed", {"status": "not_assessed", "owner": "outside_az06"})


def test_bundle_carries_no_effectiveness_or_secret_material(world):
    _, plan, _, _, _, chain = _bind(world)
    _observer(world, chain, plan).record(observation_class="interaction", surface="service")
    bundle = _bundle(world, chain)
    text = _all_text(bundle)
    assert TEST_KEY.decode() not in text
    assert "signature" not in bundle["decision"]
    assert "az_signature" not in text and "hmac" not in text.lower()


def test_interaction_count_is_bounded(world):
    _, plan, _, _, _, chain = _bind(world)
    observer = _observer(world, chain, plan)
    for _ in range(260):
        observer.record(observation_class="interaction", surface="service")
    bundle = _bundle(world, chain)
    assert len(bundle["interactions"]) <= 256
    assert bundle.get("truncated") is True or bundle["interactions_truncated"] is True or \
        bundle["outcome"].get("truncated") is True


# --- injection ---------------------------------------------------------------


def test_untrusted_interaction_text_is_hashed_never_stored_or_forwarded(world):
    _, plan, _, _, _, chain = _bind(world)
    observation = _observer(world, chain, plan).record(
        observation_class="interaction",
        surface="credential_lure",
        untrusted_text=INJECTION_TEXT,
    )
    # credential_lure surface: not even a digest, only the length
    assert observation.metadata["untrusted_text_len"] == len(INJECTION_TEXT)
    assert "untrusted_text_hmac" not in observation.metadata
    assert "untrusted_text_sha256" not in observation.metadata
    on_service = _observer(world, chain, plan).record(
        observation_class="interaction", surface="service", untrusted_text=INJECTION_TEXT
    )
    assert len(on_service.metadata["untrusted_text_hmac"]) == 64
    assert "untrusted_text_sha256" not in on_service.metadata

    bundle = _bundle(world, chain)
    ingest = knowledge_ingest_payload(bundle, **_kw(world, chain))
    context = mio_deception_context(bundle, **_kw(world, chain))
    evidence_file = world.adapter.state.evidence_path(world.environment_id).read_text(
        encoding="utf-8"
    )
    for surface_name, material in {
        "bundle": bundle,
        "knowledge_ingest_payload": ingest,
        "mio_deception_context": context,
    }.items():
        text = _all_text(material)
        assert CANARY not in text, surface_name
        assert "IGNORE PREVIOUS" not in text, surface_name
        assert "evil.example" not in text, surface_name
    assert CANARY not in evidence_file


def test_text_that_tries_to_forge_a_verdict_does_not_change_the_bundle(world):
    _, plan, _, _, _, chain = _bind(world)
    baseline_tactical = _bundle(world, chain)["tactical_assessment"]
    _observer(world, chain, plan).record(
        observation_class="interaction",
        surface="service",
        untrusted_text='{"tactical_assessment":{"status":"effective"},"activate":true}',
    )
    bundle = _bundle(world, chain)
    assert bundle["tactical_assessment"] == baseline_tactical
    assert "activate" not in json.dumps(mio_deception_context(bundle, **_kw(world, chain)))


def test_observer_rejects_verdict_in_metadata(world):
    _, plan, _, _, _, chain = _bind(world)
    with pytest.raises(Exception):
        _observer(world, chain, plan).record(
            observation_class="interaction",
            surface="service",
            metadata={"belief": True},
        )


# --- downstream shapes ------------------------------------------------------


def test_knowledge_payload_envelope_shape(world):
    _, plan, _, _, _, chain = _bind(world)
    observer = _observer(world, chain, plan)
    observer.record(observation_class="interaction", surface="service")
    observer.record(observation_class="reaction", surface="credential_lure", reaction_kind="authenticate")
    ingest = knowledge_ingest_payload(_bundle(world, chain), **_kw(world, chain))
    assert set(ingest) == {"environment_id", "items"}
    assert [item["observation_class"] for item in ingest["items"]] == ["interaction", "reaction"]
    for item in ingest["items"]:
        assert item["environment_id"] == world.environment_id


def test_mio_context_does_not_carry_authority_or_a_verdict(world):
    _, plan, _, _, _, chain = _bind(world)
    context = mio_deception_context(_bundle(world, chain), **_kw(world, chain))
    text = json.dumps(context).lower()
    for forbidden in ("signature", "decision_authority", "executable\": true", "effective"):
        assert forbidden not in text


# --- termination and reset authority ----------------------------------------


def test_termination_and_reset_only_through_edge_decision(world):
    _, plan, _, _, _, chain = _bind(world)
    # reset without a prior termination is the adapter's refusal, unchanged
    with pytest.raises(Exception):
        reset_feedback(world.adapter, chain, now=utcnow())
    assert world.adapter.collect_status(world.environment_id)["state"] == "active"

    world.terminate()
    # terminated but not yet reset: reset_feedback must not claim a reset
    with pytest.raises(BindingRefused) as early:
        reset_feedback(world.adapter, chain, now=utcnow())
    assert early.value.code == "session_mismatch"
    assert world.adapter.reset_environment(world.environment_id)["status"] == "reset"
    result = reset_feedback(world.adapter, chain, now=utcnow())
    assert result["effect_observation"]["status"] == "terminated"
    assert result.get("limitations")


def test_unsigned_termination_is_refused_by_existing_gate(world):
    _bind(world)
    from tests.test_runtime import _termination

    termination = _termination("edge-terminate-unsigned")
    termination["environment_id"] = world.environment_id
    with pytest.raises(RuntimeGateError):
        world.adapter.terminate_environment(world.environment_id, termination)
    assert world.adapter.collect_status(world.environment_id)["state"] == "active"


def test_observed_mechanism_is_separate_and_carries_the_diversion_limitation(world):
    from azazel_deception.runtime.presented_terrain import ProducerRedirectionEvidence

    decision_id, plan, _, _, _, chain = _bind(world)

    def mech(**changes):
        data = dict(
            producer_product="azazel-edge", producer_node="edge-1", trace_id="trace-55",
            decision_ref=f"decision:{decision_id}", execution_ref="execution-1",
            mechanism_observation_ref="mechanism-1", evidence_refs=["edge-nft-1"],
        )
        data.update(changes)
        return ProducerRedirectionEvidence(**data)

    bundle = _bundle(world, chain, mechanism=mech())
    assert bundle["observed_mechanism"] != {"status": "not_observed_by_az06"}
    assert "redirection_does_not_imply_diversion" in bundle["limitations"]
    assert bundle["tactical_assessment"]["status"] == "not_assessed"

    for wrong in (mech(trace_id="trace-other"), mech(decision_ref="decision:someone-else")):
        with pytest.raises(BindingRefused):
            _bundle(world, chain, mechanism=wrong)


def test_a_second_activation_decision_cannot_ride_the_first_chain(world):
    """Reusing one signed decision for a new session is the adapter's refusal, not ours."""

    decision_id, plan, signed, _, _, chain = _bind(world)
    world.terminate()
    world.adapter.reset_environment(world.environment_id)
    with pytest.raises(RuntimeGateError, match="already consumed"):
        world.adapter.activate_environment(world.environment_id, world.package, plan, signed)
    assert world.adapter.collect_status(world.environment_id)["state"] == "absent"


# --- leader's clarified conventions (digest, drift context, unbound, terrain) ---


def test_decision_digest_is_prefixed_and_chain_dict_is_json(world):
    _, plan, _, _, admitted, chain = _bind(world)
    assert admitted.decision_digest.startswith("sha256:") and chain.decision_digest == admitted.decision_digest
    as_dict = chain.to_dict()
    assert isinstance(as_dict["lease_start"], str) and "effect" not in as_dict
    json.dumps(as_dict)


def test_drift_makes_mio_context_lifecycle_unknown(world):
    _, plan, _, _, _, chain = _bind(world)
    IsolationDriftObserver(
        world.adapter.state, environment_id=world.environment_id,
        package_id=chain.package_id, node_id=chain.node_id,
    ).observe({"route_to_protected": [], "published_port": ["8080"], "capability_regranted": []})
    assert mio_deception_context(_bundle(world, chain), **_kw(world, chain))["lifecycle_state"] == "unknown"


def test_no_isolation_assertion_means_no_projected_terrain(world):
    _, plan, _, _, _, chain = _bind(world)
    bundle = _bundle(world, chain, isolation_assertion_refs=())
    assert bundle["runtime_materialization"]["presented_terrain"] is None
    assert "presented_terrain_not_projected" in bundle["limitations"]


def test_no_mechanism_means_no_active_materialized_terrain(world):
    _, plan, _, _, _, chain = _bind(world)
    bundle = _bundle(world, chain, isolation_assertion_refs=("isolation-net-none",),
                     active_surface_refs=("surface-a",))
    assert bundle["runtime_materialization"]["presented_terrain"] is None
    assert "presented_terrain_not_projected" in bundle["limitations"]
    assert "runtime_state_not_independently_reverified" in bundle["limitations"]


@pytest.mark.parametrize("with_mechanism", [False, True])
def test_persisted_active_never_yields_an_active_materialized_observation(world, with_mechanism):
    from azazel_deception.runtime.presented_terrain import ProducerRedirectionEvidence

    decision_id, plan, _, _, _, chain = _bind(world)
    mechanism = None
    if with_mechanism:
        mechanism = ProducerRedirectionEvidence(
            producer_product="azazel-edge", producer_node=chain.node_id,
            trace_id=chain.trace_id, decision_ref=f"decision:{decision_id}",
            execution_ref="execution-1", mechanism_observation_ref="mechanism-1",
            evidence_refs=["edge-nft-1"],
        )
    bundle = _bundle(
        world, chain, mechanism=mechanism,
        isolation_assertion_refs=("isolation-net-none",), active_surface_refs=("surface-a",),
    )
    runtime = bundle["runtime_materialization"]
    assert runtime["environment_state"] == "active"
    # No observation at all: never "active", never a stand-in status.
    assert runtime["effect_observation"] is None
    terrain = runtime["presented_terrain"]
    assert terrain is None or terrain["lifecycle_state_ref"].endswith(".stale")
    if terrain is not None:
        assert not terrain["lifecycle_state_ref"].endswith(".active")
        assert terrain["active_surface_refs"] == []
    limitations = bundle["limitations"]
    assert "effect_observation_withheld_not_independently_verified" in limitations
    assert "runtime_state_not_independently_reverified" in limitations
    if not with_mechanism:
        assert "presented_terrain_not_projected" in limitations
    # The honest bundle still verifies, and the live context is still not "active".
    verify_feedback_bundle(bundle, **_kw(world, chain, mechanism=mechanism))
    assert mio_deception_context(
        bundle, **_kw(world, chain, mechanism=mechanism)
    )["lifecycle_state"] == "unknown"


def test_empty_expected_telemetry_is_telemetry_missing(world):
    _, plan, _, _, _, chain = _bind(world)
    with pytest.raises(BindingRefused) as refused:
        _bundle(world, chain, expected_telemetry=(), observed_telemetry=())
    assert refused.value.code == "telemetry_missing"


def test_interaction_without_chain_refs_is_excluded_and_flagged(world):
    _, plan, _, _, _, chain = _bind(world)
    from azazel_fabric.deception_contracts import PlacementPlan
    from azazel_deception.package import parse_package
    world.adapter.make_observer(
        world.environment_id, parse_package(world.package), PlacementPlan.model_validate(plan)
    ).record(
        observation_class="interaction", surface="service"
    )
    bundle = _bundle(world, chain)
    assert bundle["interactions"] == []
    assert any(x.startswith("unbound_interactions_excluded:") for x in bundle["limitations"])


# --- addendum 1: rebuild-and-compare verification, bounded inputs, coverage ------


def _digest_ref_of(objective):
    return "advisory:mio-objective-digest-" + objective_digest(objective).split(":", 1)[1][:32]


def _admit(world, decision_id, extra_refs, objective=None):
    objective = objective or accept_mio_objective(objective_payload())
    plan = world.plan(decision_id)
    signed = world.signed_decision(
        decision_id, plan, evidence_refs=[OBJECTIVE_REF, HYPOTHESIS_REF, FRAME_REF, *extra_refs]
    )
    return objective, plan, signed


def test_objective_digest_match_binds_content(world):
    objective = accept_mio_objective(objective_payload())
    decision_id = world.next_id()
    _, plan, signed = _admit(world, decision_id, [_digest_ref_of(objective)])
    admitted = admit_objective(objective, signed, authenticator=world.authenticator, now=utcnow())
    assert isinstance(admitted, AdmittedObjective) and admitted.objective_content_bound is True


def test_objective_digest_mismatch_is_advice_only(world):
    objective = accept_mio_objective(objective_payload())
    other = accept_mio_objective(objective_payload(desired_observations=[["interaction", "file"]]))
    decision_id = world.next_id()
    _, plan, signed = _admit(world, decision_id, [_digest_ref_of(other)])
    result = admit_objective(objective, signed, authenticator=world.authenticator, now=utcnow())
    assert isinstance(result, AdvisoryRetained)
    assert world.adapter.state.decision_consumed(decision_id) is False


def test_objective_digest_absent_is_admitted_but_reported_unbound(world):
    _, plan, _, _, admitted, chain = _bind(world)
    assert admitted.objective_content_bound is False and chain.objective_content_bound is False
    bundle = _bundle(world, chain)
    assert "objective_content_not_bound" in bundle["limitations"]
    inputs = mio_frame_inputs(bundle, **_kw(world, chain))
    assert "DECEPTION_OBJECTIVE_CONTENT_NOT_BOUND" in inputs["unknowns"]


def test_forged_admission_with_mismatched_content_is_refused_by_signed_digest(world):
    signed_objective = accept_mio_objective(objective_payload())
    decision_id = world.next_id()
    _, plan, signed = _admit(world, decision_id, [_digest_ref_of(signed_objective)])
    world.adapter.activate_environment(world.environment_id, world.package, plan, signed)
    genuine = admit_objective(signed_objective, signed, authenticator=world.authenticator, now=utcnow())
    assert isinstance(genuine, AdmittedObjective)
    # Same refs, different desired_observations; caller forges an empty digest and a false flag.
    tampered = accept_mio_objective(objective_payload(desired_observations=[["interaction", "file"]]))
    forged = AdmittedObjective(
        objective=tampered,
        decision_id=genuine.decision_id,
        decision_digest=genuine.decision_digest,
        objective_digest="",
        objective_content_bound=False,
    )
    with pytest.raises(BindingRefused) as refused:
        bind_reference_chain(
            admitted=forged, signed_activation_decision=signed,
            defensive_effect_ref=accept_defensive_effect_ref(edge_effect_payload(decision_id, utcnow())),
            adapter=world.adapter, environment_id=world.environment_id, now=utcnow(),
        )
    assert refused.value.code == "decision_mismatch"


def test_bound_objective_digest_carries_through_without_the_limitation(world):
    objective = accept_mio_objective(objective_payload())
    decision_id = world.next_id()
    _, plan, signed = _admit(world, decision_id, [_digest_ref_of(objective)])
    world.adapter.activate_environment(world.environment_id, world.package, plan, signed)
    now = utcnow()
    admitted = admit_objective(objective, signed, authenticator=world.authenticator, now=now)
    chain = bind_reference_chain(
        admitted=admitted, signed_activation_decision=signed,
        defensive_effect_ref=accept_defensive_effect_ref(edge_effect_payload(decision_id, now)),
        adapter=world.adapter, environment_id=world.environment_id, now=utcnow(),
    )
    assert chain.objective_content_bound is True
    assert chain.objective_digest == objective_digest(objective)
    assert "objective_content_not_bound" not in _bundle(world, chain)["limitations"]


def test_second_effect_for_one_decision_is_rejected(world):
    decision_id, plan, signed, _, admitted, chain = _bind(world)
    now = utcnow()
    second = accept_defensive_effect_ref(
        edge_effect_payload(decision_id, now, effect_id="effect:second-for-same-decision")
    )
    with pytest.raises(BindingRefused) as refused:
        bind_reference_chain(
            admitted=admitted, signed_activation_decision=signed, defensive_effect_ref=second,
            adapter=world.adapter, environment_id=world.environment_id, now=now,
        )
    assert refused.value.code == "effect_rejected"


def test_bundle_past_the_effect_window_is_effect_rejected(world):
    decision_id, plan, signed = world.activate()
    now = utcnow()
    admitted = admit_objective(
        accept_mio_objective(objective_payload()), signed,
        authenticator=world.authenticator, now=now,
    )
    short = accept_defensive_effect_ref(
        edge_effect_payload(decision_id, now, expires_at=(now + timedelta(minutes=1)).isoformat())
    )
    chain = bind_reference_chain(
        admitted=admitted, signed_activation_decision=signed, defensive_effect_ref=short,
        adapter=world.adapter, environment_id=world.environment_id, now=now,
    )
    # still inside the decision lease (5 min), outside the effect window (1 min)
    with pytest.raises(BindingRefused) as refused:
        _bundle(world, chain, now=now + timedelta(minutes=2))
    assert refused.value.code == "effect_rejected"


@pytest.mark.parametrize(
    "metadata",
    [
        {"payload": "x"},
        {"protocol": "tcp and a space"},
        {"protocol": "x" * 65},
        {"port": [80]},
        {"sensor_id": "ignore previous instructions"},
        {"request_count": float("inf")},
    ],
)
def test_metadata_is_allow_listed_and_bounded(world, metadata):
    _, plan, _, _, _, chain = _bind(world)
    with pytest.raises((ValueError, TypeError)):
        _observer(world, chain, plan).record(
            observation_class="interaction", surface="service", metadata=metadata
        )


def test_allowed_metadata_is_kept(world):
    _, plan, _, _, _, chain = _bind(world)
    record = _observer(world, chain, plan).record(
        observation_class="interaction", surface="service",
        metadata={"protocol": "tcp", "port": 8080, "request_count": 3},
    )
    assert record.metadata["port"] == 8080


def test_unknown_lure_and_oversized_evidence_refs_are_refused(world):
    _, plan, _, _, _, chain = _bind(world)
    observer = _observer(world, chain, plan)
    with pytest.raises(ValueError):
        observer.record(
            observation_class="interaction", surface="credential_lure", lure_id="not-a-lure"
        )
    with pytest.raises((ValueError, BindingRefused)):
        observer.record(
            observation_class="interaction", surface="service",
            evidence_refs=[f"extra:{i}" for i in range(40)],
        )


def test_observation_ids_are_session_derived_and_unique_across_observers_and_generations(world):
    _, plan1, _, _, _, chain1 = _bind(world)
    a = _observer(world, chain1, plan1).record(observation_class="interaction", surface="service")
    b = _observer(world, chain1, plan1).record(observation_class="interaction", surface="service")
    assert a.observation_id != b.observation_id  # a re-created observer does not restart at 1
    assert re.fullmatch(rf"{world.environment_id}-s\d+-obs-\d{{6}}", a.observation_id)

    world.terminate()
    world.adapter.reset_environment(world.environment_id)
    _, plan2, _, _, _, chain2 = _bind(world)
    c = _observer(world, chain2, plan2).record(observation_class="interaction", surface="service")
    assert c.observation_id not in {a.observation_id, b.observation_id}
    assert f"-s{chain2.generation}-" in c.observation_id


def test_observed_at_must_lie_within_the_session(world):
    _, plan, _, _, _, chain = _bind(world)
    observer = _observer(world, chain, plan)
    with pytest.raises(BindingRefused) as future:
        observer.record(
            observation_class="interaction", surface="service",
            observed_at=utcnow() + timedelta(minutes=5),
        )
    assert future.value.code == "stale"
    with pytest.raises(BindingRefused) as past:
        observer.record(
            observation_class="interaction", surface="service",
            observed_at=utcnow() - timedelta(hours=1),
        )
    assert past.value.code == "session_mismatch"


@pytest.mark.parametrize(
    "forge",
    [
        lambda b: b["interactions"].clear(),
        lambda b: b["limitations"].clear(),
        lambda b: b["isolation"].update({"status": "asserted", "drift_count": 0}),
        lambda b: b["outcome"].update({"coverage_complete": True, "telemetry_gaps": []}),
        lambda b: b["evidence"].pop("head_hash"),
        lambda b: b["freshness"].update({"fresh": True, "age_seconds": 0}),
        lambda b: b["runtime_materialization"].update({"environment_state": "reset"}),
        lambda b: b["interactions"][0].update({"surface": "file"}),
    ],
    ids=["drop_interactions", "clear_limitations", "isolation", "coverage", "no_head",
         "freshness", "environment_state", "edit_interaction"],
)
def test_bundle_is_rebuilt_from_evidence_and_every_forgery_is_caught(world, forge):
    """The bundle's own claims are never believed. Start from a drifted, gappy,
    stale-ish bundle so each forgery claims something the evidence contradicts."""

    _, plan, _, _, _, chain = _bind(world)
    _observer(world, chain, plan).record(observation_class="interaction", surface="service")
    IsolationDriftObserver(
        world.adapter.state, environment_id=world.environment_id,
        package_id=chain.package_id, node_id=chain.node_id,
    ).observe({"route_to_protected": ["n"], "published_port": [], "capability_regranted": []})
    bundle = _bundle(world, chain, observed_telemetry=("interaction_log",))
    verify_feedback_bundle(bundle, **{k: v for k, v in _kw(world, chain).items()})
    forged = copy.deepcopy(bundle)
    forge(forged)
    with pytest.raises(BindingRefused) as refused:
        verify_feedback_bundle(forged, **_kw(world, chain))
    assert refused.value.code in {"evidence_tampered", "stale", "session_mismatch"}


def test_consumer_outputs_refuse_an_unverifiable_bundle(world):
    _, plan, _, _, _, chain = _bind(world)
    _observer(world, chain, plan).record(observation_class="interaction", surface="service")
    forged = copy.deepcopy(_bundle(world, chain))
    forged["interactions"].clear()
    for fn in (knowledge_ingest_payload, mio_deception_context, mio_frame_inputs):
        with pytest.raises(BindingRefused):
            fn(forged, **_kw(world, chain))


def test_mechanism_claiming_bundle_needs_the_mechanism_again(world):
    from azazel_deception.runtime.presented_terrain import ProducerRedirectionEvidence

    decision_id, plan, _, _, _, chain = _bind(world)
    mech = ProducerRedirectionEvidence(
        producer_product="azazel-edge", producer_node="edge-1", trace_id="trace-55",
        decision_ref=f"decision:{decision_id}", execution_ref="execution-1",
        mechanism_observation_ref="mechanism-1", evidence_refs=["edge-nft-1"],
    )
    bundle = _bundle(world, chain, mechanism=mech)
    verify_feedback_bundle(bundle, **_kw(world, chain, mechanism=mech))
    with pytest.raises(BindingRefused) as refused:
        verify_feedback_bundle(bundle, **_kw(world, chain))
    assert refused.value.code == "evidence_tampered"


def test_objective_coverage_is_caller_declared_and_never_a_verdict(world):
    _, plan, _, objective, _, chain = _bind(world)
    _observer(world, chain, plan).record(observation_class="interaction", surface="service")
    bundle = _bundle(
        world, chain, objective=objective,
        surface_telemetry={"service": "interaction_log", "credential_lure": "process_events"},
        observed_telemetry=("interaction_log",),
    )
    coverage = bundle["objective_coverage"]
    assert coverage["coverage_basis"] == "caller_declared"
    status = {(e["observation_class"], e["surface"]): e["status"] for e in coverage["entries"]}
    assert status[("interaction", "service")] == "observed"
    assert status[("interaction", "credential_lure")] == "undeterminable_telemetry_gap:process_events"
    entry = next(e for e in coverage["entries"] if e["status"] == "observed")
    assert entry["observation_ids"] and entry["hypothesis_ref"] == HYPOTHESIS_REF

    covered = _bundle(
        world, chain, objective=objective,
        surface_telemetry={"service": "interaction_log", "credential_lure": "process_events"},
    )
    status = {(e["observation_class"], e["surface"]): e["status"] for e in covered["objective_coverage"]["entries"]}
    assert status[("interaction", "credential_lure")] == "not_observed_with_coverage"
    assert "tactical" not in json.dumps(covered["objective_coverage"]).lower()

    unmapped = _bundle(world, chain, objective=objective)
    assert any(e["status"] == f"undeterminable_unmapped_surface:{e['surface']}"
               for e in unmapped["objective_coverage"]["entries"])
    assert not any("unmapped_surface" in e["status"] and e["status"].startswith("undeterminable_telemetry_gap")
                   for e in unmapped["objective_coverage"]["entries"])


def test_frame_inputs_carry_markers_for_every_honesty_limit(world):
    _, plan, _, _, _, chain = _bind(world)
    inputs = mio_frame_inputs(
        _bundle(world, chain, observed_telemetry=("interaction_log",), isolation_assertion_refs=()),
        **_kw(world, chain),
    )
    markers = set(inputs["unknowns"])
    assert "DECEPTION_TELEMETRY_GAP_PROCESS_EVENTS" in markers or any(
        m.startswith("DECEPTION_TELEMETRY_GAP_") for m in markers
    )
    assert {"DECEPTION_ISOLATION_NOT_ASSERTED", "DECEPTION_NO_INTERACTION_NOT_SAFETY"} <= markers
    assert inputs["explicit_unknowns"] == inputs["unknowns"]
    assert inputs["deception_status"] == "available"


def test_execution_request_pins_the_activated_evidence(world):
    _, plan, _, _, _, chain = _bind(world)
    request = _bundle(world, chain)["execution_request"]
    assert request["kind"] == "edge_activation_decision"
    assert request["activated_evidence_seq"] == chain.generation
    assert request["activated_evidence_hash"]


def test_after_reset_a_read_only_bundle_reports_reset_and_not_active(world):
    _, plan, _, _, _, chain = _bind(world)
    world.terminate()
    world.adapter.reset_environment(world.environment_id)
    reset_feedback(world.adapter, chain, now=utcnow())
    bundle = _bundle(world, chain)
    assert bundle["runtime_materialization"]["environment_state"] == "reset"
    assert bundle["runtime_materialization"]["effect_observation"]["status"] != "active"
    assert mio_deception_context(bundle, **_kw(world, chain))["lifecycle_state"] != "active"


# --- addendum 2: replay, races, MAC, key hygiene, coverage honesty -------------------
# Written ahead of the implementation; names follow DESIGN.md "addendum 2".

import inspect
import os
import stat
import threading

from azazel_deception.runtime import mio_feedback as _mf


@pytest.mark.parametrize(
    "mutation",
    [
        {"lease_end": datetime(2099, 1, 1, tzinfo=timezone.utc)},
        {"objective_content_bound": True},
        {"objective_digest": "sha256:" + "0" * 64},
        {"node_id": "other-node"},
        {"package_digest": "sha256:" + "1" * 64},
        {"decision_id": "dec-other"},
        {"generation": 999},
    ],
)
def test_caller_mutated_reference_chain_is_refused_everywhere(world, mutation):
    """F1: dataclasses.replace keeps the sealed value, so any changed field is refused."""

    _, plan, _, _, _, chain = _bind(world)
    forged = dataclasses.replace(chain, **mutation)
    assert forged != chain
    with pytest.raises(BindingRefused) as refused:
        _bundle(world, forged)
    assert refused.value.code == "evidence_tampered"
    with pytest.raises(BindingRefused) as refused:
        bound_observer(world.adapter, forged, world.package, plan)
    assert refused.value.code == "evidence_tampered"
    with pytest.raises(BindingRefused) as refused:
        reset_feedback(world.adapter, forged, now=utcnow())
    assert refused.value.code == "evidence_tampered"
    genuine = _bundle(world, chain)
    with pytest.raises(BindingRefused) as refused:
        verify_feedback_bundle(genuine, **_kw(world, forged))
    assert refused.value.code == "evidence_tampered"


def test_caller_replaced_effect_is_refused_everywhere(world):
    """The seal covers the effect object consumed by downstream projections."""

    _, plan, _, _, _, chain = _bind(world)
    altered_effect = chain.effect.model_copy(update={"policy_ref": "policy:other"})
    forged = dataclasses.replace(chain, effect=altered_effect)
    assert forged.seal == chain.seal
    with pytest.raises(BindingRefused) as refused:
        _bundle(world, forged)
    assert refused.value.code == "evidence_tampered"
    with pytest.raises(BindingRefused) as refused:
        bound_observer(world.adapter, forged, world.package, plan)
    assert refused.value.code == "evidence_tampered"
    with pytest.raises(BindingRefused) as refused:
        reset_feedback(world.adapter, forged, now=utcnow())
    assert refused.value.code == "evidence_tampered"
    genuine = _bundle(world, chain)
    with pytest.raises(BindingRefused) as refused:
        verify_feedback_bundle(genuine, **_kw(world, forged))
    assert refused.value.code == "evidence_tampered"


def _refused_everywhere(world, plan, chain, forged):
    with pytest.raises(BindingRefused) as refused:
        _bundle(world, forged)
    assert refused.value.code == "evidence_tampered"
    with pytest.raises(BindingRefused) as refused:
        bound_observer(world.adapter, forged, world.package, plan)
    assert refused.value.code == "evidence_tampered"
    with pytest.raises(BindingRefused) as refused:
        reset_feedback(world.adapter, forged, now=utcnow())
    assert refused.value.code == "evidence_tampered"
    genuine = _bundle(world, chain)
    with pytest.raises(BindingRefused) as refused:
        verify_feedback_bundle(genuine, **_kw(world, forged))
    assert refused.value.code == "evidence_tampered"


def test_duck_typed_effect_mimicking_the_sealed_dump_is_refused(world):
    """A stand-in whose model_dump equals the sealed value but whose attributes
    (read by consumers) differ must not pass: only exact Fabric effects do."""

    _, plan, _, _, _, chain = _bind(world)
    sealed_dump = chain.effect.model_dump(mode="json")

    class _Impostor:
        policy_ref = "policy:attacker"

        def model_dump(self, mode="python"):
            return dict(sealed_dump)

    _refused_everywhere(world, plan, chain, dataclasses.replace(chain, effect=_Impostor()))


def test_subclassed_effect_with_overridden_dump_is_refused(world):
    _, plan, _, _, _, chain = _bind(world)
    sealed_dump = chain.effect.model_dump(mode="json")

    class _Subclass(type(chain.effect)):
        def model_dump(self, *args, **kwargs):
            return dict(sealed_dump)

    forged_effect = _Subclass(**{**chain.effect.model_dump(), "policy_ref": "policy:attacker"})
    _refused_everywhere(world, plan, chain, dataclasses.replace(chain, effect=forged_effect))


def test_hand_built_reference_chain_without_seal_is_refused(world):
    _, plan, _, _, _, chain = _bind(world)
    unsealed = dataclasses.replace(chain, seal="")
    with pytest.raises(BindingRefused) as refused:
        _bundle(world, unsealed)
    assert refused.value.code == "evidence_tampered"


def test_genuine_sealed_chain_still_works_end_to_end(world):
    _, plan, _, _, _, chain = _bind(world)
    assert chain.seal
    _observer(world, chain, plan).record(observation_class="interaction", surface="service")
    bundle = _bundle(world, chain)
    verify_feedback_bundle(bundle, **_kw(world, chain))
    assert dataclasses.replace(chain).to_dict() == chain.to_dict()


def _consumers():
    return (knowledge_ingest_payload, mio_deception_context, mio_frame_inputs)


def _drift(world, chain):
    IsolationDriftObserver(
        world.adapter.state, environment_id=world.environment_id,
        package_id=chain.package_id, node_id=chain.node_id,
    ).observe({"route_to_protected": ["n"], "published_port": [], "capability_regranted": []})


def test_r1_bundle_older_than_a_later_drift_is_stale_everywhere(world):
    _, plan, _, _, _, chain = _bind(world)
    old = _bundle(world, chain)
    _drift(world, chain)  # evidence appended after the bundle was made
    for fn in (verify_feedback_bundle, *_consumers()):
        with pytest.raises(BindingRefused) as refused:
            fn(old, **_kw(world, chain))
        assert refused.value.code == "stale", fn.__name__


def test_r1_bundle_older_than_a_later_lure_contact_is_stale(world):
    _, plan, _, _, _, chain = _bind(world)
    old = _bundle(world, chain)
    _observer(world, chain, plan).record(observation_class="interaction", surface="credential_lure")
    for fn in (verify_feedback_bundle, *_consumers()):
        with pytest.raises(BindingRefused) as refused:
            fn(old, **_kw(world, chain))
        assert refused.value.code == "stale", fn.__name__


def test_r1_historical_audit_refuses_a_bundle_that_claims_live_and_consumers_cannot_ask(world):
    _, plan, _, _, _, chain = _bind(world)
    old = _bundle(world, chain)
    _drift(world, chain)
    with pytest.raises(BindingRefused):
        verify_feedback_bundle(old, allow_historical=True, **_kw(world, chain))
    for fn in _consumers():
        assert "allow_historical" not in inspect.signature(fn).parameters
        with pytest.raises(TypeError):
            fn(old, allow_historical=True, **_kw(world, chain))


def test_r1_historical_audit_accepts_a_bundle_that_does_not_claim_live(world):
    _, plan, _, _, _, chain = _bind(world)
    _observer(world, chain, plan).record(observation_class="interaction", surface="service")
    world.terminate()
    ended = _bundle(world, chain)
    assert ended["runtime_materialization"]["effect_observation"]["status"] != "active"
    world.adapter.reset_environment(world.environment_id)  # appends evidence: ended is now historical
    verify_feedback_bundle(ended, allow_historical=True, **_kw(world, chain))
    with pytest.raises(BindingRefused) as refused:
        verify_feedback_bundle(ended, **_kw(world, chain))
    assert refused.value.code == "stale"


def test_r2_terminate_during_bind_is_not_overwritten(world, monkeypatch):
    decision_id, plan, signed = world.activate()
    now = utcnow()
    admitted = admit_objective(
        accept_mio_objective(objective_payload()), signed,
        authenticator=world.authenticator, now=now,
    )
    original = _mf._coerce_effect
    fired = []

    def terminate_midway(value):
        if not fired:
            fired.append(world.terminate())
        return original(value)

    monkeypatch.setattr(_mf, "_coerce_effect", terminate_midway)
    try:
        bind_reference_chain(
            admitted=admitted, signed_activation_decision=signed,
            defensive_effect_ref=edge_effect_payload(decision_id, now),
            adapter=world.adapter, environment_id=world.environment_id, now=utcnow(),
        )
    except BindingRefused:
        pass  # refusing is fine; resurrecting or rewriting state is not
    assert fired and fired[0]["status"] == "terminated"
    assert world.adapter.collect_status(world.environment_id)["state"] == "terminated"
    assert world.adapter.verify_evidence(world.environment_id) is True


def test_r2_two_effects_bound_concurrently_exactly_one_wins(world, monkeypatch):
    decision_id, plan, signed = world.activate()
    now = utcnow()
    admitted = admit_objective(
        accept_mio_objective(objective_payload()), signed,
        authenticator=world.authenticator, now=now,
    )
    original = _mf._coerce_effect
    barrier = threading.Barrier(2, timeout=10)

    def meet(value):
        result = original(value)
        try:
            barrier.wait()
        except threading.BrokenBarrierError:
            pass
        return result

    monkeypatch.setattr(_mf, "_coerce_effect", meet)
    outcomes: list = []

    def attempt(effect_id):
        try:
            outcomes.append(("ok", bind_reference_chain(
                admitted=admitted, signed_activation_decision=signed,
                defensive_effect_ref=edge_effect_payload(decision_id, now, effect_id=effect_id),
                adapter=world.adapter, environment_id=world.environment_id, now=utcnow(),
            )))
        except BindingRefused as exc:
            outcomes.append(("refused", exc.code))

    threads = [threading.Thread(target=attempt, args=(f"effect:race-{i}",)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)
    kinds = sorted(kind for kind, _ in outcomes)
    assert kinds == ["ok", "refused"], outcomes
    assert [v for k, v in outcomes if k == "refused"] == ["effect_rejected"]
    winner = next(v for k, v in outcomes if k == "ok")

    # the same effect again is accepted; the loser's is not
    monkeypatch.setattr(_mf, "_coerce_effect", original)
    again = bind_reference_chain(
        admitted=admitted, signed_activation_decision=signed,
        defensive_effect_ref=edge_effect_payload(decision_id, now, effect_id=winner.effect_ref),
        adapter=world.adapter, environment_id=world.environment_id, now=utcnow(),
    )
    assert again.effect_ref == winner.effect_ref


def test_r2_binding_marker_is_private_and_not_in_runtime_state(world):
    _, plan, _, _, _, chain = _bind(world)
    assert "mio_bound_effect_ref" not in world.adapter.collect_status(world.environment_id)
    directory = world.adapter.state.root / "mio_bindings"
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    files = list(directory.iterdir())
    assert len(files) == 1 and stat.S_IMODE(files[0].stat().st_mode) == 0o600


def test_mb_concurrent_observers_never_duplicate_ids_and_the_bundle_verifies(world):
    _, plan, _, _, _, chain = _bind(world)
    ids: list[str] = []
    errors: list[Exception] = []
    start = threading.Barrier(4, timeout=10)

    def work():
        try:
            observer = _observer(world, chain, plan)
            start.wait()
            for _ in range(15):
                ids.append(observer.record(
                    observation_class="interaction", surface="service").observation_id)
        except Exception as exc:  # noqa: BLE001 - surfaced below
            errors.append(exc)

    threads = [threading.Thread(target=work) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert not errors, errors
    assert len(ids) == 60 and len(set(ids)) == 60
    bundle = _bundle(world, chain)
    verify_feedback_bundle(bundle, **_kw(world, chain))
    assert len(bundle["interactions"]) == 60
    assert world.adapter.verify_evidence(world.environment_id) is True


def test_ma_rewritten_caller_declared_is_caught_by_the_mac(world):
    """Declare a gap away: add the missing telemetry and an isolation assertion, in a
    self-consistent way. The rebuild would agree; only the MAC can disagree."""

    _, plan, _, _, _, chain = _bind(world)
    honest = _bundle(
        world, chain, observed_telemetry=("interaction_log",), isolation_assertion_refs=()
    )
    assert honest["outcome"]["coverage_complete"] is False
    forged = copy.deepcopy(honest)
    forged["caller_declared"]["observed_telemetry"] = ["interaction_log", "process_events", "network"]
    forged["caller_declared"]["isolation_assertion_refs"] = ["isolation-net-none"]
    forged["outcome"]["coverage_complete"] = True
    forged["outcome"]["telemetry_gaps"] = []
    forged["isolation"]["status"] = "asserted"
    forged["isolation"]["assertion_refs"] = ["isolation-net-none"]
    forged["limitations"] = [x for x in forged["limitations"] if not x.startswith("telemetry_gap:")
                             and x != "isolation_not_asserted"]
    assert "caller_declared_mac" in honest
    with pytest.raises(BindingRefused) as refused:
        verify_feedback_bundle(forged, **_kw(world, chain))
    assert refused.value.code == "evidence_tampered"
    # the MAC alone, on an otherwise untouched bundle
    only_mac = copy.deepcopy(honest)
    only_mac["caller_declared_mac"] = "0" * 64
    with pytest.raises(BindingRefused) as refused:
        verify_feedback_bundle(only_mac, **_kw(world, chain))
    assert refused.value.code == "evidence_tampered"


def test_freshness_observed_at_alone_cannot_be_rewritten(world):
    _, plan, _, _, _, chain = _bind(world)
    _observer(world, chain, plan).record(observation_class="interaction", surface="service")
    bundle = _bundle(world, chain)
    forged = copy.deepcopy(bundle)
    forged["freshness"]["observed_at"] = (utcnow() - timedelta(hours=3)).isoformat()
    with pytest.raises(BindingRefused):
        verify_feedback_bundle(forged, **_kw(world, chain))
    assert bundle["freshness"]["anchor_kind"] in {"last_interaction", "activation"}
    quiet = _bind_fresh_activation_anchor(world)
    assert quiet == "activation"


def _bind_fresh_activation_anchor(world):
    world.terminate()
    world.adapter.reset_environment(world.environment_id)
    _, plan, _, _, _, chain = _bind(world)
    return _bundle(world, chain)["freshness"]["anchor_kind"]


def test_la_caller_cannot_assert_outside_lease(world):
    _, plan, _, _, _, chain = _bind(world)
    with pytest.raises(ValueError):
        _observer(world, chain, plan).record(
            observation_class="interaction", surface="service", metadata={"outside_lease": True}
        )
    with pytest.raises(ValueError):
        _observer(world, chain, plan).record(
            observation_class="interaction", surface="service", metadata={"outside_lease": False}
        )


def _key_file(world):
    keys = sorted((world.adapter.state.root / "mio_feedback_keys").glob("*.key"))
    assert keys, "no session key file was created"
    return keys[-1]


@pytest.mark.parametrize(
    "damage",
    [
        lambda path: path.write_text(""),
        lambda path: os.chmod(path, 0o644),
        lambda path: path.write_text("ab" * 8),
        lambda path: path.write_text("ab" * 40),
    ],
    ids=["empty", "mode_0644", "short", "long"],
)
def test_lb_damaged_session_key_is_evidence_tampered(world, damage):
    _, plan, _, _, _, chain = _bind(world)
    _observer(world, chain, plan).record(
        observation_class="interaction", surface="service", untrusted_text="probe"
    )
    bundle = _bundle(world, chain)
    key = _key_file(world)
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert stat.S_IMODE(key.parent.stat().st_mode) == 0o700
    damage(key)
    with pytest.raises(BindingRefused) as refused:
        verify_feedback_bundle(bundle, **_kw(world, chain))
    assert refused.value.code == "evidence_tampered"


def test_lb_session_key_survives_reset_for_later_digest_checks(world):
    _, plan, _, _, _, chain = _bind(world)
    _observer(world, chain, plan).record(
        observation_class="interaction", surface="service", untrusted_text="probe"
    )
    key = _key_file(world)
    world.terminate()
    world.adapter.reset_environment(world.environment_id)
    reset_feedback(world.adapter, chain, now=utcnow())
    assert key.exists()


def test_mc_coverage_distinguishes_confounded_outside_lease_and_unmapped(world):
    _, plan, _, objective, _, chain = _bind(world)
    observer = _observer(world, chain, plan)
    observer.record(
        observation_class="interaction", surface="service", confounder_tags=["scanner_noise"]
    )
    late = chain.lease_end + timedelta(seconds=1)
    bound_observer(world.adapter, chain, world.package, plan, now_fn=lambda: late).record(
        observation_class="interaction", surface="credential_lure"
    )
    bundle = _bundle(
        world, chain, now=late, objective=objective,
        surface_telemetry={"service": "interaction_log", "credential_lure": "process_events"},
    )
    status = {(e["observation_class"], e["surface"]): e for e in bundle["objective_coverage"]["entries"]}
    service = status[("interaction", "service")]
    lure = status[("interaction", "credential_lure")]
    assert service["status"] == "observed_confounded_only"
    assert service["observed_count"] >= 1 and service["confounded_count"] >= 1
    assert lure["status"] == "observed_outside_lease_only"
    assert lure["outside_lease_count"] >= 1

    unmapped = _bundle(world, chain, now=late, objective=objective, surface_telemetry={})
    for entry in unmapped["objective_coverage"]["entries"]:
        if entry["observed_count"] == 0:
            assert entry["status"] == f"undeterminable_unmapped_surface:{entry['surface']}"
    assert "desired_observations_not_hypothesis_specific" in bundle["limitations"]
    assert "tactical" not in json.dumps(bundle["objective_coverage"]).lower()


# --- key and marker hygiene, remaining cases -------------------------------------


def _bundle_with_key(world):
    _, plan, signed, _, admitted, chain = _bind(world)
    _observer(world, chain, plan).record(
        observation_class="interaction", surface="service", untrusted_text="probe"
    )
    return plan, signed, admitted, chain, _bundle(world, chain)


def test_lb_symlinked_session_key_is_evidence_tampered(world, tmp_path):
    plan, signed, admitted, chain, bundle = _bundle_with_key(world)
    key = _key_file(world)
    decoy = tmp_path / "decoy.key"
    decoy.write_bytes(key.read_bytes())
    os.chmod(decoy, 0o600)
    key.unlink()
    key.symlink_to(decoy)
    with pytest.raises(BindingRefused) as refused:
        verify_feedback_bundle(bundle, **_kw(world, chain))
    assert refused.value.code == "evidence_tampered"


def test_lb_keys_directory_mode_0755_makes_build_evidence_tampered(world):
    plan, signed, admitted, chain, bundle = _bundle_with_key(world)
    directory = _key_file(world).parent
    os.chmod(directory, 0o755)
    with pytest.raises(BindingRefused) as refused:
        _bundle(world, chain)
    assert refused.value.code == "evidence_tampered"


def test_bindings_directory_mode_0755_makes_bind_evidence_tampered(world):
    decision_id, plan, signed, _, admitted, chain = _bind(world)
    directory = world.adapter.state.root / "mio_bindings"
    os.chmod(directory, 0o755)
    with pytest.raises(BindingRefused) as refused:
        bind_reference_chain(
            admitted=admitted, signed_activation_decision=signed,
            defensive_effect_ref=edge_effect_payload(decision_id, utcnow()),
            adapter=world.adapter, environment_id=world.environment_id, now=utcnow(),
        )
    assert refused.value.code == "evidence_tampered"


def test_l1_verify_never_creates_a_key(world):
    import shutil

    plan, signed, admitted, chain, bundle = _bundle_with_key(world)
    directory = world.adapter.state.root / "mio_feedback_keys"
    shutil.rmtree(directory)
    with pytest.raises(BindingRefused) as refused:
        verify_feedback_bundle(bundle, **_kw(world, chain))
    assert refused.value.code == "evidence_tampered"
    assert not directory.exists() or not list(directory.glob("*.key")), "verify recreated a key"
    for fn in _consumers():
        with pytest.raises(BindingRefused):
            fn(bundle, **_kw(world, chain))
    assert not directory.exists() or not list(directory.glob("*.key"))


# --- review M1/M2 regressions ------------------------------------------------


def _kw_at(world, chain, now):
    return dict(expected_chain=chain, state=world.adapter.state, now=now, max_age=MAX_AGE)


def test_consumer_age_reflects_consumption_time_not_build_time(world):
    """freshness_seconds and lifecycle use the consumer's now, not the build's."""

    _, plan, _, objective, _, chain = _bind(world)
    _observer(world, chain, plan).record(observation_class="interaction", surface="service")
    built = utcnow()
    bundle = _bundle(world, chain, now=built, objective=objective)
    anchor = bundle["freshness"]["observed_at"]

    early = mio_frame_inputs(bundle, **_kw_at(world, chain, built))
    later_now = built + timedelta(seconds=100)
    later = mio_frame_inputs(bundle, **_kw_at(world, chain, later_now))
    assert later["freshness_seconds"] - early["freshness_seconds"] in (99, 100, 101)
    assert later["freshness_seconds"] <= MAX_AGE
    assert later["freshness_seconds"] == int(
        (later_now - datetime.fromisoformat(anchor.replace("Z", "+00:00"))).total_seconds()
    )
    context = mio_deception_context(bundle, **_kw_at(world, chain, later_now))
    # Persisted evidence-log "active" is not an independent runtime verification.
    assert context["lifecycle_state"] == "unknown"

    # Past max_age at consumption time: refused, never reported as active.
    too_late = built + timedelta(seconds=MAX_AGE + 1)
    with pytest.raises(BindingRefused) as refused:
        mio_deception_context(bundle, **_kw_at(world, chain, too_late))
    assert refused.value.code == "stale"
    with pytest.raises(BindingRefused):
        mio_frame_inputs(bundle, **_kw_at(world, chain, too_late))


def test_caller_only_coverage_never_becomes_a_known_fact(world):
    _, plan, _, objective, _, chain = _bind(world)
    _observer(world, chain, plan).record(observation_class="interaction", surface="service")
    bundle = _bundle(
        world, chain, objective=objective,
        surface_telemetry={"service": "interaction_log", "credential_lure": "process_events"},
    )
    status = {(e["observation_class"], e["surface"]): e["status"]
              for e in bundle["objective_coverage"]["entries"]}
    assert status[("interaction", "credential_lure")] == "not_observed_with_coverage"

    inputs = mio_frame_inputs(bundle, **_kw(world, chain))
    assert not any("NOT_OBSERVED" in fact for fact in inputs["known_facts"])
    assert "DECEPTION_DESIRED_OBSERVED_INTERACTION_SERVICE" in inputs["known_facts"]
    assert "DECEPTION_DESIRED_NOT_OBSERVED_CALLER_DECLARED_COVERAGE_INTERACTION_CREDENTIAL_LURE" \
        in inputs["unknowns"]
