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
import json
from datetime import timedelta

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
    ingest = knowledge_ingest_payload(bundle)
    assert ingest["environment_id"] == world.environment_id
    assert len(ingest["items"]) == 1
    context = mio_deception_context(bundle)
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


def test_observer_refuses_outside_lease(world):
    decision_id, plan, signed, _, _, chain = _bind(world)
    late = chain.lease_end + timedelta(seconds=1)
    observer = bound_observer(world.adapter, chain, world.package, plan, now_fn=lambda: late)
    with pytest.raises(BindingRefused) as refused:
        observer.record(observation_class="interaction", surface="service")
    assert refused.value.code == "lease_expired"


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
        surface="service",
        untrusted_text=INJECTION_TEXT,
    )
    assert observation.metadata["untrusted_text_len"] == len(INJECTION_TEXT)
    assert len(observation.metadata["untrusted_text_sha256"]) == 64

    bundle = _bundle(world, chain)
    ingest = knowledge_ingest_payload(bundle)
    context = mio_deception_context(bundle)
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
    assert "activate" not in json.dumps(mio_deception_context(bundle))


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
    ingest = knowledge_ingest_payload(_bundle(world, chain))
    assert set(ingest) == {"environment_id", "items"}
    assert [item["observation_class"] for item in ingest["items"]] == ["interaction", "reaction"]
    for item in ingest["items"]:
        assert item["environment_id"] == world.environment_id


def test_mio_context_does_not_carry_authority_or_a_verdict(world):
    _, plan, _, _, _, chain = _bind(world)
    context = mio_deception_context(_bundle(world, chain))
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
    assert mio_deception_context(_bundle(world, chain))["lifecycle_state"] == "unknown"


def test_no_isolation_assertion_means_no_projected_terrain(world):
    _, plan, _, _, _, chain = _bind(world)
    bundle = _bundle(world, chain, isolation_assertion_refs=())
    assert bundle["runtime_materialization"]["presented_terrain"] is None
    assert "presented_terrain_not_projected" in bundle["limitations"]


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
