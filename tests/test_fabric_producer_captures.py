"""Consumer test: Azazel-Edge's real producer output through Deception's consumers.

Fabric publishes, in ``azazel_fabric.testing``, captures of what real producers
emitted (Azazel-Edge e84af9a, Azazel-Deception 305af85). This module feeds the
**Edge-produced** ones (``product="edge"``) to the Deception code that receives
Edge payloads. Deception's own captures are deliberately not used: reading
your own output is not an independent consumer test.

Consumer code exercised
-----------------------
* deception : ``runtime/transitions.py`` ``TransitionExecutor.execute``
              <- Edge ``EnvironmentTransitionDecision`` (signed, unsigned, from-arbiter)
* effect    : ``runtime/effect_projection.py`` ``accept_defensive_effect_ref``
              <- Edge ``DefensiveEffectRef``
* outcome   : ``runtime/producer_evidence.py``
              ``producer_redirection_from_shared_mechanism``
              <- Edge ``MechanismObservationV0``

Out of scope (Deception consumes no such model, so there is nothing to test):
``EngagementCandidate``, ``EngagementEvent``, ``ExecutionRefV0``,
``OutcomeObservationV0`` and ``TacticalEffectAssessmentRefV0``.

Derived cases
-------------
Edge's captures contain no ``redirect_to_presented_terrain`` effect and no
*observed* redirection mechanism, so nothing Edge emitted is acceptable to the
two narrowing consumers. Positive controls and the planned_shadow case are
therefore built from a real capture with one named field changed; each says so
and is labelled ``derived``. They prove the consumer's rule, not Edge's output.

Valid with Fabric >= v0.10.0rc1 (captures landed after v0.9.0); skipped on
v0.9.0, where the repository pin stays.
"""

from __future__ import annotations

import copy

import pytest

_testing = pytest.importorskip("azazel_fabric.testing")
if not hasattr(_testing, "producer_capture_names"):  # Fabric < v0.10.0rc1
    pytest.skip(
        "requires azazel_fabric >= v0.10.0rc1 producer captures (valid from v0.10.0rc1 on)",
        allow_module_level=True,
    )

from azazel_fabric.testing import (  # noqa: E402
    GOLDEN_DECISION_SIGNATURE_KEY,
    load_producer_capture,
    make_transition_catalog,
    producer_capture_body,
    producer_capture_names,
    producer_capture_provenance,
)

from azazel_deception.runtime.compose import RuntimeGateError  # noqa: E402
from azazel_deception.runtime.effect_projection import (  # noqa: E402
    EffectRefRejected,
    accept_defensive_effect_ref,
)
from azazel_deception.runtime.producer_evidence import (  # noqa: E402
    producer_redirection_from_shared_mechanism,
)
from azazel_deception.runtime.state import RuntimeStateStore  # noqa: E402
from azazel_deception.runtime.transitions import TransitionExecutor  # noqa: E402
from azazel_deception.runtime.transport import HmacDecisionAuthenticator  # noqa: E402

# Inside every Edge transition capture's [effective_at, expires_at).
AS_OF = "2026-08-21T00:00:00+00:00"
EDGE_EXEC_ARGS = dict(
    environment_id="env-1", current_state="baseline", transition_id="open-smb-share"
)


def _edge(name: str) -> str:
    return f"edge/{name}_v0"


def _payload(name: str) -> dict:
    return copy.deepcopy(load_producer_capture(_edge(name)))


def _strict(tmp_path) -> TransitionExecutor:
    return TransitionExecutor.strict(
        make_transition_catalog(),
        decision_authenticator=HmacDecisionAuthenticator(GOLDEN_DECISION_SIGNATURE_KEY),
        state=RuntimeStateStore(tmp_path),
    )


def _lenient() -> TransitionExecutor:
    return TransitionExecutor(make_transition_catalog())


def test_the_edge_captures_are_what_this_module_assumes():
    names = producer_capture_names(product="edge")
    for needed in (
        "deception_transition_signed", "deception_transition_unsigned",
        "deception_transition_from_arbiter", "effect_isolation",
        "effect_traffic_shaping", "outcome_mechanism_redirect",
        "outcome_mechanism_throttle_observed",
        "outcome_mechanism_route_change_degraded_to_unknown",
    ):
        assert _edge(needed) in names
    for name in names:
        prov = producer_capture_provenance(name)
        assert prov["product"] == "edge"
        assert prov["repository"] == "01rabbit/Azazel-Edge"


# ---------------------------------------------------------------- transitions


def test_signed_edge_transition_passes_mac_and_drives_the_strict_executor(tmp_path):
    name = _edge("deception_transition_signed")
    assert producer_capture_provenance(name)["signed"] is True
    signed = load_producer_capture(name)
    assert "decision_signature" in signed
    # The body Fabric validates is the capture minus the MAC.
    assert producer_capture_body(name) == {
        k: v for k, v in signed.items() if k != "decision_signature"
    }

    result = _strict(tmp_path).execute(edge_decision=signed, as_of=AS_OF, **EDGE_EXEC_ARGS)

    assert result["status"] == "shadow_simulated"
    assert result["edge_decision_id"] == signed["decision_id"]
    assert result["from_state"] == "baseline"
    assert result["to_state"] == "smb-share-open"
    assert result["enforcement_applied"] is False


def test_signed_edge_transition_is_one_shot(tmp_path):
    signed = load_producer_capture(_edge("deception_transition_signed"))
    executor = _strict(tmp_path)
    executor.execute(edge_decision=signed, as_of=AS_OF, **EDGE_EXEC_ARGS)
    with pytest.raises(RuntimeGateError, match="already consumed"):
        executor.execute(edge_decision=signed, as_of=AS_OF, **EDGE_EXEC_ARGS)


def test_tampered_signed_edge_transition_fails_the_mac_check(tmp_path):
    # derived: a real capture with the target state rewritten, MAC left as signed
    tampered = _payload("deception_transition_signed")
    tampered["target_state"] = "somewhere-else"
    with pytest.raises(RuntimeGateError, match="authentication"):
        _strict(tmp_path).execute(edge_decision=tampered, as_of=AS_OF, **EDGE_EXEC_ARGS)


def test_signed_edge_transition_is_rejected_under_a_different_key(tmp_path):
    other = TransitionExecutor.strict(
        make_transition_catalog(),
        decision_authenticator=HmacDecisionAuthenticator("not-the-golden-key"),
        state=RuntimeStateStore(tmp_path),
    )
    with pytest.raises(RuntimeGateError, match="authentication"):
        other.execute(
            edge_decision=load_producer_capture(_edge("deception_transition_signed")),
            as_of=AS_OF, **EDGE_EXEC_ARGS,
        )


@pytest.mark.parametrize("name", ["deception_transition_unsigned", "deception_transition_from_arbiter"])
def test_unsigned_edge_transition_is_refused_by_the_strict_executor(tmp_path, name):
    with pytest.raises(RuntimeGateError, match="authentication"):
        _strict(tmp_path).execute(
            edge_decision=load_producer_capture(_edge(name)), as_of=AS_OF, **EDGE_EXEC_ARGS
        )


@pytest.mark.parametrize("name", ["deception_transition_unsigned", "deception_transition_from_arbiter"])
def test_unsigned_edge_transition_binds_when_no_authenticator_is_required(name):
    decision = load_producer_capture(_edge(name))
    result = _lenient().execute(edge_decision=decision, as_of=AS_OF, **EDGE_EXEC_ARGS)
    assert result["edge_decision_id"] == decision["decision_id"]
    assert result["status"] == "shadow_simulated"


def test_from_arbiter_transition_carries_edge_evidence_and_reason():
    # What Deception does not read must still have validated: the capture is
    # accepted whole by the Fabric model inside the executor.
    decision = load_producer_capture(_edge("deception_transition_from_arbiter"))
    assert decision["evidence_refs"] == ["ev-soc-1", "ev-noc-1"]
    assert decision["reason_codes"] == ["soc_high_confidence_redirect_is_preferred"]
    assert _lenient().execute(edge_decision=decision, as_of=AS_OF, **EDGE_EXEC_ARGS)


@pytest.mark.parametrize(
    "field,value,match",
    [
        ("environment_id", "env-2", "environment_id"),
        ("current_state", "other-state", "current_state"),
        ("target_state", "other-state", "target_state"),
        ("status", "rejected", "status"),
        ("schema_version", "environment-transition-decision/v9.9", "not a valid transition decision"),
    ],
)
def test_edge_transition_with_one_binding_changed_is_refused(field, value, match):
    # derived: unsigned capture with a single field changed
    decision = _payload("deception_transition_unsigned")
    decision[field] = value
    with pytest.raises(RuntimeGateError, match=match):
        _lenient().execute(edge_decision=decision, as_of=AS_OF, **EDGE_EXEC_ARGS)


@pytest.mark.parametrize(
    "as_of,match",
    [
        ("2026-08-20T23:59:59+00:00", "not yet effective"),
        ("2026-08-21T00:05:00+00:00", "expired"),  # expires_at is exclusive
    ],
)
def test_edge_transition_outside_its_window_is_refused(as_of, match):
    decision = load_producer_capture(_edge("deception_transition_unsigned"))
    with pytest.raises(RuntimeGateError, match=match):
        _lenient().execute(edge_decision=decision, as_of=as_of, **EDGE_EXEC_ARGS)


# -------------------------------------------------------------------- effects


@pytest.mark.parametrize(
    "name,effect_class",
    [("effect_traffic_shaping", "rate_limit"), ("effect_isolation", "network_isolation")],
)
def test_edge_effects_are_authoritative_but_not_presentable_so_are_refused(name, effect_class):
    """Real Edge effects are decided (producer_decision_ref) yet are not
    redirect_to_presented_terrain, so Deception declines them on class."""
    payload = load_producer_capture(_edge(name))
    assert payload["authority_class"] == "producer_decision_ref"
    assert payload["effect_class"] == effect_class
    with pytest.raises(EffectRefRejected, match="Presented Terrain has no meaning"):
        accept_defensive_effect_ref(payload)


def test_derived_redirect_effect_from_edge_is_accepted():
    # derived (positive control): real Edge effect, effect_class changed
    payload = _payload("effect_isolation")
    payload["effect_class"] = "redirect_to_presented_terrain"
    effect = accept_defensive_effect_ref(payload)
    assert effect.effect_id == payload["effect_id"]
    assert effect.producer_product == "azazel-edge"
    assert effect.decision_ref == "decision-1"
    assert effect.trace_id == "trace-1"


def test_derived_planned_shadow_effect_from_edge_is_not_bound_to_live():
    # derived: a redirect effect with no decision, claiming planned_shadow.
    payload = _payload("effect_isolation")
    payload["effect_class"] = "redirect_to_presented_terrain"
    payload["authority_class"] = "planned_shadow"
    payload["decision_ref"] = None
    with pytest.raises(EffectRefRejected, match="planned_shadow"):
        accept_defensive_effect_ref(payload)


def test_derived_advisory_effect_from_edge_is_not_materialized():
    payload = _payload("effect_isolation")
    payload["effect_class"] = "redirect_to_presented_terrain"
    payload["authority_class"] = "advisory_inference"
    payload["decision_ref"] = None
    payload["advisory_ref"] = "advisory:advisory-1"  # Fabric: an advisory must name its advisory
    with pytest.raises(EffectRefRejected, match="advisory_inference"):
        accept_defensive_effect_ref(payload)


# ------------------------------------------------------------------- outcomes


def test_edge_unverified_redirection_is_not_evidence():
    payload = load_producer_capture(_edge("outcome_mechanism_redirect"))
    assert (payload["mechanism_kind"], payload["status"]) == ("redirection", "unverified")
    with pytest.raises(ValueError, match="not independently observed"):
        producer_redirection_from_shared_mechanism(payload)


@pytest.mark.parametrize(
    "name,match",
    [
        ("outcome_mechanism_throttle", "requires observed redirection"),
        ("outcome_mechanism_throttle_observed", "requires observed redirection"),
        ("outcome_mechanism_route_change_degraded_to_unknown", "requires observed redirection"),
    ],
)
def test_edge_non_redirection_mechanisms_are_not_presented_terrain_linkage(name, match):
    with pytest.raises(ValueError, match=match):
        producer_redirection_from_shared_mechanism(load_producer_capture(_edge(name)))


def test_derived_observed_redirection_from_edge_projects_references_only():
    # derived (positive control): the real redirect capture with status=observed
    payload = _payload("outcome_mechanism_redirect")
    payload["status"] = "observed"
    evidence = producer_redirection_from_shared_mechanism(payload)
    assert evidence.producer_product == "azazel-edge"
    assert evidence.producer_node == "edge-1"
    assert evidence.trace_id == "trace-test-1"
    assert evidence.decision_ref == "trace-test-1"
    assert evidence.execution_ref == payload["execution_ref"]
    assert evidence.mechanism_observation_ref == payload["observation_id"]
    assert evidence.mechanism_kind == "redirection"
    assert evidence.evidence_refs == ("rust_event_engine_v1:trace-test-1",)


def test_derived_observed_redirection_without_evidence_refs_is_refused():
    payload = _payload("outcome_mechanism_redirect")
    payload["status"] = "observed"
    payload["evidence_refs"] = []
    with pytest.raises(ValueError, match="evidence refs"):
        producer_redirection_from_shared_mechanism(payload)
