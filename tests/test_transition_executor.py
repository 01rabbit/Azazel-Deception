"""Tests for AZ-06's finite-state transition executor (Deception#6)."""

from __future__ import annotations

from typing import Any

import pytest
from azazel_fabric.testing import make_transition_catalog

from azazel_deception.runtime.compose import RuntimeGateError
from azazel_deception.runtime.state import RuntimeStateStore
from azazel_deception.runtime.transitions import TransitionExecutor
from azazel_deception.runtime.transport import HmacDecisionAuthenticator, sign_decision

AS_OF = "2026-08-21T00:00:00+00:00"
_KEY = "test-edge-transport-key"


def _approved_decision(**overrides: Any) -> dict[str, Any]:
    decision = {
        "transition_id": "open-smb-share",
        "edge_decision_id": "edge-decision-1",
        "status": "approved",
    }
    decision.update(overrides)
    return decision


def _executor(**kwargs: Any) -> TransitionExecutor:
    return TransitionExecutor(make_transition_catalog(), **kwargs)


def test_edge_approved_in_catalog_transition_is_shadow_simulated_by_default():
    executor = _executor()
    result = executor.execute(
        environment_id="env-1",
        current_state="baseline",
        transition_id="open-smb-share",
        edge_decision=_approved_decision(),
        as_of=AS_OF,
    )
    assert result["status"] == "shadow_simulated"
    assert result["enforcement_applied"] is False
    assert result["live_enabled"] is False
    assert result["from_state"] == "baseline"
    assert result["to_state"] == "smb-share-open"
    assert result["transition_id"] == "open-smb-share"
    assert result["environment_id"] == "env-1"
    assert result["edge_decision_id"] == "edge-decision-1"


def test_live_enabled_still_performs_no_container_action():
    executor = _executor(live_enabled=True)
    result = executor.execute(
        environment_id="env-1",
        current_state="baseline",
        transition_id="open-smb-share",
        edge_decision=_approved_decision(),
        as_of=AS_OF,
    )
    assert result["status"] == "would_execute"
    assert result["enforcement_applied"] is False
    assert result["live_enabled"] is True


def test_tampered_catalog_digest_fails_closed():
    catalog = make_transition_catalog()
    executor = TransitionExecutor(catalog)
    # Mutate the catalog object in-place after sealing, without recomputing
    # catalog_digest -- a live tamper attempt, not a fresh (correctly sealed)
    # catalog.
    catalog.transitions[0].evidence_backed_trigger = "tampered-trigger"

    with pytest.raises(RuntimeGateError, match="digest"):
        executor.execute(
            environment_id="env-1",
            current_state="baseline",
            transition_id="open-smb-share",
            edge_decision=_approved_decision(),
            as_of=AS_OF,
        )


def test_tampered_declared_catalog_digest_field_also_fails_closed():
    catalog = make_transition_catalog()
    executor = TransitionExecutor(catalog)
    # Rewrite the declared digest field itself to match nothing sealed.
    catalog.catalog_digest = "sha256:" + "a" * 64

    with pytest.raises(RuntimeGateError, match="digest"):
        executor.execute(
            environment_id="env-1",
            current_state="baseline",
            transition_id="open-smb-share",
            edge_decision=_approved_decision(),
            as_of=AS_OF,
        )


def test_transition_not_in_catalog_fails_closed():
    executor = _executor()
    with pytest.raises(RuntimeGateError, match="not present"):
        executor.execute(
            environment_id="env-1",
            current_state="baseline",
            transition_id="no-such-transition",
            edge_decision=_approved_decision(transition_id="no-such-transition"),
            as_of=AS_OF,
        )


def test_missing_edge_decision_fails_closed():
    executor = _executor()
    with pytest.raises(RuntimeGateError):
        executor.execute(
            environment_id="env-1",
            current_state="baseline",
            transition_id="open-smb-share",
            edge_decision={},
            as_of=AS_OF,
        )


def test_unapproved_edge_decision_status_fails_closed():
    executor = _executor()
    with pytest.raises(RuntimeGateError, match="status"):
        executor.execute(
            environment_id="env-1",
            current_state="baseline",
            transition_id="open-smb-share",
            edge_decision=_approved_decision(status="rejected"),
            as_of=AS_OF,
        )


def test_edge_decision_for_a_different_transition_fails_closed():
    executor = _executor()
    with pytest.raises(RuntimeGateError, match="does not authorize"):
        executor.execute(
            environment_id="env-1",
            current_state="baseline",
            transition_id="open-smb-share",
            edge_decision=_approved_decision(transition_id="some-other-transition"),
            as_of=AS_OF,
        )


def test_missing_edge_decision_id_fails_closed():
    executor = _executor()
    with pytest.raises(RuntimeGateError, match="edge_decision_id"):
        executor.execute(
            environment_id="env-1",
            current_state="baseline",
            transition_id="open-smb-share",
            edge_decision=_approved_decision(edge_decision_id=""),
            as_of=AS_OF,
        )


def test_wrong_current_state_fails_closed():
    executor = _executor()
    with pytest.raises(RuntimeGateError, match="from_state"):
        executor.execute(
            environment_id="env-1",
            current_state="smb-share-open",
            transition_id="open-smb-share",
            edge_decision=_approved_decision(),
            as_of=AS_OF,
        )


def test_execute_is_deterministic_for_identical_inputs():
    executor = _executor()
    kwargs = dict(
        environment_id="env-1",
        current_state="baseline",
        transition_id="open-smb-share",
        edge_decision=_approved_decision(),
        as_of=AS_OF,
    )
    first = executor.execute(**kwargs)
    second = executor.execute(**kwargs)
    assert first == second


def test_execute_never_mutates_the_sealed_catalog_digest():
    catalog = make_transition_catalog()
    original_digest = catalog.catalog_digest
    executor = TransitionExecutor(catalog)
    executor.execute(
        environment_id="env-1",
        current_state="baseline",
        transition_id="open-smb-share",
        edge_decision=_approved_decision(),
        as_of=AS_OF,
    )
    assert catalog.catalog_digest == original_digest


# -- transport authentication (forgery) -------------------------------------


def test_forged_decision_fails_closed_when_authenticator_configured():
    executor = _executor(decision_authenticator=HmacDecisionAuthenticator(_KEY))
    # An "approved"-shaped dict with no valid signature must not pass once an
    # authenticator is wired: this is exactly the forgery the gate exists for.
    with pytest.raises(RuntimeGateError, match="authentication"):
        executor.execute(
            environment_id="env-1",
            current_state="baseline",
            transition_id="open-smb-share",
            edge_decision=_approved_decision(),
            as_of=AS_OF,
        )


def test_tampered_signed_decision_fails_closed():
    executor = _executor(decision_authenticator=HmacDecisionAuthenticator(_KEY))
    signed = sign_decision(_approved_decision(), _KEY)
    signed["status"] = "approved"  # unchanged
    signed["edge_decision_id"] = "swapped-after-signing"  # tamper post-signature
    with pytest.raises(RuntimeGateError, match="authentication"):
        executor.execute(
            environment_id="env-1",
            current_state="baseline",
            transition_id="open-smb-share",
            edge_decision=signed,
            as_of=AS_OF,
        )


def test_authentically_signed_decision_is_accepted():
    executor = _executor(decision_authenticator=HmacDecisionAuthenticator(_KEY))
    signed = sign_decision(_approved_decision(), _KEY)
    result = executor.execute(
        environment_id="env-1",
        current_state="baseline",
        transition_id="open-smb-share",
        edge_decision=signed,
        as_of=AS_OF,
    )
    assert result["status"] == "shadow_simulated"
    assert result["edge_decision_id"] == "edge-decision-1"


def test_strict_posture_requires_an_authenticator():
    executor = _executor(require_authenticated_decisions=True)
    with pytest.raises(RuntimeGateError, match="no authenticator is configured"):
        executor.execute(
            environment_id="env-1",
            current_state="baseline",
            transition_id="open-smb-share",
            edge_decision=_approved_decision(),
            as_of=AS_OF,
        )


# -- environment binding -----------------------------------------------------


def test_decision_bound_to_another_environment_fails_closed():
    executor = _executor()
    with pytest.raises(RuntimeGateError, match="environment_id"):
        executor.execute(
            environment_id="env-1",
            current_state="baseline",
            transition_id="open-smb-share",
            edge_decision=_approved_decision(environment_id="env-2"),
            as_of=AS_OF,
        )


def test_decision_bound_to_matching_environment_is_accepted():
    executor = _executor()
    result = executor.execute(
        environment_id="env-1",
        current_state="baseline",
        transition_id="open-smb-share",
        edge_decision=_approved_decision(environment_id="env-1"),
        as_of=AS_OF,
    )
    assert result["status"] == "shadow_simulated"


# -- one-shot anti-replay ----------------------------------------------------


def test_replayed_decision_fails_closed_with_state_store(tmp_path):
    state = RuntimeStateStore(tmp_path)
    executor = TransitionExecutor(make_transition_catalog(), state=state)
    kwargs = dict(
        environment_id="env-1",
        current_state="baseline",
        transition_id="open-smb-share",
        edge_decision=_approved_decision(),
        as_of=AS_OF,
    )
    first = executor.execute(**kwargs)
    assert first["status"] == "shadow_simulated"
    with pytest.raises(RuntimeGateError, match="already consumed"):
        executor.execute(**kwargs)


def test_distinct_decision_ids_are_not_replays(tmp_path):
    state = RuntimeStateStore(tmp_path)
    executor = TransitionExecutor(make_transition_catalog(), state=state)
    executor.execute(
        environment_id="env-1",
        current_state="baseline",
        transition_id="open-smb-share",
        edge_decision=_approved_decision(edge_decision_id="edge-decision-1"),
        as_of=AS_OF,
    )
    # A different, genuinely new decision id is not a replay.
    result = executor.execute(
        environment_id="env-1",
        current_state="baseline",
        transition_id="open-smb-share",
        edge_decision=_approved_decision(edge_decision_id="edge-decision-2"),
        as_of=AS_OF,
    )
    assert result["status"] == "shadow_simulated"
