"""Tests for AZ-06's finite-state transition executor (Deception#6)."""

from __future__ import annotations

from typing import Any

import pytest
from azazel_fabric.testing import make_transition_catalog

from azazel_fabric.deception_contracts import EnvironmentTransitionDecision

from azazel_deception.runtime.compose import RuntimeGateError
from azazel_deception.runtime.state import RuntimeStateStore
from azazel_deception.runtime.transitions import TransitionExecutor
from azazel_deception.runtime.transport import HmacDecisionAuthenticator, sign_decision

AS_OF = "2026-08-21T00:00:00+00:00"
_KEY = "test-edge-transport-key"
_EFFECTIVE = "2026-08-20T00:00:00+00:00"
_EXPIRES = "2026-08-22T00:00:00+00:00"


def _canonical(**over):
    """A canonical Fabric EnvironmentTransitionDecision as a dict envelope."""
    base = dict(
        decision_id="edge-decision-1",
        status="accepted",
        environment_id="env-1",
        current_state="baseline",
        target_state="smb-share-open",
        effective_at=_EFFECTIVE,
        expires_at=_EXPIRES,
    )
    base.update(over)
    return EnvironmentTransitionDecision(**base).model_dump(mode="json")


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


def test_strict_replay_protection_requires_a_state_store():
    executor = _executor(require_replay_protection=True)  # no state store
    with pytest.raises(RuntimeGateError, match="replay protection required"):
        executor.execute(
            environment_id="env-1",
            current_state="baseline",
            transition_id="open-smb-share",
            edge_decision=_approved_decision(),
            as_of=AS_OF,
        )


# -- decision expiry ---------------------------------------------------------


def test_expired_decision_fails_closed():
    executor = _executor()
    with pytest.raises(RuntimeGateError, match="expired"):
        executor.execute(
            environment_id="env-1",
            current_state="baseline",
            transition_id="open-smb-share",
            edge_decision=_approved_decision(expires_at="2026-08-20T00:00:00+00:00"),
            as_of=AS_OF,  # 2026-08-21, strictly after expiry
        )


def test_far_future_as_of_cannot_replay_an_expiring_decision():
    # The finding: an approved decision replayed with an arbitrary far-future
    # as_of. With an expiry present, that is now refused.
    executor = _executor()
    decision = _approved_decision(expires_at="2026-08-21T01:00:00+00:00")
    ok = executor.execute(
        environment_id="env-1",
        current_state="baseline",
        transition_id="open-smb-share",
        edge_decision=decision,
        as_of="2026-08-21T00:30:00+00:00",  # before expiry
    )
    assert ok["status"] == "shadow_simulated"
    with pytest.raises(RuntimeGateError, match="expired"):
        executor.execute(
            environment_id="env-1",
            current_state="baseline",
            transition_id="open-smb-share",
            edge_decision=decision,
            as_of="2030-01-01T00:00:00+00:00",  # long past expiry
        )


def test_unexpired_decision_is_accepted():
    executor = _executor()
    result = executor.execute(
        environment_id="env-1",
        current_state="baseline",
        transition_id="open-smb-share",
        edge_decision=_approved_decision(expires_at="2999-01-01T00:00:00+00:00"),
        as_of=AS_OF,
    )
    assert result["status"] == "shadow_simulated"


def test_strict_expiry_requires_the_field():
    executor = _executor(require_decision_expiry=True)
    with pytest.raises(RuntimeGateError, match="missing a required expires_at"):
        executor.execute(
            environment_id="env-1",
            current_state="baseline",
            transition_id="open-smb-share",
            edge_decision=_approved_decision(),  # no expires_at
            as_of=AS_OF,
        )


def test_unparseable_expiry_fails_closed():
    executor = _executor()
    with pytest.raises(RuntimeGateError, match="valid ISO-8601"):
        executor.execute(
            environment_id="env-1",
            current_state="baseline",
            transition_id="open-smb-share",
            edge_decision=_approved_decision(expires_at="not-a-timestamp"),
            as_of=AS_OF,
        )


# -- canonical Fabric EnvironmentTransitionDecision path --------------------


def test_canonical_decision_is_accepted_and_shadow_simulated():
    executor = _executor()
    result = executor.execute(
        environment_id="env-1", current_state="baseline",
        transition_id="open-smb-share", edge_decision=_canonical(), as_of=AS_OF,
    )
    assert result["status"] == "shadow_simulated"
    assert result["edge_decision_id"] == "edge-decision-1"
    assert result["to_state"] == "smb-share-open"


def test_canonical_decision_model_instance_is_accepted():
    executor = _executor()
    decision = EnvironmentTransitionDecision(
        decision_id="edge-decision-1", status="accepted", environment_id="env-1",
        current_state="baseline", target_state="smb-share-open",
        effective_at=_EFFECTIVE, expires_at=_EXPIRES,
    )
    result = executor.execute(
        environment_id="env-1", current_state="baseline",
        transition_id="open-smb-share", edge_decision=decision, as_of=AS_OF,
    )
    assert result["status"] == "shadow_simulated"


def test_canonical_rejected_status_fails_closed():
    executor = _executor()
    with pytest.raises(RuntimeGateError, match="not executable"):
        executor.execute(
            environment_id="env-1", current_state="baseline",
            transition_id="open-smb-share", edge_decision=_canonical(status="rejected"),
            as_of=AS_OF,
        )


def test_canonical_wrong_environment_fails_closed():
    executor = _executor()
    with pytest.raises(RuntimeGateError, match="environment_id"):
        executor.execute(
            environment_id="env-1", current_state="baseline",
            transition_id="open-smb-share", edge_decision=_canonical(environment_id="env-2"),
            as_of=AS_OF,
        )


def test_canonical_target_state_mismatch_fails_closed():
    executor = _executor()
    with pytest.raises(RuntimeGateError, match="target_state"):
        executor.execute(
            environment_id="env-1", current_state="baseline",
            transition_id="open-smb-share",
            edge_decision=_canonical(target_state="some-other-state"), as_of=AS_OF,
        )


def test_canonical_current_state_mismatch_fails_closed():
    executor = _executor()
    with pytest.raises(RuntimeGateError, match="current_state"):
        executor.execute(
            environment_id="env-1", current_state="smb-share-open",
            transition_id="open-smb-share", edge_decision=_canonical(current_state="smb-share-open"),
            as_of=AS_OF,
        )


def test_canonical_expired_fails_closed():
    executor = _executor()
    with pytest.raises(RuntimeGateError, match="expired"):
        executor.execute(
            environment_id="env-1", current_state="baseline",
            transition_id="open-smb-share", edge_decision=_canonical(),
            as_of="2026-08-23T00:00:00+00:00",
        )


def test_canonical_not_yet_effective_fails_closed():
    executor = _executor()
    with pytest.raises(RuntimeGateError, match="not yet effective"):
        executor.execute(
            environment_id="env-1", current_state="baseline",
            transition_id="open-smb-share", edge_decision=_canonical(),
            as_of="2026-08-19T00:00:00+00:00",
        )


def test_canonical_extra_field_fails_closed():
    executor = _executor()
    bad = _canonical()
    bad["force_execute"] = True
    with pytest.raises(RuntimeGateError, match="not a valid transition decision"):
        executor.execute(
            environment_id="env-1", current_state="baseline",
            transition_id="open-smb-share", edge_decision=bad, as_of=AS_OF,
        )


def test_canonical_unknown_schema_version_fails_closed():
    executor = _executor()
    bad = _canonical()
    bad["schema_version"] = "environment-transition-decision/v9.9"
    with pytest.raises(RuntimeGateError, match="not a valid transition decision"):
        executor.execute(
            environment_id="env-1", current_state="baseline",
            transition_id="open-smb-share", edge_decision=bad, as_of=AS_OF,
        )


def test_require_canonical_decision_rejects_interim_dict():
    executor = _executor(require_canonical_decision=True)
    with pytest.raises(RuntimeGateError, match="canonical"):
        executor.execute(
            environment_id="env-1", current_state="baseline",
            transition_id="open-smb-share", edge_decision=_approved_decision(), as_of=AS_OF,
        )


def test_canonical_signed_decision_authenticates():
    executor = _executor(decision_authenticator=HmacDecisionAuthenticator(_KEY))
    signed = sign_decision(_canonical(), _KEY)
    result = executor.execute(
        environment_id="env-1", current_state="baseline",
        transition_id="open-smb-share", edge_decision=signed, as_of=AS_OF,
    )
    assert result["status"] == "shadow_simulated"
    assert result["edge_decision_id"] == "edge-decision-1"


def test_canonical_replay_fails_closed(tmp_path):
    state = RuntimeStateStore(tmp_path)
    executor = TransitionExecutor(make_transition_catalog(), state=state)
    kwargs = dict(
        environment_id="env-1", current_state="baseline",
        transition_id="open-smb-share", edge_decision=_canonical(), as_of=AS_OF,
    )
    assert executor.execute(**kwargs)["status"] == "shadow_simulated"
    with pytest.raises(RuntimeGateError, match="already consumed"):
        executor.execute(**kwargs)


# -- strict-posture convenience constructor (adversarial-review hardening) ----


def test_strict_constructor_enables_all_gates(tmp_path):
    state = RuntimeStateStore(tmp_path)
    executor = TransitionExecutor.strict(
        make_transition_catalog(),
        decision_authenticator=HmacDecisionAuthenticator(_KEY),
        state=state,
    )
    assert executor.require_authenticated_decisions
    assert executor.require_replay_protection
    assert executor.require_decision_expiry
    assert executor.require_canonical_decision
    # A validly-signed canonical decision passes end to end...
    signed = sign_decision(_canonical(), _KEY)
    assert executor.execute(
        environment_id="env-1", current_state="baseline",
        transition_id="open-smb-share", edge_decision=signed, as_of=AS_OF,
    )["status"] == "shadow_simulated"
    # ...and a replay of it is refused (anti-replay is on)...
    with pytest.raises(RuntimeGateError, match="already consumed"):
        executor.execute(
            environment_id="env-1", current_state="baseline",
            transition_id="open-smb-share", edge_decision=signed, as_of=AS_OF,
        )


def test_strict_constructor_rejects_interim_and_unsigned(tmp_path):
    executor = TransitionExecutor.strict(
        make_transition_catalog(),
        decision_authenticator=HmacDecisionAuthenticator(_KEY),
        state=RuntimeStateStore(tmp_path),
    )
    # A *signed* interim dict passes authentication but is then rejected for
    # not being the canonical contract (require_canonical_decision).
    with pytest.raises(RuntimeGateError, match="canonical"):
        executor.execute(
            environment_id="env-1", current_state="baseline",
            transition_id="open-smb-share",
            edge_decision=sign_decision(_approved_decision(), _KEY), as_of=AS_OF,
        )
    # canonical but UNSIGNED -> rejected at authentication (require_authenticated_decisions)
    with pytest.raises(RuntimeGateError, match="authentication"):
        executor.execute(
            environment_id="env-1", current_state="baseline",
            transition_id="open-smb-share", edge_decision=_canonical(), as_of=AS_OF,
        )
