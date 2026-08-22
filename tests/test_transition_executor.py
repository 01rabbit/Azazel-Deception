"""Tests for AZ-06's finite-state transition executor (Deception#6).

Canonical-only: the legacy interim decision shape has been retired (canonical
cutover), so every decision here is a Fabric ``EnvironmentTransitionDecision``.
"""

from __future__ import annotations

from typing import Any

import pytest
from azazel_fabric.testing import make_transition_catalog

from azazel_fabric.deception_contracts import EnvironmentTransitionDecision

from azazel_deception.runtime.compose import RuntimeGateError
from azazel_deception.runtime.posture import build_reference_transition_executor
from azazel_deception.runtime.state import RuntimeStateStore
from azazel_deception.runtime.transitions import TransitionExecutor
from azazel_deception.runtime.transport import HmacDecisionAuthenticator, sign_decision

AS_OF = "2026-08-21T00:00:00+00:00"
_KEY = "test-edge-transport-key"
_EFFECTIVE = "2026-08-20T00:00:00+00:00"
_EXPIRES = "2026-08-22T00:00:00+00:00"


def _canonical(**over: Any) -> dict[str, Any]:
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


def _interim(**overrides: Any) -> dict[str, Any]:
    """The retired interim dict shape — only used to prove it is now rejected."""
    decision = {
        "transition_id": "open-smb-share",
        "edge_decision_id": "edge-decision-1",
        "status": "approved",
    }
    decision.update(overrides)
    return decision


def _executor(**kwargs: Any) -> TransitionExecutor:
    return TransitionExecutor(make_transition_catalog(), **kwargs)


# -- accept + result shape ---------------------------------------------------


def test_canonical_decision_is_shadow_simulated_by_default():
    executor = _executor()
    result = executor.execute(
        environment_id="env-1",
        current_state="baseline",
        transition_id="open-smb-share",
        edge_decision=_canonical(),
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


def test_canonical_model_instance_is_accepted():
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


def test_execute_is_deterministic_for_identical_inputs():
    executor = _executor()
    kwargs = dict(
        environment_id="env-1", current_state="baseline",
        transition_id="open-smb-share", edge_decision=_canonical(), as_of=AS_OF,
    )
    assert executor.execute(**kwargs) == executor.execute(**kwargs)


def test_execute_never_mutates_the_sealed_catalog_digest():
    catalog = make_transition_catalog()
    original_digest = catalog.catalog_digest
    executor = TransitionExecutor(catalog)
    executor.execute(
        environment_id="env-1", current_state="baseline",
        transition_id="open-smb-share", edge_decision=_canonical(), as_of=AS_OF,
    )
    assert catalog.catalog_digest == original_digest


# -- catalog integrity -------------------------------------------------------


def test_tampered_catalog_digest_fails_closed():
    catalog = make_transition_catalog()
    executor = TransitionExecutor(catalog)
    # Mutate the catalog object in-place after sealing, without recomputing the
    # digest -- a live tamper attempt caught before any decision logic runs.
    catalog.transitions[0].evidence_backed_trigger = "tampered-trigger"
    with pytest.raises(RuntimeGateError, match="digest"):
        executor.execute(
            environment_id="env-1", current_state="baseline",
            transition_id="open-smb-share", edge_decision=_canonical(), as_of=AS_OF,
        )


def test_tampered_declared_catalog_digest_field_also_fails_closed():
    catalog = make_transition_catalog()
    executor = TransitionExecutor(catalog)
    catalog.catalog_digest = "sha256:" + "a" * 64
    with pytest.raises(RuntimeGateError, match="digest"):
        executor.execute(
            environment_id="env-1", current_state="baseline",
            transition_id="open-smb-share", edge_decision=_canonical(), as_of=AS_OF,
        )


# -- transition lookup -------------------------------------------------------


def test_transition_not_in_catalog_fails_closed():
    executor = _executor()
    with pytest.raises(RuntimeGateError, match="not present"):
        executor.execute(
            environment_id="env-1", current_state="baseline",
            transition_id="no-such-transition", edge_decision=_canonical(), as_of=AS_OF,
        )


def test_missing_edge_decision_fails_closed():
    executor = _executor()
    with pytest.raises(RuntimeGateError):
        executor.execute(
            environment_id="env-1", current_state="baseline",
            transition_id="open-smb-share", edge_decision={}, as_of=AS_OF,
        )


# -- transport authentication (forgery) --------------------------------------


def test_forged_decision_fails_closed_when_authenticator_configured():
    executor = _executor(decision_authenticator=HmacDecisionAuthenticator(_KEY))
    # A canonical decision with no valid signature must not pass once an
    # authenticator is wired -- this is exactly the forgery the gate exists for.
    with pytest.raises(RuntimeGateError, match="authentication"):
        executor.execute(
            environment_id="env-1", current_state="baseline",
            transition_id="open-smb-share", edge_decision=_canonical(), as_of=AS_OF,
        )


def test_tampered_signed_decision_fails_closed():
    executor = _executor(decision_authenticator=HmacDecisionAuthenticator(_KEY))
    signed = sign_decision(_canonical(), _KEY)
    signed["target_state"] = "smb-share-open"  # unchanged
    signed["decision_id"] = "swapped-after-signing"  # tamper post-signature
    with pytest.raises(RuntimeGateError, match="authentication"):
        executor.execute(
            environment_id="env-1", current_state="baseline",
            transition_id="open-smb-share", edge_decision=signed, as_of=AS_OF,
        )


def test_authentically_signed_canonical_decision_is_accepted():
    executor = _executor(decision_authenticator=HmacDecisionAuthenticator(_KEY))
    signed = sign_decision(_canonical(), _KEY)
    result = executor.execute(
        environment_id="env-1", current_state="baseline",
        transition_id="open-smb-share", edge_decision=signed, as_of=AS_OF,
    )
    assert result["status"] == "shadow_simulated"
    assert result["edge_decision_id"] == "edge-decision-1"


def test_strict_posture_requires_an_authenticator():
    executor = _executor(require_authenticated_decisions=True)  # no authenticator
    with pytest.raises(RuntimeGateError, match="no authenticator is configured"):
        executor.execute(
            environment_id="env-1", current_state="baseline",
            transition_id="open-smb-share", edge_decision=_canonical(), as_of=AS_OF,
        )


# -- environment / state binding ---------------------------------------------


def test_wrong_environment_fails_closed():
    executor = _executor()
    with pytest.raises(RuntimeGateError, match="environment_id"):
        executor.execute(
            environment_id="env-1", current_state="baseline",
            transition_id="open-smb-share", edge_decision=_canonical(environment_id="env-2"),
            as_of=AS_OF,
        )


def test_current_state_mismatch_fails_closed():
    executor = _executor()
    with pytest.raises(RuntimeGateError, match="current_state"):
        executor.execute(
            environment_id="env-1", current_state="smb-share-open",
            transition_id="open-smb-share",
            edge_decision=_canonical(current_state="smb-share-open"), as_of=AS_OF,
        )


def test_target_state_mismatch_fails_closed():
    executor = _executor()
    with pytest.raises(RuntimeGateError, match="target_state"):
        executor.execute(
            environment_id="env-1", current_state="baseline",
            transition_id="open-smb-share",
            edge_decision=_canonical(target_state="some-other-state"), as_of=AS_OF,
        )


# -- validity window (effective / expiry) ------------------------------------


def test_expired_decision_fails_closed():
    executor = _executor()
    with pytest.raises(RuntimeGateError, match="expired"):
        executor.execute(
            environment_id="env-1", current_state="baseline",
            transition_id="open-smb-share", edge_decision=_canonical(),
            as_of="2026-08-23T00:00:00+00:00",  # after expires_at
        )


def test_not_yet_effective_fails_closed():
    executor = _executor()
    with pytest.raises(RuntimeGateError, match="not yet effective"):
        executor.execute(
            environment_id="env-1", current_state="baseline",
            transition_id="open-smb-share", edge_decision=_canonical(),
            as_of="2026-08-19T00:00:00+00:00",  # before effective_at
        )


def test_far_future_as_of_cannot_replay_an_expiring_decision():
    # A captured decision replayed with an arbitrary far-future as_of is refused
    # because the canonical path always enforces the [effective, expires) window.
    executor = _executor()
    decision = _canonical()
    assert executor.execute(
        environment_id="env-1", current_state="baseline",
        transition_id="open-smb-share", edge_decision=decision, as_of=AS_OF,
    )["status"] == "shadow_simulated"
    with pytest.raises(RuntimeGateError, match="expired"):
        executor.execute(
            environment_id="env-1", current_state="baseline",
            transition_id="open-smb-share", edge_decision=decision,
            as_of="2030-01-01T00:00:00+00:00",
        )


# -- one-shot anti-replay ----------------------------------------------------


def test_replay_fails_closed_with_state_store(tmp_path):
    state = RuntimeStateStore(tmp_path)
    executor = TransitionExecutor(make_transition_catalog(), state=state)
    kwargs = dict(
        environment_id="env-1", current_state="baseline",
        transition_id="open-smb-share", edge_decision=_canonical(), as_of=AS_OF,
    )
    assert executor.execute(**kwargs)["status"] == "shadow_simulated"
    with pytest.raises(RuntimeGateError, match="already consumed"):
        executor.execute(**kwargs)


def test_distinct_decision_ids_are_not_replays(tmp_path):
    state = RuntimeStateStore(tmp_path)
    executor = TransitionExecutor(make_transition_catalog(), state=state)
    executor.execute(
        environment_id="env-1", current_state="baseline",
        transition_id="open-smb-share", edge_decision=_canonical(decision_id="edge-decision-1"),
        as_of=AS_OF,
    )
    result = executor.execute(
        environment_id="env-1", current_state="baseline",
        transition_id="open-smb-share", edge_decision=_canonical(decision_id="edge-decision-2"),
        as_of=AS_OF,
    )
    assert result["status"] == "shadow_simulated"


def test_strict_replay_protection_requires_a_state_store():
    executor = _executor(require_replay_protection=True)  # no state store
    with pytest.raises(RuntimeGateError, match="replay protection required"):
        executor.execute(
            environment_id="env-1", current_state="baseline",
            transition_id="open-smb-share", edge_decision=_canonical(), as_of=AS_OF,
        )


# -- canonical contract validation -------------------------------------------


def test_canonical_rejected_status_fails_closed():
    executor = _executor()
    with pytest.raises(RuntimeGateError, match="not executable"):
        executor.execute(
            environment_id="env-1", current_state="baseline",
            transition_id="open-smb-share", edge_decision=_canonical(status="rejected"),
            as_of=AS_OF,
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


# -- interim shape retired ---------------------------------------------------


def test_interim_dict_is_always_rejected():
    # The legacy interim dict shape is unconditionally rejected now, regardless
    # of any flag -- canonical is the only accepted decision.
    executor = _executor()
    with pytest.raises(RuntimeGateError, match="canonical"):
        executor.execute(
            environment_id="env-1", current_state="baseline",
            transition_id="open-smb-share", edge_decision=_interim(), as_of=AS_OF,
        )


def test_signed_interim_dict_is_rejected_under_strict(tmp_path):
    executor = TransitionExecutor.strict(
        make_transition_catalog(),
        decision_authenticator=HmacDecisionAuthenticator(_KEY),
        state=RuntimeStateStore(tmp_path),
    )
    # A *signed* interim dict passes authentication but is then rejected for not
    # being the canonical contract.
    with pytest.raises(RuntimeGateError, match="canonical"):
        executor.execute(
            environment_id="env-1", current_state="baseline",
            transition_id="open-smb-share",
            edge_decision=sign_decision(_interim(), _KEY), as_of=AS_OF,
        )


# -- live gate: strict-for-live is code-enforced -----------------------------


def test_live_enabled_requires_full_strict_posture():
    # Fail-closed: a "live" executor must wire the FULL strict posture, not just
    # authentication. A partial posture (or none) is refused at construction, so
    # a "would_execute" go-signal can never come from a decision that isn't
    # authenticated, replay-protected, expiry-bound, and canonical.
    with pytest.raises(ValueError, match="full strict posture"):
        _executor(live_enabled=True)
    with pytest.raises(ValueError, match="full strict posture"):
        _executor(live_enabled=True, require_authenticated_decisions=True)
    with pytest.raises(ValueError, match="full strict posture"):
        _executor(
            live_enabled=True,
            require_authenticated_decisions=True,
            require_replay_protection=True,
            require_decision_expiry=True,
            # require_canonical_decision missing
        )


def test_live_enabled_with_full_strict_performs_no_container_action(tmp_path):
    executor = TransitionExecutor.strict(
        make_transition_catalog(),
        decision_authenticator=HmacDecisionAuthenticator(_KEY),
        state=RuntimeStateStore(tmp_path),
        live_enabled=True,
    )
    signed = sign_decision(_canonical(), _KEY)
    result = executor.execute(
        environment_id="env-1", current_state="baseline",
        transition_id="open-smb-share", edge_decision=signed, as_of=AS_OF,
    )
    assert result["status"] == "would_execute"
    assert result["enforcement_applied"] is False
    assert result["live_enabled"] is True


# -- strict() constructor + reference factory --------------------------------


def test_strict_constructor_enables_all_gates(tmp_path):
    executor = TransitionExecutor.strict(
        make_transition_catalog(),
        decision_authenticator=HmacDecisionAuthenticator(_KEY),
        state=RuntimeStateStore(tmp_path),
    )
    assert executor.require_authenticated_decisions
    assert executor.require_replay_protection
    assert executor.require_decision_expiry
    assert executor.require_canonical_decision
    signed = sign_decision(_canonical(), _KEY)
    assert executor.execute(
        environment_id="env-1", current_state="baseline",
        transition_id="open-smb-share", edge_decision=signed, as_of=AS_OF,
    )["status"] == "shadow_simulated"
    # ...and a replay of it is refused (anti-replay is on).
    with pytest.raises(RuntimeGateError, match="already consumed"):
        executor.execute(
            environment_id="env-1", current_state="baseline",
            transition_id="open-smb-share", edge_decision=signed, as_of=AS_OF,
        )


def test_strict_constructor_rejects_unsigned(tmp_path):
    executor = TransitionExecutor.strict(
        make_transition_catalog(),
        decision_authenticator=HmacDecisionAuthenticator(_KEY),
        state=RuntimeStateStore(tmp_path),
    )
    with pytest.raises(RuntimeGateError, match="authentication"):
        executor.execute(
            environment_id="env-1", current_state="baseline",
            transition_id="open-smb-share", edge_decision=_canonical(), as_of=AS_OF,
        )


def test_build_reference_transition_executor_is_strict_and_live_no_action(tmp_path):
    executor = build_reference_transition_executor(
        make_transition_catalog(),
        decision_authenticator=HmacDecisionAuthenticator(_KEY),
        state=RuntimeStateStore(tmp_path),
        live_enabled=True,
    )
    assert executor.require_authenticated_decisions
    assert executor.require_replay_protection
    assert executor.require_decision_expiry
    assert executor.require_canonical_decision
    assert executor.live_enabled is True
    signed = sign_decision(_canonical(), _KEY)
    result = executor.execute(
        environment_id="env-1", current_state="baseline",
        transition_id="open-smb-share", edge_decision=signed, as_of=AS_OF,
    )
    assert result["status"] == "would_execute"
    assert result["enforcement_applied"] is False


def test_build_reference_transition_executor_relaxed_is_shadow_only():
    # The dev opt-out cannot go live for transitions (the strict-for-live guard),
    # so a relaxed reference build is forced shadow-only rather than raising.
    executor = build_reference_transition_executor(
        make_transition_catalog(), live_enabled=True, dev_relaxed_posture=True,
    )
    assert executor.live_enabled is False
    assert not executor.require_authenticated_decisions
    assert not executor.require_canonical_decision
