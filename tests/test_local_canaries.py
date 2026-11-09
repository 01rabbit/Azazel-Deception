import json
from dataclasses import replace
from unittest import mock

import pytest

from azazel_deception.credentials.canaries import CanaryRegistry, CanaryScope, synthetic_openapi

NOW = "2026-11-10T00:00:00+00:00"
LATER = "2026-11-10T00:00:10+00:00"


def scope():
    return CanaryScope("package", "a" * 64, "environment", "boot", "session", "surface")


def touch(registry, issued, **overrides):
    args = dict(scope=scope(), event_id="event-1", evidence_ref="observation:1", as_of=LATER)
    args.update(overrides)
    return registry.touch(issued.token, **args)


def test_token_secret_and_public_ref_are_separate_and_observation_has_no_verdict():
    registry = CanaryRegistry(scope())
    issued = registry.issue(issued_at=NOW)
    assert issued.token not in repr(issued)
    assert issued.token not in json.dumps(issued.public_reference())
    first = touch(registry, issued)
    assert first["kind"] == "touch_without_presentation"
    registry.present(issued.lure_id, scope=scope(), evidence_ref="presentation:1", as_of=NOW)
    result = touch(registry, issued, event_id="event-2")
    assert result["kind"] == "follow_through_observed"
    assert issued.token not in json.dumps(result)
    assert "AI_attacker" not in result and "success" not in result
    document = json.loads(synthetic_openapi(issued))
    assert list(document["paths"]) == [issued.local_path()]
    assert "servers" not in document


def test_scope_package_boot_session_and_surface_are_exact():
    registry = CanaryRegistry(scope())
    issued = registry.issue(issued_at=NOW)
    for name, value in (("package_sha256", "b" * 64), ("environment_id", "other"), ("boot_id", "other"), ("session_id", "other"), ("surface_id", "other")):
        assert not touch(registry, issued, scope=replace(scope(), **{name: value}))["accepted"]
    assert not CanaryRegistry(scope()).touch(issued.token, scope=scope(), event_id="e", evidence_ref="r", as_of=LATER)["accepted"]


def test_expiry_duplicates_quotas_and_reset_fail_closed():
    registry = CanaryRegistry(scope(), max_tokens=1, max_events=1)
    issued = registry.issue(issued_at=NOW, ttl_seconds=20)
    with pytest.raises(ValueError):
        registry.issue(issued_at=NOW)
    assert touch(registry, issued)["accepted"]
    assert touch(registry, issued)["reason"] == "duplicate_event"
    assert touch(registry, issued, event_id="another")["reason"] == "event_capacity_exhausted"
    assert not touch(registry, issued, as_of="2026-11-10T00:00:20+00:00")["accepted"]
    assert registry.reset(as_of=LATER)["invalidated_count"] == 1
    assert not touch(registry, issued, event_id="post-reset")["accepted"]
    with pytest.raises(ValueError):
        registry.issue(issued_at=LATER)


def test_guessed_tokens_bad_timestamps_and_impossible_presentation_are_rejected():
    registry = CanaryRegistry(scope())
    issued = registry.issue(issued_at=NOW)
    assert not registry.touch("x" * 43, scope=scope(), event_id="e", evidence_ref="r", as_of=NOW)["accepted"]
    assert not touch(registry, issued, as_of="2026-11-09T23:59:59+00:00")["accepted"]
    with pytest.raises(ValueError):
        registry.present(issued.lure_id, scope=scope(), evidence_ref="r", as_of="2026-11-09T23:59:59+00:00")
    for bad in ("2026-11-10T00:00:00", "not-a-time"):
        with pytest.raises(ValueError):
            touch(registry, issued, as_of=bad)
    with pytest.raises(ValueError):
        registry.issue(issued_at=NOW, ttl_seconds=True)


def test_preparation_and_matching_do_not_execute_or_connect():
    with mock.patch("subprocess.run", side_effect=AssertionError("execution")), mock.patch("socket.socket", side_effect=AssertionError("network")):
        registry = CanaryRegistry(scope())
        issued = registry.issue(issued_at=NOW)
        assert touch(registry, issued)["accepted"]
        registry.reset(as_of=LATER)


def test_matched_fact_uses_existing_evidence_chain_without_token_echo(tmp_path):
    from azazel_deception.credentials.canaries import record_canary_touch
    from azazel_deception.runtime.observation import InteractionObserver
    from azazel_deception.runtime.state import RuntimeStateStore
    state = RuntimeStateStore(tmp_path)
    observer = InteractionObserver(state, environment_id="environment", package_id="package", node_id="node")
    registry = CanaryRegistry(scope())
    issued = registry.issue(issued_at=NOW)
    registry.present(issued.lure_id, scope=scope(), evidence_ref="presentation:1", as_of=NOW)
    result = record_canary_touch(observer, registry, issued.token, scope=scope(), event_id="event", evidence_ref="observation:1", as_of=LATER)
    assert result["accepted"]
    assert state.verify_evidence_chain("environment")
    assert issued.token not in state.read_evidence_snapshot("environment")
    observer.package_id = "other"
    with pytest.raises(ValueError, match="scope"):
        record_canary_touch(observer, registry, issued.token, scope=scope(), event_id="other", evidence_ref="r", as_of=LATER)


def test_evidence_write_failure_is_visible_and_cannot_trigger_unbounded_retry(tmp_path):
    from azazel_deception.credentials.canaries import record_canary_touch
    from azazel_deception.runtime.observation import InteractionObserver
    from azazel_deception.runtime.state import RuntimeStateStore
    observer = InteractionObserver(RuntimeStateStore(tmp_path), environment_id="environment", package_id="package", node_id="node")
    registry = CanaryRegistry(scope())
    issued = registry.issue(issued_at=NOW)
    with mock.patch.object(observer, "record", side_effect=OSError("full")):
        result = record_canary_touch(observer, registry, issued.token, scope=scope(), event_id="event", evidence_ref="r", as_of=LATER)
    assert result == {"accepted": False, "reason": "evidence_unavailable"}
    assert registry.status()["audit_failures"] == 1
    assert registry.touch(issued.token, scope=scope(), event_id="event", evidence_ref="r", as_of=LATER)["reason"] == "duplicate_event"
    with pytest.raises(ValueError, match="predates"):
        registry.reset(as_of=NOW)
