"""Tests for the authenticated heartbeat + reconciliation shadow actions.

These prove the steady-state Edge integration surface: a liveness poll and a
state-reconciliation report, both riding the same signed envelope with the
same fail-closed gates as the bootstrap actions, and both descriptive-only.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from azazel_deception.package import calculate_package_digest, load_package
from azazel_deception.runtime.shadow_server import (
    ENVELOPE_SIGNATURE_FIELD,
    REQUEST_SCHEMA,
    RESPONSE_SCHEMA,
    ShadowReplayService,
)
from azazel_deception.runtime.transport import (
    HmacDecisionAuthenticator,
    compute_decision_signature,
)

PACKAGE = Path("examples/packages/municipal-linux-v1/package.yaml")
COMPOSE = Path("runtime/compose/reference-linux.compose.yaml")
KEY = "shadow-heartbeat-key"
EDGE_ID = "edge-node-1"
NODE_ID = "az06-node-1"


@pytest.fixture
def lite_package_path(tmp_path):
    package = load_package(PACKAGE)
    for component in package["components"]:
        component["image"]["verified"] = component["component_id"] == "intranet-web"
    package["package_digest"] = calculate_package_digest(package)
    path = tmp_path / "package.json"
    path.write_text(json.dumps(package), encoding="utf-8")
    return path


@pytest.fixture
def service(tmp_path, lite_package_path):
    return ShadowReplayService(
        node_id=NODE_ID,
        transport_key=KEY,
        allowed_edge_ids=[EDGE_ID],
        package_path=lite_package_path,
        state_root=tmp_path / "state",
        compose_file=COMPOSE,
    )


_counter = 0


def _envelope(action, payload=None, *, key=KEY, edge_id=EDGE_ID, node_id=NODE_ID, **overrides):
    global _counter
    _counter += 1
    envelope = {
        "schema_version": REQUEST_SCHEMA,
        "request_id": f"hb-req-{_counter}",
        "edge_node_id": edge_id,
        "az06_node_id": node_id,
        "action": action,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "payload": payload or {},
    }
    envelope.update(overrides)
    envelope[ENVELOPE_SIGNATURE_FIELD] = compute_decision_signature(
        envelope, key, signature_field=ENVELOPE_SIGNATURE_FIELD
    )
    return envelope


def _assert_signed_response(response):
    assert response["schema_version"] == RESPONSE_SCHEMA
    assert response["authority"] == "descriptive_only"
    assert response["enforcement_applied"] is False
    verifier = HmacDecisionAuthenticator(KEY, signature_field=ENVELOPE_SIGNATURE_FIELD)
    assert verifier(response) is True


def _write_active(service, environment_id):
    """Simulate a locally materialized environment without executing anything."""

    service.state.write(
        environment_id,
        {
            "environment_id": environment_id,
            "state": "active",
            "package_id": "municipal-linux-v1",
            "node_id": NODE_ID,
            "decision_id": f"edge-d-{environment_id}",
        },
    )


# -- heartbeat ---------------------------------------------------------------


def test_heartbeat_reports_identity_health_and_sequence(service):
    envelope = _envelope(
        "heartbeat", {"edge_sequence": 7, "edge_active_environment_ids": ["env-b", "env-a"]}
    )
    response = service.handle(envelope)
    assert response["status"] == "ok"
    assert response["reason_codes"] == ["shadow_only_no_enforcement"]
    _assert_signed_response(response)

    result = response["result"]
    assert result["node_id"] == NODE_ID
    assert result["authority"] == "descriptive_only"
    assert result["enforcement_applied"] is False
    assert result["heartbeat_sequence"] == 1
    # Edge's own sequence and active set are echoed so the Edge loop can spot a
    # crossed or stale conversation.
    assert result["edge_sequence"] == 7
    assert result["edge_active_environment_ids"] == ["env-a", "env-b"]
    assert result["issued_at"] == envelope["issued_at"]
    assert result["responded_at"]

    health = result["health"]
    # Shadow rehearsal is pinned non-live whatever the environment says.
    assert health["live_enabled"] is False
    assert health["active_environments"] == []
    assert health["consumed_decisions"] >= 1


def test_heartbeat_sequence_is_monotonic_and_payload_is_optional(service):
    first = service.handle(_envelope("heartbeat"))
    second = service.handle(_envelope("heartbeat"))
    assert first["status"] == "ok"
    assert first["result"]["edge_sequence"] is None
    assert first["result"]["edge_active_environment_ids"] is None
    assert second["result"]["heartbeat_sequence"] == first["result"]["heartbeat_sequence"] + 1


def test_heartbeat_health_tracks_local_active_state(service):
    _write_active(service, "env-local-1")
    response = service.handle(_envelope("heartbeat"))
    assert response["result"]["health"]["active_environments"] == ["env-local-1"]
    assert response["result"]["health"]["environment_count"] == 1


def test_heartbeat_rejects_malformed_edge_inputs(service):
    bad_sequence = service.handle(_envelope("heartbeat", {"edge_sequence": "seven"}))
    assert bad_sequence["status"] == "rejected"
    assert "shadow_validation_failed" in bad_sequence["reason_codes"]

    bad_set = service.handle(
        _envelope("heartbeat", {"edge_active_environment_ids": "env-a"})
    )
    assert bad_set["status"] == "rejected"
    assert "shadow_validation_failed" in bad_set["reason_codes"]
    _assert_signed_response(bad_set)


# -- reconcile ---------------------------------------------------------------


def test_reconcile_reports_consistency_when_views_agree(service):
    _write_active(service, "env-agreed")
    response = service.handle(
        _envelope("reconcile", {"edge_active_environment_ids": ["env-agreed"]})
    )
    assert response["status"] == "ok"
    _assert_signed_response(response)

    result = response["result"]
    assert result["divergence"]["consistent"] is True
    assert result["divergence"]["authority"] == "descriptive_only"
    assert result["divergent_environment_ids"] == []
    assert result["divergent_environment_states"] == {}


def test_reconcile_reports_divergence_with_local_state(service):
    _write_active(service, "env-local-orphan")
    response = service.handle(
        _envelope("reconcile", {"edge_active_environment_ids": ["env-edge-expects"]})
    )
    assert response["status"] == "ok"
    result = response["result"]

    divergence = result["divergence"]
    assert divergence["consistent"] is False
    assert divergence["local_only_active"] == ["env-local-orphan"]
    assert divergence["edge_only_active"] == ["env-edge-expects"]
    assert divergence["local_active"] == ["env-local-orphan"]
    assert divergence["edge_active"] == ["env-edge-expects"]

    # Every divergent environment carries its local state so Edge can decide.
    assert result["divergent_environment_ids"] == ["env-edge-expects", "env-local-orphan"]
    states = result["divergent_environment_states"]
    assert states["env-local-orphan"]["state"] == "active"
    assert states["env-local-orphan"]["decision_id"] == "edge-d-env-local-orphan"
    assert states["env-edge-expects"]["state"] == "absent"

    # Reporting a divergence must not change anything: no enforcement, no
    # state mutation, no decision consumed on the divergent environments.
    assert result["enforcement_applied"] is False
    assert service.adapter.collect_status("env-local-orphan")["state"] == "active"
    assert service.adapter.collect_status("env-edge-expects")["state"] == "absent"


def test_reconcile_requires_a_well_formed_edge_active_set(service):
    missing = service.handle(_envelope("reconcile"))
    assert missing["status"] == "rejected"
    assert "shadow_validation_failed" in missing["reason_codes"]

    wrong_type = service.handle(
        _envelope("reconcile", {"edge_active_environment_ids": [1, 2]})
    )
    assert wrong_type["status"] == "rejected"
    assert "shadow_validation_failed" in wrong_type["reason_codes"]


# -- transport gates still apply --------------------------------------------


@pytest.mark.parametrize("action", ["heartbeat", "reconcile"])
def test_new_actions_require_an_authentic_envelope(service, action):
    envelope = _envelope(action, {"edge_active_environment_ids": []})
    envelope[ENVELOPE_SIGNATURE_FIELD] = "0" * 64
    response = service.handle(envelope)
    assert response["reason_codes"] == ["authentication_failed"]

    forged = _envelope(
        action, {"edge_active_environment_ids": []}, key="not-the-shared-key"
    )
    assert service.handle(forged)["reason_codes"] == ["authentication_failed"]


@pytest.mark.parametrize("action", ["heartbeat", "reconcile"])
def test_new_actions_enforce_identity_binding(service, action):
    payload = {"edge_active_environment_ids": []}
    rogue = service.handle(_envelope(action, payload, edge_id="edge-rogue"))
    assert rogue["reason_codes"] == ["edge_identity_not_allowlisted"]
    other_node = service.handle(_envelope(action, payload, node_id="az06-other"))
    assert other_node["reason_codes"] == ["node_identity_mismatch"]


@pytest.mark.parametrize("action", ["heartbeat", "reconcile"])
def test_stale_heartbeat_envelope_is_rejected(service, action):
    stale = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
    response = service.handle(
        _envelope(action, {"edge_active_environment_ids": []}, issued_at=stale)
    )
    assert response["reason_codes"] == ["stale_request"]
    _assert_signed_response(response)


@pytest.mark.parametrize("action", ["heartbeat", "reconcile"])
def test_replayed_heartbeat_envelope_is_rejected(service, action):
    envelope = _envelope(action, {"edge_active_environment_ids": []})
    assert service.handle(envelope)["status"] == "ok"
    replay = service.handle(envelope)
    assert replay["status"] == "rejected"
    assert replay["reason_codes"] == ["replayed_request"]


def test_heartbeat_and_reconcile_are_audited(service):
    service.handle(_envelope("heartbeat"))
    service.handle(_envelope("reconcile", {"edge_active_environment_ids": []}))
    from azazel_deception.runtime.shadow_server import AUDIT_ENVIRONMENT_ID

    events = [
        json.loads(line)
        for line in service.state.evidence_path(AUDIT_ENVIRONMENT_ID)
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    assert [event["action"] for event in events] == ["heartbeat", "reconcile"]
    assert service.state.verify_evidence_chain(AUDIT_ENVIRONMENT_ID) is True
