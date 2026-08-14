"""Tests for the authenticated Edge shadow/replay service."""

import json
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from azazel_deception.capabilities import detect_host_capabilities
from azazel_deception.package import calculate_package_digest, load_package
from azazel_deception.planner import build_placement_plan
from azazel_deception.runtime.shadow_server import (
    ENVELOPE_SIGNATURE_FIELD,
    REQUEST_SCHEMA,
    RESPONSE_SCHEMA,
    AUDIT_ENVIRONMENT_ID,
    ShadowReplayHTTPServer,
    ShadowReplayService,
)
from azazel_deception.runtime.state import RuntimeStateStore
from azazel_deception.runtime.transport import (
    HmacDecisionAuthenticator,
    compute_decision_signature,
)

from tests.test_runtime import _decision, _termination

PACKAGE = Path("examples/packages/municipal-linux-v1/package.yaml")
COMPOSE = Path("runtime/compose/reference-linux.compose.yaml")
KEY = "shadow-test-key"
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
        "request_id": f"req-{_counter}",
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


def test_capabilities_requires_authentic_envelope(service):
    envelope = _envelope("capabilities")
    envelope[ENVELOPE_SIGNATURE_FIELD] = "0" * 64
    response = service.handle(envelope)
    assert response["status"] == "rejected"
    assert response["reason_codes"] == ["authentication_failed"]
    _assert_signed_response(response)


def test_wrong_key_fails_authentication(service):
    response = service.handle(_envelope("capabilities", key="not-the-shared-key"))
    assert response["reason_codes"] == ["authentication_failed"]


def test_unknown_edge_identity_is_rejected(service):
    response = service.handle(_envelope("capabilities", edge_id="edge-rogue"))
    assert response["reason_codes"] == ["edge_identity_not_allowlisted"]


def test_wrong_node_identity_is_rejected(service):
    response = service.handle(_envelope("capabilities", node_id="az06-other"))
    assert response["reason_codes"] == ["node_identity_mismatch"]


def test_stale_envelope_is_rejected(service):
    stale = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
    response = service.handle(_envelope("capabilities", issued_at=stale))
    assert response["reason_codes"] == ["stale_request"]


def test_replayed_envelope_is_rejected(service):
    envelope = _envelope("capabilities")
    first = service.handle(envelope)
    assert first["status"] == "ok"
    replay = service.handle(envelope)
    assert replay["status"] == "rejected"
    assert replay["reason_codes"] == ["replayed_request"]


def test_unsupported_schema_and_action_fail_closed(service):
    response = service.handle(_envelope("capabilities", schema_version="bogus/v9"))
    assert response["reason_codes"] == ["unsupported_schema"]
    response = service.handle(_envelope("route_traffic"))
    assert response["reason_codes"] == ["unsupported_action"]


def test_malformed_envelope_fails_closed(service):
    response = service.handle("not a mapping")
    assert response["status"] == "rejected"
    assert response["reason_codes"] == ["malformed_envelope"]


def test_capabilities_and_package_and_plan_flow(service, lite_package_path):
    response = service.handle(_envelope("capabilities"))
    assert response["status"] == "ok"
    _assert_signed_response(response)
    capabilities = response["result"]["capabilities"]
    assert capabilities["authority"] == "descriptive_only"

    package_response = service.handle(_envelope("package"))
    assert package_response["status"] == "ok"
    package = package_response["result"]["package"]
    assert package_response["result"]["package_digest"] == package["package_digest"]

    plan_response = service.handle(
        _envelope("plan", {"requested_tier": "lite", "edge_decision_id": "edge-d-1"})
    )
    assert plan_response["status"] == "ok"
    plan = plan_response["result"]["placement_plan"]
    assert plan["authority"] == "descriptive_only"
    assert plan["edge_decision_id"] == "edge-d-1"
    assert plan["selected_tier"] == "lite"
    # Deterministic: an identical plan request yields an identical plan.
    again = service.handle(
        _envelope("plan", {"requested_tier": "lite", "edge_decision_id": "edge-d-1"})
    )
    assert again["result"]["placement_plan"] == plan


def test_shadow_activation_and_termination_rehearsal(service, lite_package_path):
    package = json.loads(lite_package_path.read_text(encoding="utf-8"))
    plan = build_placement_plan(
        package,
        detect_host_capabilities(),
        requested_tier="lite",
        edge_decision_id="edge-d-2",
    )
    decision = _decision(package, plan, decision_id="edge-d-2")
    response = service.handle(
        _envelope(
            "activate",
            {
                "environment_id": "env-shadow-1",
                "package": package,
                "placement": plan,
                "decision": decision,
            },
        )
    )
    assert response["status"] == "ok"
    result = response["result"]
    assert result["status"] == "shadow_accepted"
    assert result["live_execution"] is False
    assert result["simulated_state"] == "active"

    termination = _termination("edge-t-2")
    termination["environment_id"] = "env-shadow-1"
    terminate_response = service.handle(
        _envelope("terminate", {"environment_id": "env-shadow-1", "decision": termination})
    )
    assert terminate_response["status"] == "ok"
    assert terminate_response["result"]["simulated_state"] == "terminated"

    # Rehearsal must not consume the one-shot decision ledger or write state.
    assert service.state.decision_consumed("edge-d-2") is False
    assert service.adapter.collect_status("env-shadow-1")["state"] == "absent"


def test_shadow_activation_binding_mismatch_is_deterministic(service, lite_package_path):
    package = json.loads(lite_package_path.read_text(encoding="utf-8"))
    plan = build_placement_plan(
        package,
        detect_host_capabilities(),
        requested_tier="lite",
        edge_decision_id="edge-d-3",
    )
    decision = _decision(package, plan, decision_id="edge-d-other")
    response = service.handle(
        _envelope(
            "activate",
            {
                "environment_id": "env-shadow-2",
                "package": package,
                "placement": plan,
                "decision": decision,
            },
        )
    )
    assert response["status"] == "rejected"
    assert "shadow_validation_failed" in response["reason_codes"]


def test_expired_shadow_decision_is_rejected(service, lite_package_path):
    package = json.loads(lite_package_path.read_text(encoding="utf-8"))
    plan = build_placement_plan(
        package,
        detect_host_capabilities(),
        requested_tier="lite",
        edge_decision_id="edge-d-4",
    )
    decision = _decision(package, plan, decision_id="edge-d-4")
    decision["expires_at"] = (
        datetime.now(timezone.utc) - timedelta(minutes=1)
    ).isoformat()
    response = service.handle(
        _envelope(
            "activate",
            {
                "environment_id": "env-shadow-3",
                "package": package,
                "placement": plan,
                "decision": decision,
            },
        )
    )
    assert response["status"] == "rejected"
    assert "shadow_validation_failed" in response["reason_codes"]


def test_every_request_is_audited_with_intact_evidence_chain(service, tmp_path):
    service.handle(_envelope("capabilities"))
    service.handle(_envelope("capabilities", edge_id="edge-rogue"))
    store = RuntimeStateStore(tmp_path / "state")
    events = [
        json.loads(line)
        for line in store.evidence_path(AUDIT_ENVIRONMENT_ID)
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    assert [event["status"] for event in events] == ["ok", "rejected"]
    assert store.verify_evidence_chain(AUDIT_ENVIRONMENT_ID) is True


def test_http_round_trip(service):
    with ShadowReplayHTTPServer(service) as server:
        host, port = server.address
        request = urllib.request.Request(
            f"http://{host}:{port}/shadow",
            data=json.dumps(_envelope("capabilities")).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=10) as raw:
            response = json.loads(raw.read().decode("utf-8"))
    assert response["status"] == "ok"
    _assert_signed_response(response)
