"""Authenticated Edge-decision transport verification."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from azazel_deception.package import load_package
from azazel_deception.planner import build_placement_plan
from azazel_deception.runtime.compose import DockerComposeAdapter, RuntimeGateError
from azazel_deception.runtime.transport import (
    DecisionAuthenticationError,
    HmacDecisionAuthenticator,
    canonical_decision_bytes,
    require_authenticated_decision,
    sign_decision,
)

PACKAGE = Path("examples/packages/municipal-linux-v1/package.yaml")
COMPOSE = Path("runtime/compose/reference-linux.compose.yaml")
KEY = "edge-shared-secret-not-in-repo"


def _host():
    return {
        "node_id": "az06-test",
        "architecture": "amd64",
        "cpu_cores": 4,
        "memory_mb": 8192,
        "storage_free_mb": 65536,
        "runtime_adapters": {"docker_compose": True},
        "kvm_available": False,
        "gpu_available": False,
    }


def _decision(raw, plan, decision_id="edge-decision-1"):
    now = datetime.now(timezone.utc)
    return {
        "schema_version": "environment-activation-decision/v0.1",
        "decision_id": decision_id,
        "decision_authority": "azazel-edge",
        "status": "accepted",
        "package_id": raw["package_id"],
        "package_digest": raw["package_digest"],
        "target_node_id": plan["node_id"],
        "selected_tier": plan["selected_tier"],
        "budget": {
            "cpu_cores": 2,
            "memory_mb": 1024,
            "storage_mb": 2048,
            "max_connections": 100,
            "max_duration_seconds": 300,
            "bandwidth_kbps": 5000,
        },
        "safety": {
            "outbound_allowed": False,
            "production_access": False,
            "privileged_containers": False,
            "host_network": False,
            "runtime_socket_exposed_to_decoys": False,
            "edge_control_access_from_decoys": False,
        },
        "effective_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=5)).isoformat(),
        "evidence_refs": [],
        "reason_codes": ["test"],
    }


# --------------------------------------------------------------------------- #
# Signature primitives
# --------------------------------------------------------------------------- #

def test_sign_then_authenticate_roundtrip():
    decision = {"decision_id": "d1", "value": 7, "nested": {"a": 1}}
    signed = sign_decision(decision, KEY)
    assert HmacDecisionAuthenticator(KEY)(signed) is True


def test_canonical_bytes_exclude_signature_field():
    decision = {"decision_id": "d1", "value": 7}
    signed = sign_decision(decision, KEY)
    assert canonical_decision_bytes(signed) == canonical_decision_bytes(decision)


@pytest.mark.parametrize("field", ["decision_id", "value"])
def test_tamper_after_signing_fails(field):
    signed = sign_decision({"decision_id": "d1", "value": 7}, KEY)
    signed[field] = "tampered"
    assert HmacDecisionAuthenticator(KEY)(signed) is False


def test_wrong_key_fails():
    signed = sign_decision({"decision_id": "d1"}, KEY)
    assert HmacDecisionAuthenticator("other-key")(signed) is False


def test_missing_or_non_string_signature_fails():
    assert HmacDecisionAuthenticator(KEY)({"decision_id": "d1"}) is False
    assert HmacDecisionAuthenticator(KEY)({"decision_id": "d1", "decision_signature": 123}) is False


def test_empty_key_rejected():
    with pytest.raises(ValueError):
        HmacDecisionAuthenticator("")


def test_require_authenticated_decision_gate():
    signed = sign_decision({"decision_id": "d1"}, KEY)
    auth = HmacDecisionAuthenticator(KEY)
    require_authenticated_decision(signed, auth)  # no raise
    require_authenticated_decision(signed, None)  # optional -> no raise
    with pytest.raises(DecisionAuthenticationError):
        require_authenticated_decision({"decision_id": "d1"}, auth)


def test_require_authenticated_decision_wraps_authenticator_exception():
    def boom(_decision):
        raise RuntimeError("kaboom")

    with pytest.raises(DecisionAuthenticationError, match="authenticator failed"):
        require_authenticated_decision({"x": 1}, boom)


# --------------------------------------------------------------------------- #
# Adapter integration
# --------------------------------------------------------------------------- #

def _accept_all(_package):
    return True


def test_unsigned_activation_rejected_when_authenticator_configured(tmp_path):
    raw = load_package(PACKAGE)
    plan = build_placement_plan(raw, _host(), "lite", edge_decision_id="edge-decision-1")
    adapter = DockerComposeAdapter(
        COMPOSE,
        tmp_path,
        live_enabled=True,
        package_verifier=_accept_all,
        decision_authenticator=HmacDecisionAuthenticator(KEY),
    )
    with pytest.raises(RuntimeGateError, match="failed authentication"):
        adapter.activate_environment("env-1", raw, plan, _decision(raw, plan))
    # Rejected before the one-shot decision was consumed.
    assert adapter.state.decision_consumed("edge-decision-1") is False


def test_signed_activation_accepted(tmp_path, monkeypatch):
    raw = load_package(PACKAGE)
    plan = build_placement_plan(raw, _host(), "lite", edge_decision_id="edge-decision-1")
    adapter = DockerComposeAdapter(
        COMPOSE,
        tmp_path,
        live_enabled=True,
        package_verifier=_accept_all,
        decision_authenticator=HmacDecisionAuthenticator(KEY),
    )
    monkeypatch.setattr(adapter, "_compose", lambda *a, **k: None)
    signed = sign_decision(_decision(raw, plan), KEY)
    result = adapter.activate_environment("env-1", raw, plan, signed)
    assert result["status"] == "active"


def test_tampered_signed_decision_rejected(tmp_path):
    raw = load_package(PACKAGE)
    plan = build_placement_plan(raw, _host(), "lite", edge_decision_id="edge-decision-1")
    adapter = DockerComposeAdapter(
        COMPOSE,
        tmp_path,
        live_enabled=True,
        package_verifier=_accept_all,
        decision_authenticator=HmacDecisionAuthenticator(KEY),
    )
    signed = sign_decision(_decision(raw, plan), KEY)
    signed["budget"]["memory_mb"] = 999999  # tamper after signing
    with pytest.raises(RuntimeGateError, match="failed authentication"):
        adapter.activate_environment("env-1", raw, plan, signed)
    assert adapter.state.decision_consumed("edge-decision-1") is False


def test_absent_authenticator_preserves_existing_behavior(tmp_path, monkeypatch):
    raw = load_package(PACKAGE)
    plan = build_placement_plan(raw, _host(), "lite", edge_decision_id="edge-decision-1")
    adapter = DockerComposeAdapter(
        COMPOSE, tmp_path, live_enabled=True, package_verifier=_accept_all
    )  # no decision_authenticator
    monkeypatch.setattr(adapter, "_compose", lambda *a, **k: None)
    result = adapter.activate_environment("env-1", raw, plan, _decision(raw, plan))
    assert result["status"] == "active"
