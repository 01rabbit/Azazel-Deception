"""Strict live posture: injected security gates can be made mandatory."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from azazel_deception.package import load_package
from azazel_deception.planner import build_placement_plan
from azazel_deception.runtime.compose import DockerComposeAdapter, RuntimeGateError
from azazel_deception.runtime.transport import HmacDecisionAuthenticator, sign_decision

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


def _decision(raw, plan):
    now = datetime.now(timezone.utc)
    return {
        "schema_version": "environment-activation-decision/v0.1",
        "decision_id": "edge-decision-1",
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


def _accept_all(_package):
    return True


def _plan(raw):
    return build_placement_plan(raw, _host(), "lite", edge_decision_id="edge-decision-1")


def test_strict_sbom_requires_configured_verifier(tmp_path):
    raw = load_package(PACKAGE)
    adapter = DockerComposeAdapter(
        COMPOSE,
        tmp_path,
        live_enabled=True,
        package_verifier=_accept_all,
        require_sbom_verification=True,  # but no sbom_verifier supplied
    )
    with pytest.raises(RuntimeGateError, match="SBOM verification required"):
        adapter.activate_environment("env-1", raw, _plan(raw), _decision(raw, _plan(raw)))
    assert adapter.state.decision_consumed("edge-decision-1") is False


def test_strict_auth_requires_configured_authenticator(tmp_path):
    raw = load_package(PACKAGE)
    adapter = DockerComposeAdapter(
        COMPOSE,
        tmp_path,
        live_enabled=True,
        package_verifier=_accept_all,
        require_authenticated_decisions=True,  # but no authenticator supplied
    )
    with pytest.raises(RuntimeGateError, match="authenticated Edge decision required"):
        adapter.activate_environment("env-1", raw, _plan(raw), _decision(raw, _plan(raw)))
    assert adapter.state.decision_consumed("edge-decision-1") is False


def test_strict_posture_accepts_when_all_gates_present(tmp_path, monkeypatch):
    raw = load_package(PACKAGE)
    plan = _plan(raw)
    adapter = DockerComposeAdapter(
        COMPOSE,
        tmp_path,
        live_enabled=True,
        package_verifier=_accept_all,
        sbom_verifier=lambda p: True,
        decision_authenticator=HmacDecisionAuthenticator(KEY),
        require_sbom_verification=True,
        require_authenticated_decisions=True,
    )
    monkeypatch.setattr(adapter, "_compose", lambda *a, **k: None)
    signed = sign_decision(_decision(raw, plan), KEY)
    result = adapter.activate_environment("env-1", raw, plan, signed)
    assert result["status"] == "active"


def test_health_reports_strict_posture(tmp_path):
    adapter = DockerComposeAdapter(
        COMPOSE,
        tmp_path,
        live_enabled=True,
        require_sbom_verification=True,
        require_authenticated_decisions=True,
    )
    health = adapter.health()
    assert health["require_sbom_verification"] is True
    assert health["require_authenticated_decisions"] is True
    assert health["package_verifier_configured"] is False
    assert health["sbom_verifier_configured"] is False
    assert health["decision_authenticator_configured"] is False


def test_defaults_are_not_strict(tmp_path):
    adapter = DockerComposeAdapter(COMPOSE, tmp_path)
    assert adapter.require_sbom_verification is False
    assert adapter.require_authenticated_decisions is False
