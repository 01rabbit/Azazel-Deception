"""Operator kill switch and descriptive status/health surface."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from azazel_deception.package import load_package
from azazel_deception.planner import build_placement_plan
from azazel_deception.runtime.compose import DockerComposeAdapter, RuntimeGateError

PACKAGE = Path("examples/packages/municipal-linux-v1/package.yaml")
COMPOSE = Path("runtime/compose/reference-linux.compose.yaml")


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


def _active_adapter(tmp_path, monkeypatch):
    raw = load_package(PACKAGE)
    plan = build_placement_plan(raw, _host(), "lite", edge_decision_id="edge-decision-1")
    adapter = DockerComposeAdapter(
        COMPOSE, tmp_path, live_enabled=True, package_verifier=_accept_all
    )
    monkeypatch.setattr(adapter, "_compose", lambda *a, **k: None)
    adapter.activate_environment("env-1", raw, plan, _decision(raw, plan))
    assert adapter.collect_status("env-1")["state"] == "active"
    return adapter


def test_kill_switch_requires_operator_and_reason(tmp_path):
    adapter = DockerComposeAdapter(COMPOSE, tmp_path, live_enabled=True)
    with pytest.raises(RuntimeGateError, match="operator and reason"):
        adapter.emergency_stop("env-1", operator="", reason="x")
    with pytest.raises(RuntimeGateError, match="operator and reason"):
        adapter.emergency_stop("env-1", operator="alice", reason="")


def test_kill_switch_terminates_active_environment_without_edge_decision(tmp_path, monkeypatch):
    adapter = _active_adapter(tmp_path, monkeypatch)
    result = adapter.emergency_stop("env-1", operator="alice", reason="incident-42")
    assert result["termination_kind"] == "operator_kill_switch"
    state = adapter.state.read("env-1")
    assert state["state"] == "terminated"
    assert state["kill_switch_operator"] == "alice"
    # No termination Edge decision was consumed by the override.
    assert adapter.state.consumed_decision_count() == 1  # only the activation

    evidence = adapter.export_evidence("env-1")
    kill_events = [e for e in evidence if e["metadata"].get("kind") == "operator_kill_switch"]
    assert kill_events and kill_events[-1]["event_type"] == "terminated"
    assert kill_events[-1]["metadata"]["reason"] == "incident-42"


def test_kill_switch_surfaces_stop_failure(tmp_path, monkeypatch):
    adapter = _active_adapter(tmp_path, monkeypatch)

    def boom(*a, **k):
        raise RuntimeGateError("docker down failed")

    monkeypatch.setattr(adapter, "_compose", boom)
    with pytest.raises(RuntimeGateError, match="docker down failed"):
        adapter.emergency_stop("env-1", operator="alice", reason="incident")
    state = adapter.state.read("env-1")
    assert state["state"] == "kill_switch_failed"
    evidence = adapter.export_evidence("env-1")
    assert any(e["event_type"] == "failure" for e in evidence)


def test_health_surface_is_descriptive_only(tmp_path, monkeypatch):
    adapter = _active_adapter(tmp_path, monkeypatch)
    health = adapter.health()
    assert health["authority"] == "descriptive_only"
    assert health["live_enabled"] is True
    assert health["adapter_id"] == "docker_compose"
    assert health["compose_present"] is True
    assert "env-1" in health["active_environments"]
    assert any(e["environment_id"] == "env-1" for e in health["environments"])
    assert health["consumed_decisions"] == 1


def test_health_surface_on_empty_state(tmp_path):
    adapter = DockerComposeAdapter(COMPOSE, tmp_path, live_enabled=False)
    health = adapter.health()
    assert health["live_enabled"] is False
    assert health["environments"] == []
    assert health["active_environments"] == []
