from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from azazel_deception.package import load_package
from azazel_deception.planner import build_placement_plan
from azazel_deception.runtime.compose import DockerComposeAdapter, RuntimeGateError
from azazel_fabric.testing import make_deception_package

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


def _decision(package, plan, decision_id="edge-decision-1", **budget_overrides):
    now = datetime.now(timezone.utc)
    budget = {
        "cpu_cores": 2,
        "memory_mb": 1024,
        "storage_mb": 2048,
        "max_connections": 100,
        "max_duration_seconds": 300,
        "bandwidth_kbps": 5000,
    }
    budget.update(budget_overrides)
    return {
        "schema_version": "environment-activation-decision/v0.1",
        "decision_id": decision_id,
        "decision_authority": "azazel-edge",
        "status": "accepted",
        "package_id": package["package_id"],
        "package_digest": package["package_digest"],
        "target_node_id": plan["node_id"],
        "selected_tier": plan["selected_tier"],
        "budget": budget,
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


def _termination(decision_id="edge-terminate-1", *, expired=False):
    now = datetime.now(timezone.utc)
    issued = now - timedelta(minutes=2) if expired else now
    expires = now - timedelta(minutes=1) if expired else now + timedelta(minutes=1)
    return {
        "schema_version": "environment-termination-decision/v0.1",
        "decision_id": decision_id,
        "decision_authority": "azazel-edge",
        "environment_id": "env-1",
        "reason": "operator_request",
        "issued_at": issued.isoformat(),
        "expires_at": expires.isoformat(),
        "evidence_refs": [],
    }


def _verified_package():
    return make_deception_package(verified=True).model_dump(mode="json")


def test_live_activation_is_disabled_by_default(tmp_path):
    package = load_package(PACKAGE)
    plan = build_placement_plan(package, _host(), "lite", edge_decision_id="edge-decision-1")
    adapter = DockerComposeAdapter(COMPOSE, tmp_path, live_enabled=False)
    result = adapter.activate_environment("env-1", package, plan, _decision(package, plan))
    assert result["status"] == "disabled"
    assert result["live_execution"] is False
    assert adapter.collect_status("env-1")["state"] == "absent"
    assert adapter.state.decision_consumed("edge-decision-1") is False


def test_unverified_oci_blocks_live_before_docker(tmp_path):
    package = load_package(PACKAGE)
    plan = build_placement_plan(package, _host(), "lite", edge_decision_id="edge-decision-1")
    adapter = DockerComposeAdapter(COMPOSE, tmp_path, live_enabled=True)
    with pytest.raises(RuntimeGateError, match="verified OCI provenance"):
        adapter.activate_environment("env-1", package, plan, _decision(package, plan))
    assert adapter.collect_status("env-1")["state"] == "absent"
    assert adapter.state.decision_consumed("edge-decision-1") is False


def test_placement_must_bind_same_edge_decision(tmp_path):
    package = _verified_package()
    plan = build_placement_plan(package, _host(), "lite", edge_decision_id="different-decision")
    adapter = DockerComposeAdapter(COMPOSE, tmp_path, live_enabled=True)
    with pytest.raises(RuntimeGateError, match="placement is not bound"):
        adapter.activate_environment("env-1", package, plan, _decision(package, plan))


def test_edge_budget_cannot_exceed_package_maximum(tmp_path):
    package = _verified_package()
    plan = build_placement_plan(package, _host(), "lite", edge_decision_id="edge-decision-1")
    adapter = DockerComposeAdapter(COMPOSE, tmp_path, live_enabled=True)
    decision = _decision(package, plan, memory_mb=99999)
    with pytest.raises(RuntimeGateError, match="exceeds package maximum"):
        adapter.activate_environment("env-1", package, plan, decision)
    assert adapter.state.decision_consumed("edge-decision-1") is False


def test_edge_budget_must_cover_selected_tier_minimum(tmp_path):
    package = _verified_package()
    plan = build_placement_plan(package, _host(), "lite", edge_decision_id="edge-decision-1")
    adapter = DockerComposeAdapter(COMPOSE, tmp_path, live_enabled=True)
    decision = _decision(package, plan, cpu_cores=1, memory_mb=512)
    with pytest.raises(RuntimeGateError, match="below selected tier minimum"):
        adapter.activate_environment("env-1", package, plan, decision)


def test_live_allocation_requires_explicit_bandwidth_budget(tmp_path):
    package = _verified_package()
    plan = build_placement_plan(package, _host(), "lite", edge_decision_id="edge-decision-1")
    adapter = DockerComposeAdapter(COMPOSE, tmp_path, live_enabled=True)
    decision = _decision(package, plan)
    decision["budget"]["bandwidth_kbps"] = None
    with pytest.raises(RuntimeGateError, match="exceeds package maximum"):
        adapter.activate_environment("env-1", package, plan, decision)


def test_activation_decision_is_one_shot(tmp_path, monkeypatch):
    package = _verified_package()
    plan = build_placement_plan(package, _host(), "lite", edge_decision_id="edge-decision-1")
    adapter = DockerComposeAdapter(COMPOSE, tmp_path, live_enabled=True)
    monkeypatch.setattr(adapter, "_compose", lambda *args, **kwargs: None)

    decision = _decision(package, plan)
    first = adapter.activate_environment("env-1", package, plan, decision)
    assert first["status"] == "active"
    assert adapter.state.decision_consumed("edge-decision-1") is True

    state = adapter.state.read("env-1")
    assert state is not None
    state["state"] = "terminated"
    adapter.state.write("env-1", state)

    with pytest.raises(RuntimeGateError, match="already consumed"):
        adapter.activate_environment("env-1", package, plan, decision)


def test_expired_termination_decision_is_rejected(tmp_path):
    adapter = DockerComposeAdapter(COMPOSE, tmp_path, live_enabled=False)
    adapter.state.write("env-1", {"environment_id": "env-1", "state": "active"})
    with pytest.raises(RuntimeGateError, match="termination decision is expired"):
        adapter.terminate_environment("env-1", _termination(expired=True))
    assert adapter.state.decision_consumed("edge-terminate-1") is False


def test_termination_decision_is_one_shot(tmp_path):
    adapter = DockerComposeAdapter(COMPOSE, tmp_path, live_enabled=False)
    adapter.state.write(
        "env-1",
        {
            "environment_id": "env-1",
            "state": "active",
            "package_id": "municipal-linux-v1",
            "node_id": "az06-test",
        },
    )
    decision = _termination()
    assert adapter.terminate_environment("env-1", decision)["status"] == "terminated"
    with pytest.raises(RuntimeGateError, match="already consumed"):
        adapter.terminate_environment("env-1", decision)


def test_reset_clears_runtime_state_but_preserves_evidence(tmp_path):
    adapter = DockerComposeAdapter(COMPOSE, tmp_path, live_enabled=False)
    adapter.state.write(
        "env-1",
        {
            "environment_id": "env-1",
            "state": "terminated",
            "package_id": "municipal-linux-v1",
            "node_id": "az06-test",
        },
    )
    adapter.state.append_evidence("env-1", {"event": "before-reset"})
    result = adapter.reset_environment("env-1")
    assert result["status"] == "reset"
    assert result["evidence_preserved"] is True
    assert adapter.collect_status("env-1")["state"] == "absent"
    events = adapter.export_evidence("env-1")
    assert events[0]["event"] == "before-reset"
    assert events[-1]["event_type"] == "reset_completed"
