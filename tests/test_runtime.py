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


def _decision(package, plan, decision_id="edge-decision-1"):
    now = datetime.now(timezone.utc)
    return {
        "schema_version": "environment-activation-decision/v0.1",
        "decision_id": decision_id,
        "decision_authority": "azazel-edge",
        "status": "accepted",
        "package_id": package["package_id"],
        "package_digest": package["package_digest"],
        "target_node_id": plan["node_id"],
        "selected_tier": plan["selected_tier"],
        "budget": {
            "cpu_cores": 2,
            "memory_mb": 1024,
            "storage_mb": 2048,
            "max_connections": 100,
            "max_duration_seconds": 300,
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


def test_live_activation_is_disabled_by_default(tmp_path):
    package = load_package(PACKAGE)
    plan = build_placement_plan(package, _host(), "lite", edge_decision_id="edge-decision-1")
    adapter = DockerComposeAdapter(COMPOSE, tmp_path, live_enabled=False)
    result = adapter.activate_environment("env-1", package, plan, _decision(package, plan))
    assert result["status"] == "disabled"
    assert result["live_execution"] is False
    assert adapter.collect_status("env-1")["state"] == "absent"


def test_unverified_oci_blocks_live_before_docker(tmp_path):
    package = load_package(PACKAGE)
    plan = build_placement_plan(package, _host(), "lite", edge_decision_id="edge-decision-1")
    adapter = DockerComposeAdapter(COMPOSE, tmp_path, live_enabled=True)
    with pytest.raises(RuntimeGateError, match="verified OCI provenance"):
        adapter.activate_environment("env-1", package, plan, _decision(package, plan))
    assert adapter.collect_status("env-1")["state"] == "absent"


def test_placement_must_bind_same_edge_decision(tmp_path):
    package = load_package(PACKAGE)
    plan = build_placement_plan(package, _host(), "lite", edge_decision_id="different-decision")
    adapter = DockerComposeAdapter(COMPOSE, tmp_path, live_enabled=True)
    with pytest.raises(RuntimeGateError, match="placement is not bound"):
        adapter.activate_environment("env-1", package, plan, _decision(package, plan))


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
