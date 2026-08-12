from pathlib import Path

import pytest

from azazel_deception.package import PackageValidationError, load_package
from azazel_deception.planner import build_placement_plan

PACKAGE = Path("examples/packages/municipal-linux-v1/package.yaml")


def host(arch="arm64", memory=8192, storage=65536, docker=True):
    return {
        "node_id": "test-node",
        "architecture": arch,
        "cpu_cores": 4,
        "memory_mb": memory,
        "storage_free_mb": storage,
        "runtime_adapters": {"docker_compose": docker},
        "kvm_available": False,
        "gpu_available": False,
    }


def test_lite_plan_is_deterministic_and_descriptive_only():
    first = build_placement_plan(load_package(PACKAGE), host(), "lite")
    second = build_placement_plan(load_package(PACKAGE), host(), "lite")
    assert first == second
    assert first["schema_version"] == "placement-plan/v0.1"
    assert first["selected_tier"] == "lite"
    assert first["component_ids"] == ["intranet-web"]
    assert first["authority"] == "descriptive_only"
    assert first["edge_decision_id"] is None


def test_edge_decision_reference_is_descriptive_binding_only():
    plan = build_placement_plan(
        load_package(PACKAGE), host(), "lite", edge_decision_id="edge-shadow-1"
    )
    assert plan["edge_decision_id"] == "edge-shadow-1"
    assert plan["authority"] == "descriptive_only"


def test_amd64_is_supported():
    plan = build_placement_plan(load_package(PACKAGE), host(arch="amd64"), "lite")
    assert plan["architecture"] == "amd64"


def test_missing_runtime_fails_closed():
    with pytest.raises(PackageValidationError):
        build_placement_plan(load_package(PACKAGE), host(docker=False), "lite")
