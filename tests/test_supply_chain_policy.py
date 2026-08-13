"""Fail-closed supply-chain policy: verified images need real provenance/SBOM."""

from pathlib import Path

import pytest

from azazel_deception.package import (
    calculate_package_digest,
    load_package,
    parse_package,
)
from azazel_deception.planner import build_placement_plan
from azazel_deception.runtime.compose import DockerComposeAdapter, RuntimeGateError
from azazel_deception.runtime.preflight import (
    RuntimePreflightError,
    require_supply_chain_backed_images,
)
from azazel_fabric.deception_contracts import PlacementPlan

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
    from datetime import datetime, timedelta, timezone

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


def test_reference_verified_component_has_real_refs():
    raw = load_package(PACKAGE)
    package = parse_package(raw)
    plan = PlacementPlan.model_validate(
        build_placement_plan(raw, _host(), "lite", edge_decision_id="edge-decision-1")
    )
    require_supply_chain_backed_images(package, plan)  # must not raise


# Note: an empty ref is rejected earlier by the Fabric model (min_length=1), an
# even stronger fail-closed; these are the non-empty placeholder forms that would
# otherwise slip a "verified" claim past the schema.
@pytest.mark.parametrize(
    "bad_ref",
    ["bootstrap:unverified", "unverified-thing", "placeholder", "none"],
)
def test_verified_component_with_placeholder_provenance_fails_closed(bad_ref):
    raw = load_package(PACKAGE)
    raw["components"][0]["image"]["provenance_ref"] = bad_ref
    raw["package_digest"] = calculate_package_digest(raw)
    package = parse_package(raw)
    plan = PlacementPlan.model_validate(
        build_placement_plan(raw, _host(), "lite", edge_decision_id="edge-decision-1")
    )
    with pytest.raises(RuntimePreflightError, match="provenance"):
        require_supply_chain_backed_images(package, plan)


def test_verified_component_with_bootstrap_sbom_fails_closed():
    raw = load_package(PACKAGE)
    raw["components"][0]["image"]["sbom_ref"] = "bootstrap:unverified"
    raw["package_digest"] = calculate_package_digest(raw)
    package = parse_package(raw)
    plan = PlacementPlan.model_validate(
        build_placement_plan(raw, _host(), "lite", edge_decision_id="edge-decision-1")
    )
    with pytest.raises(RuntimePreflightError, match="SBOM"):
        require_supply_chain_backed_images(package, plan)


def test_unselected_unverified_optional_component_does_not_block():
    # The optional alpine placeholder is verified=false with bootstrap refs; a
    # lite placement that excludes it must still pass the supply-chain gate.
    raw = load_package(PACKAGE)
    package = parse_package(raw)
    plan = PlacementPlan.model_validate(
        build_placement_plan(raw, _host(), "lite", edge_decision_id="edge-decision-1")
    )
    assert plan.component_ids == ["intranet-web"]
    require_supply_chain_backed_images(package, plan)  # must not raise


def _accept_all(package):
    return True


def test_activation_gate_rejects_placeholder_provenance_before_docker(tmp_path):
    raw = load_package(PACKAGE)
    raw["components"][0]["image"]["provenance_ref"] = "bootstrap:unverified"
    raw["package_digest"] = calculate_package_digest(raw)
    plan = build_placement_plan(raw, _host(), "lite", edge_decision_id="edge-decision-1")
    adapter = DockerComposeAdapter(
        COMPOSE, tmp_path, live_enabled=True, package_verifier=_accept_all
    )
    with pytest.raises(RuntimeGateError, match="supply-chain policy failed"):
        adapter.activate_environment("env-1", raw, plan, _decision(raw, plan))
    assert adapter.state.decision_consumed("edge-decision-1") is False
