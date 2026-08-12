"""Deterministic dry-run placement planning.

A PlacementPlan is descriptive AZ-06-local output tied to no authority. It
never starts a container or expands an Edge decision.
"""

from __future__ import annotations

from typing import Any

from .package import PackageValidationError, require_valid_package

TIER_ORDER = ("lite", "standard", "heavy", "cluster")


def _resources_fit(minimum: dict[str, Any], host: dict[str, Any]) -> bool:
    return (
        host.get("cpu_cores", 0) >= int(minimum.get("cpu_cores", 0))
        and host.get("memory_mb", 0) >= int(minimum.get("memory_mb", 0))
        and host.get("storage_free_mb", 0) >= int(minimum.get("storage_mb", 0))
    )


def build_placement_plan(package: dict[str, Any], host: dict[str, Any], requested_tier: str | None = None) -> dict[str, Any]:
    require_valid_package(package)
    req = package["runtime_requirements"]
    if host.get("architecture") not in req.get("architectures", []):
        raise PackageValidationError("host architecture does not satisfy package requirements")
    adapter = req.get("runtime_adapter")
    if not host.get("runtime_adapters", {}).get(adapter, False):
        raise PackageValidationError("required runtime adapter is unavailable")
    if req.get("kvm_required") and not host.get("kvm_available"):
        raise PackageValidationError("KVM is required but unavailable")
    if req.get("gpu_required") and not host.get("gpu_available"):
        raise PackageValidationError("GPU is required but unavailable")

    tiers = package["deployment_tiers"]
    candidates = [requested_tier] if requested_tier else [t for t in TIER_ORDER if t in tiers]
    selected = None
    for tier_name in candidates:
        if tier_name not in tiers:
            continue
        if _resources_fit(tiers[tier_name].get("minimum", {}), host):
            selected = tier_name
            break
    if selected is None:
        raise PackageValidationError("no authored deployment tier fits host capabilities")

    tier = tiers[selected]
    component_ids = {c["id"] for c in package["components"]}
    included = list(tier.get("include", []))
    unknown = sorted(set(included) - component_ids)
    if unknown:
        raise PackageValidationError(f"tier references unknown components: {unknown}")
    required_ids = {c["id"] for c in package["components"] if c.get("required", False)}
    if not required_ids.issubset(set(included)):
        raise PackageValidationError("selected tier omits a required narrative component")

    return {
        "schema_version": "placement-plan/bootstrap-v0.1",
        "package_id": package["package_id"],
        "package_version": package["version"],
        "node_id": host.get("node_id"),
        "architecture": host.get("architecture"),
        "runtime_adapter": adapter,
        "selected_tier": selected,
        "components": included,
        "authority": "descriptive_only",
        "live_execution": False,
    }
