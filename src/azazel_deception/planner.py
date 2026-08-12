"""Deterministic descriptive placement planning for AZ-06.

Placement is local scheduling inside an Edge-approved boundary.  A
``PlacementPlan`` is descriptive-only and cannot grant activation authority.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from azazel_fabric.deception_contracts import HostCapabilities, PlacementPlan

from .package import PackageValidationError, require_valid_package

TIER_ORDER = ("gadget-lite", "lite", "standard", "heavy", "cluster")


def _resources_fit(minimum: Any, host: HostCapabilities) -> bool:
    return (
        host.cpu_cores >= float(minimum.cpu_cores)
        and host.memory_mb >= int(minimum.memory_mb)
        and host.storage_free_mb >= int(minimum.storage_mb)
    )


def _sha_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def build_placement_plan(
    package: dict[str, Any],
    host: dict[str, Any],
    requested_tier: str | None = None,
    edge_decision_id: str | None = None,
) -> dict[str, Any]:
    pkg = require_valid_package(package)
    try:
        capabilities = HostCapabilities.model_validate(host)
    except Exception as exc:  # Pydantic error shape is not part of AZ-06 public API.
        raise PackageValidationError(f"invalid host capabilities: {exc}") from exc

    req = pkg.runtime_requirements
    if capabilities.architecture not in req.architectures:
        raise PackageValidationError("host architecture does not satisfy package requirements")
    if not capabilities.runtime_adapters.get(req.runtime_adapter, False):
        raise PackageValidationError("required runtime adapter is unavailable")
    if req.kvm_required and not capabilities.kvm_available:
        raise PackageValidationError("KVM is required but unavailable")
    if req.gpu_required and not capabilities.gpu_available:
        raise PackageValidationError("GPU is required but unavailable")
    if not _resources_fit(req.minimum, capabilities):
        raise PackageValidationError("host does not satisfy package minimum resources")

    by_name = {tier.tier_id: tier for tier in pkg.deployment_tiers}
    candidates = [requested_tier] if requested_tier else [name for name in TIER_ORDER if name in by_name]
    selected = None
    for tier_name in candidates:
        if tier_name is None or tier_name not in by_name:
            continue
        if _resources_fit(by_name[tier_name].minimum, capabilities):
            selected = tier_name
            break
    if selected is None:
        raise PackageValidationError("no authored deployment tier fits host capabilities")

    tier = by_name[selected]
    capability_digest = _sha_json(capabilities.model_dump(mode="json"))
    placement_seed = {
        "package_digest": pkg.package_digest,
        "node_id": capabilities.node_id,
        "selected_tier": selected,
        "capability_snapshot_digest": capability_digest,
        "edge_decision_id": edge_decision_id,
    }
    placement_id = "az06-placement-" + _sha_json(placement_seed).split(":", 1)[1][:16]

    plan = PlacementPlan(
        placement_id=placement_id,
        package_id=pkg.package_id,
        package_digest=pkg.package_digest,
        node_id=capabilities.node_id,
        architecture=capabilities.architecture,
        runtime_adapter=req.runtime_adapter,
        selected_tier=selected,
        component_ids=list(tier.include_components),
        capability_snapshot_digest=capability_digest,
        edge_decision_id=edge_decision_id,
    )
    return plan.model_dump(mode="json")
