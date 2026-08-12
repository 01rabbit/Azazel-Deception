"""Bootstrap deception-package loading and fail-closed validation.

These local shapes are temporary bootstrap data, not a replacement for the
canonical Azazel-Fabric contracts tracked in Azazel-Fabric#9.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

SUPPORTED_SCHEMA = "deception-package/bootstrap-v0.1"
SUPPORTED_ARCHITECTURES = {"arm64", "amd64"}
SUPPORTED_ADAPTERS = {"docker_compose"}


class PackageValidationError(ValueError):
    pass


def load_package(path: str | Path) -> dict[str, Any]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise PackageValidationError("package root must be a mapping")
    return data


def validate_package(data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    required = ["schema_version", "package_id", "version", "runtime_requirements", "safety", "components", "deployment_tiers"]
    for field in required:
        if field not in data:
            errors.append(f"missing required field: {field}")

    if data.get("schema_version") != SUPPORTED_SCHEMA:
        errors.append(f"unsupported schema_version: {data.get('schema_version')!r}")

    req = data.get("runtime_requirements") or {}
    archs = set(req.get("architectures") or [])
    if not archs:
        errors.append("runtime_requirements.architectures must not be empty")
    if archs - SUPPORTED_ARCHITECTURES:
        errors.append(f"unsupported architectures: {sorted(archs - SUPPORTED_ARCHITECTURES)}")
    adapter = req.get("runtime_adapter")
    if adapter not in SUPPORTED_ADAPTERS:
        errors.append(f"unsupported runtime adapter: {adapter!r}")

    safety = data.get("safety") or {}
    if safety.get("outbound_allowed") is not False:
        errors.append("safety.outbound_allowed must be false in bootstrap profiles")
    if safety.get("production_access") is not False:
        errors.append("safety.production_access must be false")
    if not isinstance(safety.get("max_duration_seconds"), int) or safety.get("max_duration_seconds", 0) <= 0:
        errors.append("safety.max_duration_seconds must be a positive integer")

    components = data.get("components") or []
    if not isinstance(components, list) or not components:
        errors.append("components must be a non-empty list")
    else:
        ids: set[str] = set()
        for component in components:
            if not isinstance(component, dict):
                errors.append("every component must be a mapping")
                continue
            cid = component.get("id")
            if not cid or cid in ids:
                errors.append(f"component id must be unique and non-empty: {cid!r}")
            ids.add(cid)
            if component.get("privileged") is True:
                errors.append(f"component {cid!r} may not be privileged")
            if component.get("host_network") is True:
                errors.append(f"component {cid!r} may not use host networking")

    tiers = data.get("deployment_tiers") or {}
    if not isinstance(tiers, dict) or not tiers:
        errors.append("deployment_tiers must be a non-empty mapping")

    consistency = data.get("narrative_consistency") or {}
    if consistency.get("fatal_contradictions"):
        errors.append("package has unresolved fatal narrative contradictions")

    return errors


def require_valid_package(data: dict[str, Any]) -> None:
    errors = validate_package(data)
    if errors:
        raise PackageValidationError("; ".join(errors))
