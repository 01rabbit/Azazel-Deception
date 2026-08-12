"""Canonical deception-package loading, sealing, and fail-closed validation.

External/runtime-facing package semantics are owned by
``azazel_fabric.deception_contracts``. The original bootstrap-v0.1 shape is
accepted only as a temporary compatibility input and is normalized immediately
into the canonical Fabric ``DeceptionPackage`` model.

``package_digest`` is a deterministic *semantic* content digest. It is defined
by exactly one pipeline::

    raw mapping / bootstrap shape
        -> Fabric ``DeceptionPackage`` normalization (types, defaults, ordering)
        -> canonical semantic signing payload (digest + signature_ref removed)
        -> deterministic JSON serialization
        -> SHA-256

Because the digest is *always* computed from the normalized model, the same
semantic content produces an identical digest whether it arrives as a raw dict,
a Pydantic model dump, a YAML reload, or a JSON round-trip. Hashing a raw,
un-normalized mapping is deliberately never done here: integer/float coercion,
omitted-vs-default fields, and key ordering would otherwise cause digest drift.

``package_digest`` binds every package semantic except the digest field itself
and the detached ``signature_ref`` locator. ``signer_ref`` is bound, so changing
the expected signer identity changes the content digest.

Sealing and validation are separated on purpose:

* ``seal_package_digest`` is an explicit *authoring-time* operation: it computes
  and stamps the canonical digest. It never mutates its input.
* ``parse_package`` / ``validate_package`` are *runtime* operations: they only
  verify that a declared digest matches the recomputed canonical digest. They
  are fail-closed and never silently repair a bad digest.
"""

from __future__ import annotations

import hashlib
from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from azazel_fabric.deception_contracts import DeceptionPackage
from azazel_fabric.deception_integrity import (
    PackageIntegrityError,
    assert_package_content_digest,
    canonical_package_signing_bytes,
    package_content_digest,
    package_signing_payload,
)

CANONICAL_SCHEMA = "deception-package/v0.1"
BOOTSTRAP_SCHEMA = "deception-package/bootstrap-v0.1"
SUPPORTED_SCHEMAS = {CANONICAL_SCHEMA, BOOTSTRAP_SCHEMA}

_PLACEHOLDER_DIGEST = "sha256:" + "0" * 64


class PackageValidationError(ValueError):
    pass


def load_package(path: str | Path) -> dict[str, Any]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise PackageValidationError("package root must be a mapping")
    return data


def _sha(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _adapt_bootstrap(data: dict[str, Any]) -> dict[str, Any]:
    """Convert the repository's pre-Fabric bootstrap shape into v0.1.

    Generated image digest/provenance values remain explicitly unverified
    placeholders. The caller's declared ``package_digest`` is *preserved* (not
    silently recomputed) so that :func:`parse_package` stays fail-closed for
    bootstrap input: a bootstrap mapping with a wrong or absent digest fails
    validation exactly like a canonical one. Migrating a legacy bootstrap
    mapping into a usable package is therefore an explicit
    :func:`seal_package_digest` step, not a side effect of loading it. Live
    activation still rejects unverified selected images regardless.
    """

    req = data.get("runtime_requirements") or {}
    safety = data.get("safety") or {}
    raw_components = data.get("components") or []
    components: list[dict[str, Any]] = []
    for component in raw_components:
        image = str(component.get("image") or "bootstrap-missing-image")
        platforms = [
            {"architecture": arch, "digest": _sha(f"{image}:{arch}:bootstrap")}
            for arch in req.get("architectures", [])
            if arch in {"arm64", "amd64"}
        ]
        surfaces = []
        if component.get("container_port"):
            surfaces.append(
                {
                    "surface_id": f"{component.get('id')}-surface",
                    "protocol": "tcp",
                    "port": int(component["container_port"]),
                    "service": str(component.get("exposed_service") or "unknown"),
                }
            )
        components.append(
            {
                "component_id": component.get("id"),
                "required": bool(component.get("required", False)),
                "image": {
                    "image": image,
                    "manifest_digest": _sha(f"{image}:manifest:bootstrap"),
                    "platforms": platforms,
                    "provenance_ref": "bootstrap:unverified",
                    "sbom_ref": "bootstrap:unverified",
                    "verified": False,
                },
                "privileged": False,
                "host_network": False,
                "read_only_rootfs": True,
                "surfaces": surfaces,
            }
        )

    tiers = []
    for tier_id, tier in (data.get("deployment_tiers") or {}).items():
        minimum = tier.get("minimum") or {}
        tiers.append(
            {
                "tier_id": tier_id,
                "minimum": {
                    "cpu_cores": float(minimum.get("cpu_cores", 1)),
                    "memory_mb": int(minimum.get("memory_mb", 1)),
                    "storage_mb": int(minimum.get("storage_mb", 1)),
                    "max_connections": int(safety.get("max_connections", 100)),
                    "max_duration_seconds": int(safety.get("max_duration_seconds", 300)),
                },
                "include_components": list(tier.get("include") or []),
            }
        )

    narrative = data.get("narrative") or {}
    consistency = data.get("narrative_consistency") or {}
    minimum_tier = min(tiers, key=lambda item: item["minimum"]["memory_mb"]) if tiers else None
    minimum = (minimum_tier or {}).get("minimum") or {
        "cpu_cores": 1,
        "memory_mb": 1,
        "storage_mb": 1,
        "max_connections": 100,
        "max_duration_seconds": int(safety.get("max_duration_seconds", 300)),
    }

    tier_minima = [item["minimum"] for item in tiers] or [minimum]
    maximum_budget = {
        "cpu_cores": max(float(item["cpu_cores"]) for item in tier_minima),
        "memory_mb": max(int(item["memory_mb"]) for item in tier_minima),
        "storage_mb": max(int(item["storage_mb"]) for item in tier_minima),
        "max_connections": max(int(item["max_connections"]) for item in tier_minima),
        "max_duration_seconds": max(int(item["max_duration_seconds"]) for item in tier_minima),
        "bandwidth_kbps": int(safety.get("bandwidth_kbps", 10000)),
    }

    payload: dict[str, Any] = {
        "schema_version": CANONICAL_SCHEMA,
        "package_id": data.get("package_id"),
        "package_version": data.get("version"),
        # Preserve the caller's declared digest so validation stays fail-closed;
        # a bootstrap mapping is only usable after an explicit seal step.
        "package_digest": data.get("package_digest") or _PLACEHOLDER_DIGEST,
        "narrative": {
            "narrative_id": f"{data.get('package_id')}-narrative",
            "purpose": narrative.get("purpose") or "bootstrap deception environment",
            "environment_profile_id": f"{data.get('package_id')}-environment",
            "synthetic_only": bool(narrative.get("synthetic_only", True)),
            "locale": narrative.get("locale") or "en-US",
            "timezone": narrative.get("timezone") or "UTC",
            "engage_objective": narrative.get("engage_objective"),
            "engage_approach": narrative.get("engage_approach"),
            "engage_activities": list(narrative.get("engage_activities") or []),
        },
        "runtime_requirements": {
            "architectures": list(req.get("architectures") or []),
            "runtime_adapter": req.get("runtime_adapter") or "docker_compose",
            "minimum": minimum,
            "kvm_required": bool(req.get("kvm_required", False)),
            "gpu_required": bool(req.get("gpu_required", False)),
            "required_runtime_features": ["isolated_network", "resource_limits"],
            "required_profile_classes": ["static_linux"],
        },
        "maximum_budget": maximum_budget,
        "safety": {
            "outbound_allowed": False,
            "production_access": False,
            "privileged_containers": False,
            "host_network": False,
            "runtime_socket_exposed_to_decoys": False,
            "edge_control_access_from_decoys": False,
        },
        "components": components,
        "deployment_tiers": tiers,
        "consistency": {
            "report_id": f"{data.get('package_id')}-bootstrap-consistency",
            "fatal_contradictions": list(consistency.get("fatal_contradictions") or []),
            "warnings": list(consistency.get("warnings") or [])
            + ["normalized from bootstrap-v0.1; image provenance is unverified"],
            "waivers": [],
        },
        "credentials": [],
        "signer_ref": "bootstrap:unverified",
        "signature_ref": "bootstrap:detached-unverified",
    }
    return payload


def canonical_payload(data: dict[str, Any]) -> dict[str, Any]:
    """Return the canonical v0.1 mapping for a raw or bootstrap input.

    This only performs schema dispatch; it does not normalize field types or
    inject model defaults. Semantic normalization happens in
    :func:`normalize_package`.
    """

    schema = data.get("schema_version")
    if schema == BOOTSTRAP_SCHEMA:
        return _adapt_bootstrap(data)
    if schema == CANONICAL_SCHEMA:
        return data
    raise PackageValidationError(f"unsupported schema_version: {schema!r}")


def normalize_package(data: dict[str, Any]) -> DeceptionPackage:
    """Normalize raw/bootstrap input into the canonical Fabric model.

    This is the single semantic-normalization boundary: type coercion, default
    injection, and field ordering are resolved here so every downstream digest
    or payload derives from one canonical representation. It does not check the
    declared ``package_digest``; use :func:`parse_package` for that.
    """

    try:
        return DeceptionPackage.model_validate(canonical_payload(data))
    except ValidationError as exc:
        raise PackageValidationError(str(exc)) from exc


def canonical_package_payload(data: dict[str, Any]) -> dict[str, Any]:
    """Return the semantic payload covered by ``package_digest``.

    The detached ``signature_ref`` locator and ``package_digest`` field are
    excluded; every other normalized semantic field is included.
    """

    return package_signing_payload(normalize_package(data))


def canonical_package_payload_bytes(data: dict[str, Any]) -> bytes:
    """Return the exact detached bytes bound by ``package_digest``.

    These are the bytes an external signer/attestation service covers, so YAML
    whitespace, key order, and quoting never enter the signed semantics.
    """

    return canonical_package_signing_bytes(normalize_package(data))


def calculate_package_digest(data: dict[str, Any]) -> str:
    """Calculate the canonical content digest without trusting the declaration."""

    return package_content_digest(normalize_package(data))


def seal_package_digest(data: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of ``data`` stamped with its canonical content digest.

    Authoring-time operation. The input is not mutated and its original shape is
    preserved (only ``package_digest`` is replaced), so the sealed mapping stays
    human-readable while validating against the normalized digest.
    """

    sealed = deepcopy(data)
    sealed["package_digest"] = calculate_package_digest(data)
    return sealed


# Backwards-compatible alias retained for existing callers/CLI.
def package_signing_bytes(data: dict[str, Any]) -> bytes:
    return canonical_package_payload_bytes(data)


def parse_package(data: dict[str, Any]) -> DeceptionPackage:
    try:
        model = normalize_package(data)
        assert_package_content_digest(model)
        return model
    except (PackageValidationError, PackageIntegrityError) as exc:
        raise PackageValidationError(str(exc)) from exc


def validate_package(data: dict[str, Any]) -> list[str]:
    try:
        parse_package(data)
    except PackageValidationError as exc:
        return [str(exc)]
    return []


def require_valid_package(data: dict[str, Any]) -> DeceptionPackage:
    return parse_package(data)
