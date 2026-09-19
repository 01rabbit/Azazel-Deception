"""Bounded Lite profiles as *reductions* of a signed package (Deception#35).

The issue asks for a proof that an overlay "cannot add or widen services,
images, ports, routes, DNS, mounts, capabilities, commands, credentials, or
resources". There are two ways to get that, and this module uses both, in this
order:

**1. Make widening unrepresentable.** A `ProfileOverlay` is a *selection*, not
a patch. Every one of its fields is either a set of identifiers that must
already resolve inside the signed base package, or a numeric ceiling that is
combined with the base's by taking the minimum. There is no free-form field, no
"add" list, and no place to write an image, a port, a route, a DNS name, a
mount, a command, or a credential that the base does not already carry. An
overlay naming something the base lacks is refused at render time.

**2. Check the rendered result anyway.** `assert_is_reduction` compares the
rendered manifest against the base independently of how it was produced. Four
of the ten dimensions the issue names — routes, DNS, mounts, commands — have
**no representation in `deception-package/v0.1` at all**. Rather than invent
schema for them, the check proves something stronger and schema-independent:
every string that appears anywhere in the rendered manifest already appears
somewhere in the base. A route, a DNS name, a mount path or a command would
have to be a string that was not there before, so none can be introduced,
whether or not the schema ever learns to model it.

The rendered manifest is a **derived artifact**. It is not separately signed:
it binds to exactly one `base_package_digest`, and a consumer verifies the
signed base first and the rendering second. An overlay confers nothing. AZ-06
materializes what Edge already approved; it does not select, approve, or widen.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any

from .package import (
    PackageValidationError,
    calculate_package_digest,
    require_valid_package,
)

__all__ = [
    "BOOT_EMERGENCY_LITE",
    "CEILING_FIELDS",
    "NEXUS_EMBEDDED_LITE",
    "EvidenceBudget",
    "ProfileOverlay",
    "ResourceCeiling",
    "assert_is_reduction",
    "render_profile",
]

#: Budget fields an overlay may lower. Each is a number, and the rendered value
#: is `min(base, overlay)`, so "lower" is the only direction available.
CEILING_FIELDS = (
    "cpu_cores",
    "memory_mb",
    "storage_mb",
    "max_connections",
    "max_duration_seconds",
    "bandwidth_kbps",
)


@dataclass(frozen=True)
class ResourceCeiling:
    """A ceiling that can only tighten. `None` means "inherit the base's"."""

    cpu_cores: float | None = None
    memory_mb: int | None = None
    storage_mb: int | None = None
    max_connections: int | None = None
    max_duration_seconds: int | None = None
    bandwidth_kbps: int | None = None

    def applied_to(self, base: dict[str, Any]) -> dict[str, Any]:
        out = dict(base)
        for field in CEILING_FIELDS:
            mine = getattr(self, field)
            if mine is None:
                continue
            theirs = base.get(field)
            out[field] = mine if theirs is None else min(mine, theirs)
        return out


@dataclass(frozen=True)
class EvidenceBudget:
    """Finite evidence budget (AC-3).

    Required and finite on purpose. An unbounded evidence budget is how hostile
    telemetry consumes Core reserves, so a profile that declines to state one
    is not a bounded profile.
    """

    max_observation_events: int
    max_observation_bytes: int
    max_retention_seconds: int

    def __post_init__(self) -> None:
        for field in ("max_observation_events", "max_observation_bytes", "max_retention_seconds"):
            value = getattr(self, field)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise PackageValidationError(
                    f"evidence budget {field} must be a positive integer; a profile "
                    "without a finite evidence budget is not bounded"
                )


@dataclass(frozen=True)
class ProfileOverlay:
    """A named reduction of one signed package. It grants nothing."""

    profile_id: str
    base_package_id: str
    base_package_digest: str
    keep_components: tuple[str, ...]
    keep_surfaces: tuple[str, ...]
    keep_credentials: tuple[str, ...]
    ceiling: ResourceCeiling
    evidence: EvidenceBudget


def _ids(items: list[dict[str, Any]], key: str) -> set[str]:
    return {str(item[key]) for item in items if key in item}


def render_profile(base: dict[str, Any], overlay: ProfileOverlay) -> dict[str, Any]:
    """Render `overlay` against `base`. Refuses anything that is not a reduction."""

    package = require_valid_package(base)
    # The full validated package, not `canonical_package_payload` -- that one
    # omits the digest/signature fields because it is the digest *input*.
    payload = copy.deepcopy(package.model_dump(mode="json"))

    if package.package_id != overlay.base_package_id:
        raise PackageValidationError(
            f"overlay {overlay.profile_id!r} targets package "
            f"{overlay.base_package_id!r}, not {package.package_id!r}"
        )
    if package.package_digest != overlay.base_package_digest:
        raise PackageValidationError(
            f"overlay {overlay.profile_id!r} is bound to a different package digest; "
            "an overlay applies to exactly one signed package"
        )

    known_components = _ids(payload["components"], "component_id")
    unknown = set(overlay.keep_components) - known_components
    if unknown:
        raise PackageValidationError(
            f"overlay would keep components the package does not have: {sorted(unknown)}"
        )
    if not overlay.keep_components:
        raise PackageValidationError("an overlay must keep at least one component")

    required = {
        str(item["component_id"]) for item in payload["components"] if item.get("required", True)
    }
    dropped_required = required - set(overlay.keep_components)
    if dropped_required:
        raise PackageValidationError(
            f"overlay drops components the package marks required: {sorted(dropped_required)}. "
            "A profile without them is a different package, not a reduction of this one"
        )

    known_surfaces = {
        str(surface["surface_id"])
        for component in payload["components"]
        for surface in component.get("surfaces", [])
    }
    unknown = set(overlay.keep_surfaces) - known_surfaces
    if unknown:
        raise PackageValidationError(
            f"overlay would keep surfaces the package does not expose: {sorted(unknown)}"
        )

    known_credentials = _ids(payload.get("credentials", []), "credential_id")
    unknown = set(overlay.keep_credentials) - known_credentials
    if unknown:
        raise PackageValidationError(
            f"overlay would keep credentials the package does not carry: {sorted(unknown)}"
        )

    kept = set(overlay.keep_components)
    payload["components"] = [
        {
            **component,
            "surfaces": [
                surface
                for surface in component.get("surfaces", [])
                if str(surface["surface_id"]) in set(overlay.keep_surfaces)
            ],
        }
        for component in payload["components"]
        if str(component["component_id"]) in kept
    ]
    payload["credentials"] = [
        credential
        for credential in payload.get("credentials", [])
        if str(credential.get("credential_id")) in set(overlay.keep_credentials)
    ]

    payload["maximum_budget"] = overlay.ceiling.applied_to(payload["maximum_budget"])

    # A tier survives only if every component it includes survived and its own
    # minimum still fits under the tightened ceiling. A tier's minimum is a
    # statement about what the workload needs, so it is dropped, never lowered:
    # lowering it would be inventing a resource claim nobody made.
    surviving = []
    for tier in payload["deployment_tiers"]:
        if not set(tier["include_components"]) <= kept:
            continue
        if not _fits(tier["minimum"], payload["maximum_budget"]):
            continue
        surviving.append(tier)
    if not surviving:
        raise PackageValidationError(
            f"overlay {overlay.profile_id!r} leaves no deployment tier that fits its "
            "own ceiling; the profile is not deployable and must not be rendered"
        )
    payload["deployment_tiers"] = surviving

    if not _fits(payload["runtime_requirements"]["minimum"], payload["maximum_budget"]):
        raise PackageValidationError(
            f"overlay {overlay.profile_id!r} lowers the ceiling below the package's own "
            "runtime minimum"
        )

    payload["package_digest"] = calculate_package_digest(payload)
    rendered = {
        "profile_id": overlay.profile_id,
        "base_package_id": overlay.base_package_id,
        "base_package_digest": overlay.base_package_digest,
        # The artifact declares what it selected, so the manifest can be checked
        # against the profile's own claim and not only against the base.
        "selection": {
            "components": sorted(overlay.keep_components),
            "surfaces": sorted(overlay.keep_surfaces),
            "credentials": sorted(overlay.keep_credentials),
        },
        "evidence_budget": {
            "max_observation_events": overlay.evidence.max_observation_events,
            "max_observation_bytes": overlay.evidence.max_observation_bytes,
            "max_retention_seconds": overlay.evidence.max_retention_seconds,
        },
        "manifest": payload,
    }
    assert_is_reduction(base, rendered)
    return rendered


def _fits(minimum: dict[str, Any], ceiling: dict[str, Any]) -> bool:
    for field in CEILING_FIELDS:
        want = minimum.get(field)
        cap = ceiling.get(field)
        if want is None or cap is None:
            continue
        if want > cap:
            return False
    return True


def _strings(value: Any, out: set[str]) -> None:
    if isinstance(value, str):
        out.add(value)
    elif isinstance(value, dict):
        for key, child in value.items():
            out.add(str(key))
            _strings(child, out)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _strings(child, out)


def assert_is_reduction(base: dict[str, Any], rendered: dict[str, Any]) -> None:
    """Prove the rendered manifest adds and widens nothing. Raises otherwise.

    Independent of `render_profile`: it takes the two payloads and checks them,
    so a hand-edited or third-party rendering is held to the same rule.
    """

    base_payload = require_valid_package(base).model_dump(mode="json")
    manifest = rendered["manifest"]

    base_components = {
        str(item["component_id"]): item for item in base_payload["components"]
    }
    for component in manifest["components"]:
        cid = str(component["component_id"])
        original = base_components.get(cid)
        if original is None:
            raise PackageValidationError(f"rendered manifest adds a service: {cid}")
        if component["image"] != original["image"]:
            raise PackageValidationError(f"rendered manifest changes the image of {cid}")
        base_surfaces = {
            (s["protocol"], s["port"], s["service"]) for s in original.get("surfaces", [])
        }
        for surface in component.get("surfaces", []):
            key = (surface["protocol"], surface["port"], surface["service"])
            if key not in base_surfaces:
                raise PackageValidationError(
                    f"rendered manifest opens a port the package does not: {cid} {key}"
                )
        # Capabilities may only stay closed or become more closed.
        if component.get("privileged", False) or component.get("host_network", False):
            raise PackageValidationError(f"rendered manifest widens capabilities of {cid}")
        if not component.get("read_only_rootfs", True) and original.get("read_only_rootfs", True):
            raise PackageValidationError(f"rendered manifest loosens the rootfs of {cid}")

    # Check the manifest against the profile's own declared selection, not only
    # against the base. Without this, re-adding a component the profile excluded
    # reads as a reduction of the base -- which it is -- while being a widening
    # of the profile, which is what a consumer actually installed.
    #
    # What this catches: an edit to the manifest alone. What it does not catch:
    # a consistent edit to both the selection and the manifest, which produces a
    # different profile that is still a valid reduction of the same base.
    # Deciding *which* profiles are authorized is a policy question, answered by
    # whatever verifies this artifact, not by this function.
    selection = rendered.get("selection")
    if selection is not None:
        declared = set(selection["components"])
        present = {str(item["component_id"]) for item in manifest["components"]}
        if present != declared:
            raise PackageValidationError(
                f"rendered manifest holds components {sorted(present)}, but the profile "
                f"selected {sorted(declared)}"
            )
        declared_surfaces = set(selection["surfaces"])
        present_surfaces = {
            str(surface["surface_id"])
            for component in manifest["components"]
            for surface in component.get("surfaces", [])
        }
        if not present_surfaces <= declared_surfaces:
            raise PackageValidationError(
                f"rendered manifest exposes surfaces the profile did not select: "
                f"{sorted(present_surfaces - declared_surfaces)}"
            )
        declared_credentials = set(selection["credentials"])
        present_credentials = {
            str(item.get("credential_id")) for item in manifest.get("credentials", [])
        }
        if not present_credentials <= declared_credentials:
            raise PackageValidationError(
                f"rendered manifest carries credentials the profile did not select: "
                f"{sorted(present_credentials - declared_credentials)}"
            )
        for tier in manifest["deployment_tiers"]:
            extra = set(tier["include_components"]) - declared
            if extra:
                raise PackageValidationError(
                    f"tier {tier['tier_id']} includes components the profile excluded: "
                    f"{sorted(extra)}"
                )

    base_credentials = _ids(base_payload.get("credentials", []), "credential_id")
    for credential in manifest.get("credentials", []):
        cid = str(credential.get("credential_id"))
        if cid not in base_credentials:
            raise PackageValidationError(f"rendered manifest adds a credential: {cid}")

    for field in CEILING_FIELDS:
        cap = manifest["maximum_budget"].get(field)
        original = base_payload["maximum_budget"].get(field)
        if cap is None or original is None:
            continue
        if cap > original:
            raise PackageValidationError(
                f"rendered manifest widens the resource ceiling {field}: {original} -> {cap}"
            )

    base_tiers = {str(t["tier_id"]): t for t in base_payload["deployment_tiers"]}
    for tier in manifest["deployment_tiers"]:
        original = base_tiers.get(str(tier["tier_id"]))
        if original is None:
            raise PackageValidationError(f"rendered manifest adds a tier: {tier['tier_id']}")
        if not set(tier["include_components"]) <= set(original["include_components"]):
            raise PackageValidationError(
                f"tier {tier['tier_id']} includes components the base tier does not"
            )

    if manifest["safety"] != base_payload["safety"]:
        raise PackageValidationError("rendered manifest changes the package safety policy")

    # The schema-independent guard. Routes, DNS names, mount paths and commands
    # have no field in deception-package/v0.1; each would have to arrive as a
    # string that was not in the base. `package_digest` is exempt because it is
    # recomputed over the reduced payload by design.
    base_strings: set[str] = set()
    _strings(base_payload, base_strings)
    base_strings.add(manifest["package_digest"])
    rendered_strings: set[str] = set()
    _strings(manifest, rendered_strings)
    introduced = sorted(rendered_strings - base_strings)
    if introduced:
        raise PackageValidationError(
            f"rendered manifest introduces strings absent from the signed package: {introduced}. "
            "A route, DNS name, mount, or command could only arrive this way"
        )


#: The two profiles the program plan names. Both are authored against
#: `examples/packages/municipal-linux-v1`; a deployment authors its own against
#: whatever package it actually signed.
#:
#: The budgets are the *shape* of a bounded profile, not a measured envelope:
#: no Nexus and no Boot host has been measured, so these are ceilings chosen to
#: be conservative, and they are config, not a hardware claim.
NEXUS_EMBEDDED_LITE = ProfileOverlay(
    profile_id="nexus-embedded-lite",
    base_package_id="municipal-linux-v1",
    base_package_digest="sha256:baca710857669a1901afaf18f32c44f7b0d18a913c11dad6030a40aa8785de53",
    keep_components=("intranet-web",),
    keep_surfaces=("intranet-web-http",),
    keep_credentials=(),
    ceiling=ResourceCeiling(
        cpu_cores=2, memory_mb=2048, storage_mb=4096,
        max_connections=100, max_duration_seconds=300, bandwidth_kbps=2000,
    ),
    evidence=EvidenceBudget(
        max_observation_events=50_000,
        max_observation_bytes=32 * 1024 * 1024,
        max_retention_seconds=7 * 24 * 3600,
    ),
)

#: Boot runs on borrowed hardware: the host is not ours, the session is short,
#: and evidence that outlives the incident is a liability rather than an asset.
#:
#: Note what this profile does **not** do. Its compute ceiling equals this
#: package's own declared floor (cpu 2 / memory 1024 / storage 2048 /
#: connections 100) rather than going lower, because the package states that is
#: what the workload needs. A profile cannot promise a workload less than the
#: workload declared, and lowering a ceiling past a declared minimum is a
#: misconfiguration rather than a reduction -- `render_profile` refuses it, and
#: refusing it was how this constraint was found rather than assumed.
#:
#: So against *this* base package, Boot Lite differs from Nexus Lite in
#: bandwidth and in evidence budget, not in compute. A package authored for
#: emergency use with a smaller declared minimum would reduce further; this one
#: does not, and saying so is better than inventing headroom it never had.
BOOT_EMERGENCY_LITE = ProfileOverlay(
    profile_id="boot-emergency-lite",
    base_package_id="municipal-linux-v1",
    base_package_digest="sha256:baca710857669a1901afaf18f32c44f7b0d18a913c11dad6030a40aa8785de53",
    keep_components=("intranet-web",),
    keep_surfaces=("intranet-web-http",),
    keep_credentials=(),
    ceiling=ResourceCeiling(
        cpu_cores=2, memory_mb=1024, storage_mb=2048,
        max_connections=100, max_duration_seconds=300, bandwidth_kbps=512,
    ),
    evidence=EvidenceBudget(
        max_observation_events=5_000,
        max_observation_bytes=4 * 1024 * 1024,
        max_retention_seconds=12 * 3600,
    ),
)
