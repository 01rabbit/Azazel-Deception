"""Live-runtime preflight checks that bind local assets to canonical packages."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import yaml

from azazel_fabric.deception_contracts import DeceptionPackage, PlacementPlan


class RuntimePreflightError(ValueError):
    pass


PackageVerifier = Callable[[DeceptionPackage], bool]
SbomVerifier = Callable[[DeceptionPackage], bool]


def require_sbom_attestation(
    package: DeceptionPackage,
    verifier: SbomVerifier | None,
) -> None:
    """Optionally require a cryptographic SBOM-attestation verifier to accept.

    When no verifier is injected this gate is skipped (making it mandatory for
    every live activation is a remaining live-gate step). When a verifier is
    injected it is enforced fail-closed: any exception or non-``True`` result
    rejects the package.
    """

    if verifier is None:
        return
    try:
        verified = verifier(package)
    except Exception as exc:
        raise RuntimePreflightError(f"SBOM verifier failed: {exc}") from exc
    if verified is not True:
        raise RuntimePreflightError("SBOM verifier rejected package")

# Reference prefixes that denote unverified/placeholder supply-chain metadata.
# A component claiming ``verified: true`` must not carry any of these.
_UNVERIFIED_REF_PREFIXES = ("bootstrap:", "unverified", "placeholder", "none")


def _is_real_supply_chain_ref(value: str | None) -> bool:
    if not value:
        return False
    text = value.strip().lower()
    if not text:
        return False
    return not text.startswith(_UNVERIFIED_REF_PREFIXES)


def require_supply_chain_backed_images(
    package: DeceptionPackage,
    placement: PlacementPlan,
) -> None:
    """Bind ``ImageManifest.verified`` to real provenance and SBOM references.

    A component selected to run and marked ``verified=true`` must carry a
    non-placeholder ``provenance_ref`` and ``sbom_ref``. This prevents a package
    from asserting verified state over an image whose supply-chain metadata is
    still a bootstrap/unverified placeholder. It does not itself perform
    cryptographic SBOM verification; the injected trusted ``PackageVerifier``
    remains the authenticity authority.
    """

    selected = set(placement.component_ids)
    manifests = {component.component_id: component for component in package.components}
    offenders: list[str] = []
    for component_id in sorted(selected):
        component = manifests.get(component_id)
        if component is None:
            # Component/placement consistency is enforced elsewhere; skip here.
            continue
        image = component.image
        if not image.verified:
            continue
        if not _is_real_supply_chain_ref(image.provenance_ref):
            offenders.append(f"{component_id}:provenance_ref={image.provenance_ref!r}")
        if not _is_real_supply_chain_ref(image.sbom_ref):
            offenders.append(f"{component_id}:sbom_ref={image.sbom_ref!r}")
    if offenders:
        raise RuntimePreflightError(
            "verified images must carry real provenance and SBOM references: "
            + ", ".join(offenders)
        )


def require_trusted_package_verifier(
    package: DeceptionPackage,
    verifier: PackageVerifier | None,
) -> None:
    """Require an externally configured trusted package verification hook.

    The `ImageManifest.verified` field is evidence state, not cryptographic
    proof by itself. Until a signing implementation is selected, live runtime
    must have a verifier supplied by the operator/integration boundary.
    """

    if verifier is None:
        raise RuntimePreflightError("trusted package verifier is not configured")
    try:
        verified = verifier(package)
    except Exception as exc:
        raise RuntimePreflightError(f"trusted package verifier failed: {exc}") from exc
    if verified is not True:
        raise RuntimePreflightError("trusted package verifier rejected package")


def require_compose_package_binding(
    compose_file: str | Path,
    package: DeceptionPackage,
    placement: PlacementPlan,
) -> None:
    """Require exact service/image binding between placement and Compose.

    Every Compose service must correspond to a selected package component and
    use exactly the package-declared OCI image reference. Extra services,
    omitted selected services, local builds, and image substitution fail
    closed.
    """

    document = yaml.safe_load(Path(compose_file).read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise RuntimePreflightError("compose root must be a mapping")
    services = document.get("services")
    if not isinstance(services, dict):
        raise RuntimePreflightError("compose services must be a mapping")

    selected = set(placement.component_ids)
    actual = set(services)
    if actual != selected:
        missing = sorted(selected - actual)
        extra = sorted(actual - selected)
        raise RuntimePreflightError(
            f"compose/package component mismatch: missing={missing}, extra={extra}"
        )

    manifests = {component.component_id: component for component in package.components}
    for component_id in sorted(selected):
        component = manifests.get(component_id)
        if component is None:
            raise RuntimePreflightError(
                f"placement references unknown package component: {component_id}"
            )
        service = services.get(component_id)
        if not isinstance(service, dict):
            raise RuntimePreflightError(f"compose service is not a mapping: {component_id}")
        if service.get("build") is not None:
            raise RuntimePreflightError(f"local build forbidden for live component: {component_id}")
        actual_image = service.get("image")
        if actual_image != component.image.image:
            raise RuntimePreflightError(
                f"compose image does not match package manifest for {component_id}: "
                f"{actual_image!r} != {component.image.image!r}"
            )
