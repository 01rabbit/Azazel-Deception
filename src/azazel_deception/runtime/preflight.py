"""Live-runtime preflight checks that bind local assets to canonical packages."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import yaml

from azazel_fabric.deception_contracts import DeceptionPackage, PlacementPlan


class RuntimePreflightError(ValueError):
    pass


PackageVerifier = Callable[[DeceptionPackage], bool]


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
