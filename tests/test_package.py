from pathlib import Path

from azazel_deception.package import (
    calculate_package_digest,
    load_package,
    validate_package,
)

PACKAGE = Path("examples/packages/municipal-linux-v1/package.yaml")


def test_reference_package_is_valid():
    package = load_package(PACKAGE)
    assert validate_package(package) == []
    assert calculate_package_digest(package) == package["package_digest"]


def test_unrestricted_egress_fails_closed():
    package = load_package(PACKAGE)
    package["safety"]["outbound_allowed"] = True
    assert any("outbound_allowed" in error for error in validate_package(package))


def test_privileged_component_fails_closed():
    package = load_package(PACKAGE)
    package["components"][0]["privileged"] = True
    assert any("privileged" in error for error in validate_package(package))


def test_semantic_mutation_without_redigest_fails_closed():
    package = load_package(PACKAGE)
    package["narrative"]["purpose"] = "tampered purpose"
    errors = validate_package(package)
    assert any("package_digest mismatch" in error for error in errors)


def test_detached_signature_locator_can_change_without_content_digest_change():
    package = load_package(PACKAGE)
    package["signature_ref"] = "github-attestation:replacement-detached-reference"
    assert calculate_package_digest(package) == package["package_digest"]
