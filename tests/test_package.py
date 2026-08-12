from pathlib import Path

from azazel_deception.package import load_package, validate_package

PACKAGE = Path("examples/packages/municipal-linux-v1/package.yaml")


def test_reference_package_is_valid():
    assert validate_package(load_package(PACKAGE)) == []


def test_unrestricted_egress_fails_closed():
    package = load_package(PACKAGE)
    package["safety"]["outbound_allowed"] = True
    assert any("outbound_allowed" in error for error in validate_package(package))


def test_privileged_component_fails_closed():
    package = load_package(PACKAGE)
    package["components"][0]["privileged"] = True
    assert any("privileged" in error for error in validate_package(package))
