"""Cross-repository contract tests against the shared Fabric golden factory.

The Fabric ``make_deception_package`` factory ships a *placeholder*
``package_digest`` (``sha256:dddd...``): it exercises the model shape, not the
integrity pipeline. AZ-06 therefore seals the fixture through its canonical
normalize-then-hash operation before consuming it, exactly as an authored
package would be sealed. This documents that the Fabric contract owns the
package *shape* while AZ-06 owns the deterministic *content digest*.
"""

from azazel_deception.package import (
    calculate_package_digest,
    parse_package,
    seal_package_digest,
)
from azazel_deception.planner import build_placement_plan
from azazel_fabric.testing import (
    make_deception_host_capabilities,
    make_deception_package,
)

# The Fabric factory intentionally ships an unsealed placeholder digest.
PLACEHOLDER_DIGEST = "sha256:" + "d" * 64


def test_fabric_golden_package_ships_unsealed_placeholder_digest():
    # Guards the assumption behind the seal step below: if Fabric ever starts
    # shipping a real digest, this fails loudly instead of hiding drift.
    fixture = make_deception_package(verified=True)
    assert fixture.package_digest == PLACEHOLDER_DIGEST


def test_fabric_golden_package_can_be_canonically_sealed_and_consumed():
    fixture = make_deception_package(verified=True).model_dump(mode="json")
    sealed = seal_package_digest(fixture)

    assert sealed["package_digest"] == calculate_package_digest(fixture)
    assert sealed["package_digest"] != PLACEHOLDER_DIGEST

    parsed = parse_package(sealed)
    assert parsed.package_id == "municipal-linux-v1"
    assert parsed.package_digest == sealed["package_digest"]
    assert parsed.schema_version == "deception-package/v0.1"


def test_same_fabric_golden_package_plans_on_arm64_and_amd64():
    package = seal_package_digest(make_deception_package(verified=True).model_dump(mode="json"))
    identities = set()
    for architecture in ("arm64", "amd64"):
        host = make_deception_host_capabilities(architecture=architecture)
        plan = build_placement_plan(
            package,
            host.model_dump(mode="json"),
            requested_tier="lite",
            edge_decision_id="edge-shadow-fixture",
        )
        identities.add((plan["package_id"], plan["package_digest"]))
        assert plan["architecture"] == architecture
        assert plan["authority"] == "descriptive_only"
        assert plan["edge_decision_id"] == "edge-shadow-fixture"
        assert plan["component_ids"] == ["intranet-web"]
    assert len(identities) == 1
