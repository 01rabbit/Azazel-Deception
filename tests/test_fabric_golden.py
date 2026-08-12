from azazel_deception.package import parse_package
from azazel_deception.planner import build_placement_plan
from azazel_fabric.testing import (
    make_deception_host_capabilities,
    make_deception_package,
)


def test_fabric_golden_package_is_accepted_as_canonical():
    fixture = make_deception_package(verified=True)
    parsed = parse_package(fixture.model_dump(mode="json"))
    assert parsed.package_id == "municipal-linux-v1"
    assert parsed.package_digest == fixture.package_digest
    assert parsed.schema_version == "deception-package/v0.1"


def test_same_fabric_golden_package_plans_on_arm64_and_amd64():
    package = make_deception_package(verified=True).model_dump(mode="json")
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
