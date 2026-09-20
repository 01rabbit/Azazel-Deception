"""AZ-06 as a producer for Fabric's `effect_contracts` family (Fabric#15).

Fabric#15 was closed as completed with an acceptance criterion that no one had
exercised: "Edge/Gadget/AZ-06 can describe an **actual** bounded effect/outcome
using one compatible shared envelope/reference family". This file is that
exercise, run against AZ-06's real presented-terrain record rather than against
a fixture written to fit.

Two kinds of test live here and they are doing different jobs:

*What the projection does.* The ordinary producer tests -- a snapshot goes in,
a `PresentedTerrainRef` comes out, and the refusals fire where AZ-06 holds no
fact the contract requires.

*What the contract currently cannot express.* Measurements, pinned so they
turn red when the situation changes rather than staying true silently. They are
the result of the validation, not scaffolding around it.
"""

from __future__ import annotations

import pytest
from azazel_fabric.effect_contracts import (
    AuthorityClass,
    DefensiveEffectRef,
    EffectClass,
    PresentedTerrainRef,
    assert_effect_chain_consistent,
    parse_ref,
)
from pydantic import ValidationError

from azazel_deception.runtime.effect_projection import (
    NOT_CARRIED_INTO_FABRIC,
    EffectProjectionRefused,
    fabric_lifecycle_state_ref,
    fabric_presentation_id,
    project_presented_terrain,
)
from azazel_deception.runtime.presented_terrain import (
    ProducerRedirectionEvidence,
    PresentedTerrainSnapshotV0,
    build_presented_terrain_snapshot,
)

#: References that satisfy the grammar of the *pinned* Fabric. See
#: `test_the_references_az06_mints_today_are_not_projectable` for the ones it
#: actually mints, and why that is the finding rather than a fixture problem.
CONFORMING_SURFACE = "surface:http-8080"
CONFORMING_ARTIFACT = "artifact:honey-invoice-2026"


def _producer(**overrides) -> ProducerRedirectionEvidence:
    data = {
        "producer_product": "azazel-edge",
        "producer_node": "edge-1",
        "trace_id": "trace-1",
        "decision_ref": "decision-1",
        "execution_ref": "execution-1",
        "mechanism_observation_ref": "mechanism-1",
        "evidence_refs": ["edge-nft-1"],
    }
    data.update(overrides)
    return ProducerRedirectionEvidence(**data)


def _snapshot(**overrides) -> PresentedTerrainSnapshotV0:
    data = {
        "environment_id": "env-1",
        "producer": _producer(),
        "runtime_state": {
            "environment_id": "env-1",
            "state": "active",
            "package_id": "municipal-linux-v1",
            "package_digest": "sha256:abc123",
            "node_id": "deception-node-1",
            "activated_at": "2026-08-26T00:00:00+00:00",
        },
        "expected_package_id": "municipal-linux-v1",
        "expected_package_digest": "sha256:abc123",
        "package_version": "1.0.0",
        "observed_at": "2026-08-26T00:00:02+00:00",
        "active_surface_refs": (CONFORMING_SURFACE,),
        "isolation_assertion_refs": ("isolation-net-none",),
        "runtime_verified_active": True,
        "evidence_refs": ("runtime-inspect-1",),
        "expires_at": "2026-08-26T01:00:00+00:00",
    }
    data.update(overrides)
    return build_presented_terrain_snapshot(**data)


def _project(**overrides):
    return project_presented_terrain(
        _snapshot(**overrides.pop("snapshot_overrides", {})),
        presentation_version=overrides.pop("presentation_version", 0),
        **overrides,
    )


# --------------------------------------------------------------------------
# The producer
# --------------------------------------------------------------------------


def test_a_live_presentation_projects_into_a_fabric_record():
    projected = _project()

    assert isinstance(projected.ref, PresentedTerrainRef)
    assert projected.ref.producer_product == "azazel-deception"
    assert projected.ref.authority_class is AuthorityClass.ACTIVE_MATERIALIZED
    assert projected.ref.activation_decision_ref == "decision-1"
    assert projected.ref.active_surface_refs == (CONFORMING_SURFACE,)
    assert projected.ref.describes == "defender_presented_surface"
    assert projected.ref.directive is False


def test_the_projection_never_writes_back_into_the_snapshot():
    """A rendering that mutates its subject is not a rendering.

    AZ-06's runtime is the only local lifecycle authority; a projector that
    could alter a snapshot would be a second one.
    """

    snapshot = _snapshot()
    before = snapshot.model_dump_json()
    project_presented_terrain(snapshot, presentation_version=0)
    assert snapshot.model_dump_json() == before


def test_the_fabric_presentation_id_carries_the_local_body_unchanged():
    snapshot = _snapshot()
    projected = project_presented_terrain(snapshot, presentation_version=0)

    kind, body = parse_ref(projected.ref.presentation_id)
    assert kind is not None and kind.value == "presentation"
    assert snapshot.presentation_id == f"presentation-{body}", (
        "the two ids must name the same presentation, or correlating AZ-06's "
        "own record with the one it published becomes guesswork"
    )


def test_a_reference_is_not_minted_from_a_value_of_unknown_shape():
    """Prefixing an arbitrary string produces a valid reference to nothing."""

    for hostile in ("presentation-NOTHEX", "env-1", "presentation:already-typed", ""):
        with pytest.raises(EffectProjectionRefused):
            fabric_presentation_id(hostile)


def test_the_lifecycle_reference_moves_when_the_lifecycle_state_does():
    """A state reference that ignores the state stays plausible after the fact."""

    local = "presentation-" + "a" * 24
    active = fabric_lifecycle_state_ref(local, "active")
    terminated = fabric_lifecycle_state_ref(local, "terminated")

    assert active != terminated
    assert parse_ref(active)[0].value == "lifecycle"
    assert parse_ref(terminated)[0].value == "lifecycle"


@pytest.mark.parametrize(
    "lifecycle_state,expected",
    [
        ("active", AuthorityClass.ACTIVE_MATERIALIZED),
        ("terminated", AuthorityClass.OBSERVED_FACT),
        ("failed", AuthorityClass.OBSERVED_FACT),
        ("stale", AuthorityClass.STALE_OR_UNKNOWN),
    ],
)
def test_each_lifecycle_state_claims_the_authority_it_can_support(
    lifecycle_state, expected
):
    """`stale` is the one worth checking: it claims least, not `observed_fact`.

    A stale snapshot is one whose runtime AZ-06 could not independently read
    back. Calling that an observed fact would assert precisely the thing that
    could not be observed.
    """

    from azazel_deception.runtime.effect_projection import _AUTHORITY_BY_LIFECYCLE

    assert _AUTHORITY_BY_LIFECYCLE[lifecycle_state] is expected


def test_an_unverified_runtime_projects_as_stale_not_as_live():
    """End to end, through the local rule that produces `stale` in the first place."""

    projected = _project(
        snapshot_overrides={
            "runtime_verified_active": False,
            "active_surface_refs": (),
        }
    )
    assert projected.ref.authority_class is AuthorityClass.STALE_OR_UNKNOWN


# --------------------------------------------------------------------------
# Refusals: a fact AZ-06 does not hold is never a default
# --------------------------------------------------------------------------


def test_a_presentation_with_no_declared_bound_is_refused_not_bounded_here():
    """The refusal that matters most.

    Fabric requires `expires_at`; AZ-06 commonly has none. Any value invented
    here would report that AZ-06 time-boxed a presentation it did not, and the
    record would validate.
    """

    with pytest.raises(EffectProjectionRefused, match="time-boxed"):
        _project(snapshot_overrides={"expires_at": None})


def test_a_caller_supplied_bound_is_accepted_because_it_can_come_from_a_fact():
    projected = _project(
        snapshot_overrides={"expires_at": None},
        expires_at="2026-08-26T02:00:00+00:00",
    )
    assert projected.ref.expires_at == "2026-08-26T02:00:00+00:00"


def test_more_isolation_assertions_than_fabric_can_hold_is_refused():
    """Fabric's slot is singular; AZ-06's is not. Dropping the rest is silent."""

    with pytest.raises(EffectProjectionRefused, match="narrow the evidence"):
        _project(
            snapshot_overrides={
                "isolation_assertion_refs": ("isolation-a", "isolation-b"),
            }
        )


def test_a_presentation_that_never_started_is_refused():
    with pytest.raises(EffectProjectionRefused, match="no start instant"):
        _project(
            snapshot_overrides={
                "runtime_state": {
                    "environment_id": "env-1",
                    "state": "failed",
                    "package_id": "municipal-linux-v1",
                    "package_digest": "sha256:abc123",
                    "node_id": "deception-node-1",
                },
                "active_surface_refs": (),
                "runtime_verified_active": False,
            }
        )


def test_a_non_snapshot_is_refused_rather_than_duck_typed():
    with pytest.raises(EffectProjectionRefused):
        project_presented_terrain({"presentation_id": "x"}, presentation_version=0)


# --------------------------------------------------------------------------
# What the contract cannot express: measurements, pinned
# --------------------------------------------------------------------------


#: Values AZ-06's own suite mints today, copied literally from the files named.
#: A derived list would stop saying anything the moment a producer changed.
REFS_AZ06_MINTS_TODAY = (
    ("surface:http:8080", "tests/test_presented_terrain_evidence.py"),
    ("surface:http:8080", "tests/test_cross_product_golden_outcome.py"),
    ("deception:surface:http-8080", "tests/test_defensive_state_boundary.py"),
)


@pytest.mark.parametrize("value,minted_in", REFS_AZ06_MINTS_TODAY)
def test_the_references_az06_mints_today_are_not_projectable(value, minted_in):
    """The measurement that produced Azazel-Fabric#48.

    Under the pinned Fabric the typed-ref body may not contain a colon, so
    every hierarchical reference in this repository is refused by every slot
    that requires a typed ref -- which is why `effect_contracts` shipped with
    no possible producer anywhere in the series.

    Rewriting them was considered and refused: `surface:http:8080` rewritten to
    `surface:http-8080` is a well-formed reference to a surface that does not
    exist. The projector says so instead.

    **This test flips when the pin moves.** Azazel-Fabric#48 widens the body to
    admit further colons; at that pin these values become projectable and this
    test fails, which is the signal to move the repository's references back to
    their natural form rather than leaving the workaround in place.
    """

    assert parse_ref(value)[0] is None, f"{value!r} (from {minted_in})"

    with pytest.raises(EffectProjectionRefused, match="will not rewrite"):
        _project(snapshot_overrides={"active_surface_refs": (value,)})


def test_nothing_in_the_series_mints_an_effect_id_so_observations_are_blocked():
    """Why this module produces no `EffectObservation`.

    `EffectObservation.effect_ref` and `OutcomeObservationEnvelope.effect_ref`
    are keyed on an `effect:`-typed id minted by whoever constructed the
    effect. AZ-06 receives an `EnvironmentActivationDecision`, which carries no
    such id, and no Azazel repository mints one. AZ-06 is the materializer, so
    the observation is its record to make -- it simply has nothing to make it
    against.

    Pinned as a fact rather than left as an absence: if AZ-06 ever receives an
    effect id, this is where the blocker is recorded as lifted.
    """

    snapshot = _snapshot()
    payload = snapshot.model_dump(mode="json")
    typed = {
        key: value
        for key, value in payload.items()
        if isinstance(value, str) and parse_ref(value)[0] is not None
    }
    assert not any(
        parse_ref(value)[0].value == "effect" for value in typed.values()
    ), f"an effect reference appeared in AZ-06's record: {typed}"


def test_a_shadow_run_presentation_cannot_be_chained_to_its_effect():
    """Measured: `assert_effect_chain_consistent` admits one authority class.

    A terrain is compared to `effect_ref.decision_ref`, which is `None` for
    every class except `producer_decision_ref`, while the terrain's own
    `activation_decision_ref` is required and non-empty. So the comparison can
    never hold for a `planned_shadow` effect -- and AZ-06's default mode is
    exactly that (`TransitionExecutor` reports `shadow_simulated` unless
    `live_enabled`). The error even says the terrain "was activated by a
    different decision", when in fact the effect named none.
    """

    terrain = _project().ref
    base = dict(
        effect_id="effect:e1",
        effect_class=EffectClass.REDIRECT_TO_PRESENTED_TERRAIN,
        producer_product="azazel-edge",
        producer_node="edge-1",
        trace_id="trace-1",
        target_scope_ref="scope:s1",
        policy_ref="policy-1",
        created_at="2026-08-26T00:00:00+00:00",
        expires_at="2026-08-26T01:00:00+00:00",
    )

    decided = DefensiveEffectRef(
        **base,
        authority_class=AuthorityClass.PRODUCER_DECISION_REF,
        decision_ref="decision-1",
    )
    assert_effect_chain_consistent(decided, terrain=terrain)

    shadow = DefensiveEffectRef(**base, authority_class=AuthorityClass.PLANNED_SHADOW)
    with pytest.raises(ValueError, match="a different decision"):
        assert_effect_chain_consistent(shadow, terrain=terrain)


# --------------------------------------------------------------------------
# The loss list
# --------------------------------------------------------------------------


#: Local field -> the `PresentedTerrainRef` slot it reaches.
MAPPED_INTO_FABRIC = {
    "schema_version": "schema_version",
    "presentation_id": "presentation_id",
    "producer_product": "producer_product",
    "producer_decision_ref": "activation_decision_ref",
    "lifecycle_state": "lifecycle_state_ref",
    "active_surface_refs": "active_surface_refs",
    "synthetic_artifact_refs": "synthetic_artifact_refs",
    "isolation_assertion_refs": "isolation_assertion_ref",
    "started_at": "created_at",
    "expires_at": "expires_at",
    "evidence_refs": "evidence_refs",
    "authority_class": "authority_class",
}


def test_every_local_field_is_either_mapped_or_declared_unmapped():
    """No third category. An unclassified field is a field dropped by accident."""

    local = set(PresentedTerrainSnapshotV0.model_fields)
    classified = set(MAPPED_INTO_FABRIC) | NOT_CARRIED_INTO_FABRIC

    assert local == classified, (
        "unclassified local fields: "
        f"{sorted(local - classified)}; stale entries: {sorted(classified - local)}"
    )


def test_nothing_declared_unmapped_has_quietly_acquired_a_fabric_slot():
    """The direction a pin bump would change.

    If Fabric adds a `trace_id` or a `synthetic_credential_refs` to this
    record, the loss list must stop claiming there is nowhere to put it.
    """

    fabric = set(PresentedTerrainRef.model_fields)
    collisions = NOT_CARRIED_INTO_FABRIC & fabric

    assert collisions == set(), (
        f"{sorted(collisions)} now exist(s) on PresentedTerrainRef; carry the "
        "value instead of declaring it unmapped"
    )


def test_every_mapped_target_is_a_field_fabric_actually_has():
    fabric = set(PresentedTerrainRef.model_fields)
    missing = sorted(set(MAPPED_INTO_FABRIC.values()) - fabric)
    assert missing == [], f"mapped onto slots Fabric does not have: {missing}"


def test_the_loss_list_travels_with_every_projection():
    """Reported, not logged.

    A lossy projection that says nothing is how a consumer comes to read the
    Fabric record as the whole of what AZ-06 observed.
    """

    assert _project().not_carried == NOT_CARRIED_INTO_FABRIC
    assert "trace_id" in NOT_CARRIED_INTO_FABRIC
    assert "synthetic_credential_refs" in NOT_CARRIED_INTO_FABRIC


def test_the_projected_record_carries_no_directive_or_authority_field():
    """Fabric enforces this; AZ-06 checks that what it publishes passes it."""

    payload = _project().ref.model_dump(mode="json")
    assert payload["directive"] is False
    for banned in ("authorize", "enforce", "must_apply", "adversary_belief"):
        assert banned not in payload

    with pytest.raises(ValidationError):
        PresentedTerrainRef(**{**payload, "directive": True})
