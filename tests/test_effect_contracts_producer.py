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
    MATERIALIZABLE_EFFECT_CLASSES,
    NOT_CARRIED_INTO_FABRIC,
    EffectProjectionRefused,
    EffectRefRejected,
    accept_defensive_effect_ref,
    observe_effect,
    fabric_lifecycle_state_ref,
    fabric_presentation_id,
    project_presented_terrain,
)
from azazel_deception.runtime.presented_terrain import (
    ProducerRedirectionEvidence,
    PresentedTerrainSnapshotV0,
    build_presented_terrain_snapshot,
)

#: The references AZ-06 actually mints, used unchanged.
#:
#: They were not usable here until `v0.9.0rc3`. Under the previous grammar a
#: typed ref's body could not contain a colon, so `surface:http:8080` was
#: refused by every slot requiring a typed ref and this file had to carry
#: flattened stand-ins (`surface:http-8080`). The pin bump turned the test
#: that recorded that into a failure, which was its whole purpose, and the
#: stand-ins are gone.
CONFORMING_SURFACE = "surface:http:8080"
CONFORMING_ARTIFACT = "artifact:honey:invoice-2026"


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


#: Values AZ-06's own suite mints today, copied literally from the files named,
#: with what the pinned Fabric makes of each.
#:
#: This list used to record that **none** of them was projectable. That was the
#: measurement behind Azazel-Fabric#48, and moving the pin to `v0.9.0rc3` is
#: what turned it from a finding into history.
REFS_AZ06_MINTS_TODAY = (
    ("surface:http:8080", "surface", "tests/test_presented_terrain_evidence.py"),
    ("surface:http:8080", "surface", "tests/test_cross_product_golden_outcome.py"),
    ("artifact:honey:invoice-2026", "artifact", "tests/test_honey_artifacts.py"),
    # Still untyped, and for a different reason: `deception` is not a RefKind.
    # Fabric does not know the kind, rather than the value being punctuated in
    # a way the grammar happened to exclude. That distinction is the point.
    ("deception:surface:http-8080", None, "tests/test_defensive_state_boundary.py"),
)


@pytest.mark.parametrize("value,expected_kind,minted_in", REFS_AZ06_MINTS_TODAY)
def test_the_references_az06_mints_are_what_fabric_says_they_are(
    value, expected_kind, minted_in
):
    """The pin bump's result, pinned in turn.

    A hierarchical reference is now a reference. The one that still is not
    fails for a reason that has nothing to do with punctuation -- Fabric has no
    `deception` kind -- and a test that could not tell those two apart would
    have called the grammar fixed when it was not.
    """

    kind, _ = parse_ref(value)
    assert (kind.value if kind is not None else None) == expected_kind, (
        f"{value!r} (from {minted_in})"
    )


def test_a_hierarchical_surface_reference_now_reaches_the_record():
    """End to end: the value from AZ-06's own fixtures, projected unchanged.

    Nothing rewrote it. `surface:http:8080` goes into the readout and comes out
    of `PresentedTerrainRef` byte-identical, which is the whole reason the
    projector refused to flatten it rather than making it fit.
    """

    projected = _project(
        snapshot_overrides={"active_surface_refs": ("surface:http:8080",)}
    )

    assert projected.ref.active_surface_refs == ("surface:http:8080",)


def test_a_reference_of_a_kind_fabric_does_not_know_is_still_refused():
    """The grammar widened; it did not stop discriminating.

    `deception:surface:http-8080` announces a kind Fabric has no name for, so
    it cannot stand in a slot that requires `surface`. Widening the body must
    not have made every colon-bearing string acceptable anywhere.
    """

    with pytest.raises(EffectProjectionRefused, match="will not rewrite"):
        _project(
            snapshot_overrides={"active_surface_refs": ("deception:surface:http-8080",)}
        )


def test_az06_now_observes_against_an_effect_edge_minted():
    """The successor to a guard that has fired.

    This file used to assert that **no** repository minted an `effect:` id, so
    `EffectObservation` had no possible producer anywhere in the series. That
    was the measurement; Azazel-Edge#419 answered it. A guard whose event has
    happened is replaced by one for the invariant that matters next -- that the
    observation AZ-06 makes really does chain to the effect it names.
    """

    effect = accept_defensive_effect_ref(an_edge_effect())
    observation = observe_effect(
        effect, status="active", observed_at="2026-09-20T12:05:00+00:00"
    )

    assert observation.effect_ref == effect.effect_id
    assert observation.materialization_producer == "azazel-deception"
    assert_effect_chain_consistent(effect, observations=[observation])


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


# --------------------------------------------------------------------------
# AZ-06 as a consumer: what it accepts, and what it refuses on doctrine
# --------------------------------------------------------------------------


def an_edge_effect(**overrides) -> dict:
    """A `DefensiveEffectRef` shaped as Azazel-Edge's exporter emits one."""

    data = {
        "effect_id": "effect:cff74a8556ff401bc72249812018afcc",
        "effect_class": "redirect_to_presented_terrain",
        "producer_product": "azazel-edge",
        "producer_node": "edge-1",
        "trace_id": "trace-1",
        "decision_ref": "decision-1",
        "target_scope_ref": "scope:6617f9307d832d50e04395e5604619cd",
        "policy_ref": "policy:soc-default",
        "created_at": "2026-09-20T12:00:00+00:00",
        "expires_at": "2026-09-20T13:00:00+00:00",
        "authority_class": "producer_decision_ref",
    }
    data.update(overrides)
    return data


def test_an_edge_effect_reference_is_accepted():
    effect = accept_defensive_effect_ref(an_edge_effect())

    assert effect.producer_product == "azazel-edge"
    assert effect.decision_ref == "decision-1"
    assert effect.directive is False


def test_az06_refuses_to_materialize_advice_or_a_shadow_run():
    """Doctrine, not taste.

    Deception materializes an Edge-approved environment. `advisory_inference`
    was advised and `planned_shadow` was considered; materializing either would
    make AZ-06 the step that turns a suggestion into an environment, which is
    exactly the authority it does not hold.
    """

    for authority, extra in (
        ("planned_shadow", {"decision_ref": None}),
        ("advisory_inference", {"decision_ref": None, "advisory_ref": "advisory:a1"}),
        ("stale_or_unknown", {"decision_ref": None}),
    ):
        with pytest.raises(EffectRefRejected, match="Edge-approved"):
            accept_defensive_effect_ref(
                an_edge_effect(authority_class=authority, **extra)
            )


def test_only_redirection_can_become_presented_terrain():
    """There is nothing for AZ-06 to present behind isolation or a notification."""

    for effect_class in ("network_isolation", "rate_limit", "notify_only", "observe_only"):
        with pytest.raises(EffectRefRejected, match="no meaning behind"):
            accept_defensive_effect_ref(an_edge_effect(effect_class=effect_class))

    assert MATERIALIZABLE_EFFECT_CLASSES == {EffectClass.REDIRECT_TO_PRESENTED_TERRAIN}


def test_az06_refuses_an_effect_it_produced_itself():
    """An effect returning to its own producer as an instruction is that
    producer deciding, whatever authority class it carries."""

    with pytest.raises(EffectRefRejected, match="produced itself"):
        accept_defensive_effect_ref(an_edge_effect(producer_product="azazel-deception"))


def test_the_contract_is_fabrics_statement_and_is_not_restated_here():
    """A malformed payload is refused by the model, not by a local check."""

    with pytest.raises(ValidationError):
        accept_defensive_effect_ref(an_edge_effect(effect_id="not-a-typed-ref"))
    with pytest.raises(ValidationError):
        accept_defensive_effect_ref(an_edge_effect(expires_at="2026-09-20T11:00:00+00:00"))
    with pytest.raises(ValidationError):
        accept_defensive_effect_ref(an_edge_effect(directive=True))


def test_a_non_mapping_payload_is_refused_rather_than_duck_typed():
    with pytest.raises(EffectRefRejected):
        accept_defensive_effect_ref("effect:e1")


# --------------------------------------------------------------------------
# AZ-06 as the materializer: the observation it may make
# --------------------------------------------------------------------------


def test_the_observation_takes_its_trace_from_the_effect():
    """A caller-supplied trace could attach an observation to an unrelated
    incident, and the chain check would pass because both halves would agree
    with each other and with nothing else."""

    effect = accept_defensive_effect_ref(an_edge_effect(trace_id="trace-77"))
    observation = observe_effect(
        effect, status="active", observed_at="2026-09-20T12:05:00+00:00"
    )

    assert observation.trace_id == "trace-77"
    import inspect

    assert "trace_id" not in inspect.signature(observe_effect).parameters


@pytest.mark.parametrize(
    "status,expected",
    [
        ("started", "active_materialized"),
        ("active", "active_materialized"),
        ("completed", "observed_fact"),
        ("eligible", "observed_fact"),
    ],
)
def test_the_authority_class_is_derived_from_the_status(status, expected):
    """Fabric requires `active_materialized` for a live status and forbids it
    otherwise, so a caller-supplied class could only agree or be rejected."""

    effect = accept_defensive_effect_ref(an_edge_effect())
    observation = observe_effect(
        effect, status=status, observed_at="2026-09-20T12:05:00+00:00"
    )

    assert observation.authority_class.value == expected


def test_a_terminal_status_must_say_why_it_ended():
    """Fabric's rule: an unexplained termination is indistinguishable from a
    lost observation."""

    effect = accept_defensive_effect_ref(an_edge_effect())

    with pytest.raises(ValidationError):
        observe_effect(effect, status="terminated", observed_at="2026-09-20T12:30:00+00:00")

    assert observe_effect(
        effect,
        status="terminated",
        observed_at="2026-09-20T12:30:00+00:00",
        termination_reason="lease expired",
    )


def test_a_stale_live_observation_cannot_prolong_a_bounded_effect():
    """Fabric's rule, applied by calling it rather than re-deciding it.

    A replayed `active` arriving after the effect expired is how a time-boxed
    environment silently becomes an unbounded one.
    """

    effect = accept_defensive_effect_ref(an_edge_effect())

    with pytest.raises(ValueError, match="cannot prolong"):
        observe_effect(effect, status="active", observed_at="2026-09-20T14:00:00+00:00")

    # ...while reporting that it *ended* after expiry is exactly what should
    # still be possible.
    assert observe_effect(
        effect,
        status="completed",
        observed_at="2026-09-20T14:00:00+00:00",
    )


def test_two_observations_of_one_effect_are_two_records():
    """An id that collapsed them would make the later one look like a
    correction of the earlier."""

    effect = accept_defensive_effect_ref(an_edge_effect())
    first = observe_effect(effect, status="started", observed_at="2026-09-20T12:01:00+00:00")
    second = observe_effect(effect, status="active", observed_at="2026-09-20T12:05:00+00:00")

    assert first.observation_id != second.observation_id
    assert first.effect_ref == second.effect_ref


def test_replaying_one_observation_gives_the_same_record():
    effect = accept_defensive_effect_ref(an_edge_effect())
    args = {"status": "active", "observed_at": "2026-09-20T12:05:00+00:00"}

    assert (
        observe_effect(effect, **args).observation_id
        == observe_effect(effect, **args).observation_id
    )


def test_an_observation_of_a_different_effect_does_not_chain():
    """The guard against a cross-trace identifier collision producing a chain
    that validates field-by-field while describing two unrelated events."""

    effect = accept_defensive_effect_ref(an_edge_effect())
    other = accept_defensive_effect_ref(
        an_edge_effect(effect_id="effect:0000000000000000000000000000000a")
    )
    observation = observe_effect(
        other, status="active", observed_at="2026-09-20T12:05:00+00:00"
    )

    with pytest.raises(ValueError, match="different effect"):
        assert_effect_chain_consistent(effect, observations=[observation])
