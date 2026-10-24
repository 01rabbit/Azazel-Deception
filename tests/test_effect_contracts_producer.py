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
    MAPPED_INTO_FABRIC,
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


def _shadow_effect(**overrides) -> DefensiveEffectRef:
    """An Edge effect with no decision behind it: AZ-06's default mode."""

    data = dict(
        effect_id="effect:e1",
        effect_class=EffectClass.REDIRECT_TO_PRESENTED_TERRAIN,
        producer_product="azazel-edge",
        producer_node="edge-1",
        trace_id="trace-1",
        target_scope_ref="scope:s1",
        policy_ref="policy-1",
        created_at="2026-08-26T00:00:00+00:00",
        expires_at="2026-08-26T01:00:00+00:00",
        authority_class=AuthorityClass.PLANNED_SHADOW,
    )
    data.update(overrides)
    return DefensiveEffectRef(**data)


def _decided_effect(**overrides) -> DefensiveEffectRef:
    return _shadow_effect(
        **{
            "authority_class": AuthorityClass.PRODUCER_DECISION_REF,
            "decision_ref": "decision-1",
            **overrides,
        }
    )


#: A presentation AZ-06 rehearsed rather than verified live. `stale` is what
#: the local rule produces for it, and a shadow-bound terrain may not claim
#: more.
_SHADOW_SNAPSHOT = {"runtime_verified_active": False, "active_surface_refs": ()}


def test_a_shadow_run_presentation_now_chains_to_its_effect():
    """The successor to a measurement that has done its job.

    This test used to record that a `planned_shadow` terrain could **not** be
    chained to its effect: `assert_effect_chain_consistent` compared the
    terrain's required `activation_decision_ref` to the effect's `None`, so
    the comparison could never hold -- for exactly the mode AZ-06 runs in by
    default. `v0.9.0rc5` (Fabric#51) added a binding of its own, by effect and
    trace, and the gap it recorded is closed. What it now pins is that the
    binding is real: the decision is absent rather than invented, and the
    terrain claims a shadow run rather than a materialization.
    """

    shadow = _shadow_effect()
    terrain = _project(
        snapshot_overrides=_SHADOW_SNAPSHOT, source_effect=shadow
    ).ref

    assert terrain.activation_decision_ref is None
    assert terrain.source_effect_ref == shadow.effect_id
    assert terrain.trace_id == shadow.trace_id
    assert terrain.authority_class is AuthorityClass.PLANNED_SHADOW
    assert_effect_chain_consistent(shadow, terrain=terrain)


def test_a_decided_effect_still_chains_through_its_decision():
    decided = _decided_effect()

    plain = _project().ref
    assert_effect_chain_consistent(decided, terrain=plain)

    bound = _project(source_effect=decided).ref
    assert bound.activation_decision_ref == "decision-1"
    assert bound.source_effect_ref == decided.effect_id
    assert bound.authority_class is AuthorityClass.ACTIVE_MATERIALIZED
    assert_effect_chain_consistent(decided, terrain=bound)


def test_a_decision_terrain_does_not_chain_to_a_shadow_effect():
    """The terrain names a decision the shadow effect never made."""

    terrain = _project().ref
    with pytest.raises(ValueError, match="effect has none"):
        assert_effect_chain_consistent(_shadow_effect(), terrain=terrain)


def test_a_shadow_terrain_does_not_chain_to_a_different_effect():
    terrain = _project(
        snapshot_overrides=_SHADOW_SNAPSHOT, source_effect=_shadow_effect()
    ).ref
    other = _shadow_effect(effect_id="effect:e2")

    with pytest.raises(ValueError, match="different effect"):
        assert_effect_chain_consistent(other, terrain=terrain)


def test_a_terrain_does_not_chain_to_an_effect_of_another_trace():
    """Checked in both bindings: the trace now travels with every terrain."""

    shadow_terrain = _project(
        snapshot_overrides=_SHADOW_SNAPSHOT, source_effect=_shadow_effect()
    ).ref
    with pytest.raises(ValueError, match="different trace"):
        assert_effect_chain_consistent(
            _shadow_effect(trace_id="trace-2"), terrain=shadow_terrain
        )

    decided_terrain = _project().ref
    with pytest.raises(ValueError, match="different trace"):
        assert_effect_chain_consistent(
            _decided_effect(trace_id="trace-2"), terrain=decided_terrain
        )


def test_the_projector_refuses_to_bind_an_effect_of_another_trace():
    """Refused before a record exists, not left to a consumer's chain check."""

    with pytest.raises(EffectRefRejected, match="different trace"):
        _project(
            snapshot_overrides=_SHADOW_SNAPSHOT,
            source_effect=_shadow_effect(trace_id="trace-2"),
        )
    with pytest.raises(EffectRefRejected, match="different trace"):
        _project(source_effect=_decided_effect(trace_id="trace-2"))


def test_the_projector_refuses_a_decision_that_is_not_the_effects():
    with pytest.raises(EffectRefRejected, match="different decision"):
        _project(source_effect=_decided_effect(decision_ref="decision-9"))


def test_a_shadow_effect_cannot_be_bound_to_a_live_presentation():
    """A live terrain for an effect nobody decided is AZ-06 materializing a
    shadow run -- what `accept_defensive_effect_ref` declines. Binding must
    not become the side door."""

    with pytest.raises(EffectRefRejected, match="nobody approved"):
        _project(source_effect=_shadow_effect())


def test_a_failed_run_cannot_be_recorded_as_a_shadow_run():
    """`failed` says a run was attempted. Binding it to a shadow effect would
    turn a failed live attempt into a rehearsal."""

    failed = _snapshot(
        runtime_state={
            "environment_id": "env-1",
            "state": "failed",
            "package_id": "municipal-linux-v1",
            "package_digest": "sha256:abc123",
            "node_id": "deception-node-1",
            "activated_at": "2026-08-26T00:00:00+00:00",
        },
        active_surface_refs=(),
    )
    assert failed.lifecycle_state == "failed"

    with pytest.raises(EffectRefRejected, match="only a 'stale' presentation"):
        project_presented_terrain(
            failed, presentation_version=0, source_effect=_shadow_effect()
        )


def test_a_stale_snapshot_with_active_surfaces_cannot_be_a_shadow_run():
    """The builder never produces this, but the snapshot model accepts it.

    So it is reachable, and a `planned_shadow` terrain presenting live surfaces
    would be a materialization under a shadow label.
    """

    stale = _snapshot(**_SHADOW_SNAPSHOT)
    with_surfaces = PresentedTerrainSnapshotV0(
        **{**stale.model_dump(), "active_surface_refs": (CONFORMING_SURFACE,)}
    )
    assert with_surfaces.lifecycle_state == "stale"

    with pytest.raises(EffectRefRejected, match="carries active surfaces"):
        project_presented_terrain(
            with_surfaces, presentation_version=0, source_effect=_shadow_effect()
        )


def test_only_a_shadow_run_binds_without_a_decision():
    for authority, extra in (
        (AuthorityClass.STALE_OR_UNKNOWN, {}),
        (AuthorityClass.ADVISORY_INFERENCE, {"advisory_ref": "advisory:a1"}),
    ):
        effect = _shadow_effect(authority_class=authority, **extra)
        with pytest.raises(EffectRefRejected, match="only to a shadow run"):
            _project(snapshot_overrides=_SHADOW_SNAPSHOT, source_effect=effect)


def test_binding_refuses_what_accepting_refuses():
    with pytest.raises(EffectRefRejected, match="no meaning behind"):
        _project(
            source_effect=_decided_effect(effect_class=EffectClass.NETWORK_ISOLATION)
        )
    with pytest.raises(EffectRefRejected, match="produced itself"):
        _project(source_effect=_decided_effect(producer_product="azazel-deception"))
    with pytest.raises(EffectProjectionRefused, match="DefensiveEffectRef"):
        _project(source_effect={"effect_id": "effect:e1", "trace_id": "trace-1"})


# --------------------------------------------------------------------------
# trace_id, synthetic identities and credentials (Fabric#51, `v0.9.0rc5`)
# --------------------------------------------------------------------------


def test_the_trace_reaches_the_record():
    assert _project().ref.trace_id == "trace-1"


def test_typed_identity_and_credential_refs_reach_the_record_unchanged():
    projected = _project(
        snapshot_overrides={
            "synthetic_identity_refs": ("identity:finance:clerk-1",),
            "synthetic_credential_refs": ("credential:smb:clerk-1",),
        }
    )

    assert projected.ref.synthetic_identity_refs == ("identity:finance:clerk-1",)
    assert projected.ref.synthetic_credential_refs == ("credential:smb:clerk-1",)


def test_an_untyped_identity_is_refused_not_prefixed():
    """`finance-clerk` given an `identity:` prefix is a reference to an
    identity record nobody wrote. The refusal says which value and why."""

    with pytest.raises(EffectProjectionRefused, match="'identity' reference") as exc:
        _project(snapshot_overrides={"synthetic_identity_refs": ("finance-clerk",)})
    assert "finance-clerk" in str(exc.value)
    assert "will not rewrite" in str(exc.value)


def test_a_credential_of_a_kind_fabric_does_not_know_is_refused():
    """AZ-06's own rule asks for a `credential:` prefix; Fabric's asks for the
    kind. A prefix-shaped value the grammar does not parse fails the second."""

    with pytest.raises(EffectProjectionRefused, match="'credential' reference"):
        _project(snapshot_overrides={"synthetic_credential_refs": ("credential:",)})


@pytest.mark.parametrize(
    "material",
    [
        "credential:-----BEGIN-OPENSSH-PRIVATE-KEY-----",
        "credential:ssh-ed25519:AAAAC3NzaC1lZDI1NTE5",
        "credential:ssh-rsa:AAAAB3NzaC1yc2E",
    ],
)
def test_credential_material_never_reaches_the_contract(material):
    """AZ-06's refusal, ahead of Fabric's.

    Each of these passes the local snapshot rule (no whitespace, no `=`) and
    the reference grammar. What stops it is recognizable secret material, and
    the projector stops it before any Fabric record is constructed.
    """

    snapshot = _snapshot(synthetic_credential_refs=(material,))

    with pytest.raises(EffectProjectionRefused, match="secret material"):
        project_presented_terrain(snapshot, presentation_version=0)

    # Fabric would refuse it too; the two checks are independent.
    payload = _project().ref.model_dump(mode="python")
    with pytest.raises(ValidationError, match="secret material"):
        PresentedTerrainRef(**{**payload, "synthetic_credential_refs": (material,)})


#: Every reference `PresentedTerrainRef` receives from the projector, by where
#: it comes from: the snapshot, the caller, or the effect a terrain is bound to.
_NEWLINE_CASES = [
    ("snapshot", "synthetic_credential_refs", ("credential:smb-1\n",)),
    ("snapshot", "synthetic_identity_refs", ("identity:clerk-1\n",)),
    ("snapshot", "synthetic_artifact_refs", ("artifact:memo-1\n",)),
    ("snapshot", "active_surface_refs", ("surface:http:8080\n",)),
    ("snapshot", "trace_id", "trace-1\n"),
    ("snapshot", "producer_decision_ref", "decision-1\n"),
    ("snapshot", "evidence_refs", ("runtime-inspect-1\n",)),
    ("snapshot", "isolation_assertion_refs", ("isolation-net-none\n",)),
    ("caller", "isolation_result_ref", "evidence:isolation-result-1\n"),
    ("effect", "effect_id", "effect:e1\n"),
    ("effect", "decision_ref", "decision-1\n"),
    ("effect", "trace_id", "trace-1\n"),
]


@pytest.mark.parametrize("source,field,value", _NEWLINE_CASES)
def test_a_trailing_newline_reference_is_never_emitted(source, field, value):
    """Azazel-Fabric#65: the pinned grammar accepts `kind:body\\n`.

    `OPAQUE_REF_PATTERN` ends in `$` and is applied with `.match`, and `$`
    matches before one trailing newline. AZ-06 does not rely on that. Where a
    local model already refuses the value, the record is copied without
    validation to reach the projector with it anyway: the projector's own
    refusal is what this checks, independent of every layer upstream.
    """

    kind, _ = parse_ref("credential:smb-1\n")
    assert kind is not None, (
        "Fabric#65 is fixed in the pinned release: keep the refusal below, "
        "drop this precondition and the note that explains it"
    )

    snapshot = _snapshot()
    kwargs = {}
    if source == "snapshot":
        snapshot = snapshot.model_copy(update={field: value})
    elif source == "caller":
        kwargs[field] = value
    else:
        kwargs["source_effect"] = _decided_effect().model_copy(update={field: value})

    with pytest.raises(EffectProjectionRefused, match="whitespace or a control"):
        project_presented_terrain(snapshot, presentation_version=0, **kwargs)


@pytest.mark.parametrize(
    "field", ["trace_id", "decision_ref", "execution_ref", "mechanism_observation_ref"]
)
def test_a_producer_reference_with_a_newline_is_refused_where_it_enters(field):
    """Length was the only check, so `decision-1\\n` from a producer went through
    the ordinary builder and out as the terrain's activation decision."""

    with pytest.raises(ValidationError, match="whitespace or control"):
        _producer(**{field: "ref-1\n"})
    with pytest.raises(ValidationError, match="whitespace or control"):
        _producer(evidence_refs=["edge-nft-1\n"])


def test_a_snapshot_reference_with_a_newline_is_refused_where_it_enters():
    payload = _snapshot().model_dump()
    for field in ("trace_id", "producer_decision_ref", "producer_execution_ref"):
        with pytest.raises(ValidationError, match="whitespace or control"):
            PresentedTerrainSnapshotV0(**{**payload, field: "ref-1\n"})


@pytest.mark.parametrize(
    "overrides,kwargs,field",
    [
        ({"evidence_refs": ("evidence:ssh-ed25519:AAAAC3Nza",)}, {}, "evidence_refs"),
        (
            {"isolation_assertion_refs": ("isolation:-----BEGIN-PRIVATE",)},
            {},
            "isolation_assertion_ref",
        ),
        ({}, {"isolation_result_ref": "evidence:ssh-rsa:AAAAB3Nza"}, "isolation_result_ref"),
    ],
)
def test_secret_material_is_refused_in_every_reference_field(overrides, kwargs, field):
    """Not only the credential slot: evidence and isolation references are
    published too, and secret material in them travels just as far."""

    with pytest.raises(EffectProjectionRefused, match=f"{field} carries secret material"):
        _project(snapshot_overrides=overrides, **kwargs)


# --------------------------------------------------------------------------
# The loss list
# --------------------------------------------------------------------------


def test_every_local_field_is_either_mapped_or_declared_unmapped():
    """No third category. An unclassified field is a field dropped by accident."""

    local = set(PresentedTerrainSnapshotV0.model_fields)
    classified = set(MAPPED_INTO_FABRIC) | NOT_CARRIED_INTO_FABRIC

    assert not set(MAPPED_INTO_FABRIC) & NOT_CARRIED_INTO_FABRIC, (
        "a field cannot be both carried and declared unmapped"
    )
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
    # Carried since `v0.9.0rc5` (Fabric#51); the loss list no longer claims
    # there is nowhere to put them.
    for carried in ("trace_id", "synthetic_identity_refs", "synthetic_credential_refs"):
        assert carried not in NOT_CARRIED_INTO_FABRIC
        assert MAPPED_INTO_FABRIC[carried] == carried


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
