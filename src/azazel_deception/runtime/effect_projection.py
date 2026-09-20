"""Project AZ-06's presented-terrain fact into Fabric's `effect_contracts` form.

This is Azazel-Deception's **producer** for the cross-series
`effect_contracts` family (Fabric#15). It sits after
`presented_terrain.build_presented_terrain_snapshot` and converts the local
`PresentedTerrainSnapshotV0` into `azazel_fabric.effect_contracts.PresentedTerrainRef`.

It adds nothing. It selects nothing. It never authorizes materialization, and
it never writes back into the snapshot it was handed. A projection is a
rendering of a fact AZ-06 already established; Azazel-Edge's deterministic
arbiter remains the only decision and enforcement authority.

Why it refuses instead of filling gaps
--------------------------------------
Fabric's record requires things AZ-06's record does not always have. Every one
of them could be papered over with a plausible default, and each such default
would make the contract *look* adopted while telling a consumer something AZ-06
never observed. The most consequential is `expires_at`: Fabric requires a
bounded presentation, AZ-06 commonly has no declared bound, and a projector
that invented one would let a consumer believe AZ-06 time-boxed a presentation
it did not. So the rule here is:

    a fact AZ-06 does not hold is a refusal, never a default.

`EffectProjectionRefused` names which fact was missing. A caller that gets one
has learned something true about the contract's fit; a caller that got a
record with an invented bound would have learned something false.

What this module does not produce, and why
------------------------------------------
`EffectObservation` and `OutcomeObservationEnvelope` are AZ-06-shaped records
-- AZ-06 is the materializer, and "what a materializer observed" is its claim
to make. Neither is producible today, for a reason outside this repository:
both are keyed on an `effect:`-typed id minted by whoever constructed the
effect, and **nothing in the series mints one**. AZ-06 receives an
`EnvironmentActivationDecision`, not a `DefensiveEffectRef`, so there is no
effect id to observe against. `tests/test_effect_contracts_producer.py` pins
that as a measured blocker rather than leaving it as an absence someone has to
rediscover.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from azazel_fabric.effect_contracts import (
    AuthorityClass,
    PresentedTerrainRef,
    RefKind,
    parse_ref,
)

from azazel_deception.runtime.presented_terrain import PresentedTerrainSnapshotV0

__all__ = [
    "NOT_CARRIED_INTO_FABRIC",
    "EffectProjectionRefused",
    "ProjectedPresentedTerrain",
    "fabric_lifecycle_state_ref",
    "fabric_presentation_id",
    "project_presented_terrain",
]


class EffectProjectionRefused(ValueError):
    """AZ-06 does not hold a fact the Fabric record requires."""


#: AZ-06's local presentation ids are `presentation-<24 hex>`.
_LOCAL_PRESENTATION_ID = re.compile(r"^presentation-(?P<body>[0-9a-f]{24})$")

#: How a local lifecycle state is mapped onto an authority claim.
#:
#: `stale` lands on the weakest class rather than on `observed_fact`. A stale
#: snapshot is one whose runtime AZ-06 could not independently read back, so
#: calling it an observed fact would assert exactly the thing that could not be
#: observed.
_AUTHORITY_BY_LIFECYCLE: dict[str, AuthorityClass] = {
    "active": AuthorityClass.ACTIVE_MATERIALIZED,
    "terminated": AuthorityClass.OBSERVED_FACT,
    "reset": AuthorityClass.OBSERVED_FACT,
    "failed": AuthorityClass.OBSERVED_FACT,
    "stale": AuthorityClass.STALE_OR_UNKNOWN,
}

#: Local snapshot fields that reach no `PresentedTerrainRef` slot.
#:
#: Pinned literally, not derived. A set computed from the two models would
#: shrink silently when a field is deleted on either side, which is the one
#: change this needs to notice. `tests/test_effect_contracts_producer.py`
#: checks it against both models in both directions, so a new local field
#: cannot be left unclassified and a Fabric field arriving under one of these
#: names turns the list red instead of leaving the value dropped.
#:
#: Three of these are worth naming out loud rather than merely listing:
#:
#: `trace_id`
#:     `effect_contracts` correlates by trace everywhere else --
#:     `DefensiveEffectRef`, `EffectObservation` and `OutcomeObservationEnvelope`
#:     all carry one and `assert_effect_chain_consistent` compares them --
#:     but `PresentedTerrainRef` has no trace slot. A presented terrain is
#:     therefore correlatable only through `activation_decision_ref`.
#:
#: `synthetic_identity_refs`, `synthetic_credential_refs`
#:     Named in Fabric#15's own candidate field list ("synthetic
#:     artifact/identity/credential refs"), absent from the shipped model,
#:     which kept `synthetic_artifact_refs` alone.
NOT_CARRIED_INTO_FABRIC = frozenset(
    {
        "ended_at",
        "environment_id",
        "executable",
        "limitations",
        "observed_at",
        "package_digest",
        "package_id",
        "package_version",
        "producer_defensive_state",
        "producer_defensive_state_is_canonical",
        "producer_execution_ref",
        "producer_mechanism_kind",
        "producer_mechanism_ref",
        "producer_node",
        "reset_ref",
        "runtime_node_id",
        "synthetic_credential_refs",
        "synthetic_identity_refs",
        "trace_id",
    }
)


@dataclass(frozen=True)
class ProjectedPresentedTerrain:
    """A Fabric record and an explicit statement of what it left behind.

    The loss list is returned rather than logged because a lossy projection
    that reports nothing is how a consumer comes to read the Fabric record as
    the whole of what AZ-06 observed. It is the same list for every snapshot,
    which is the point: it describes the contract's reach, not this record's.
    """

    ref: PresentedTerrainRef
    not_carried: frozenset[str]


def fabric_presentation_id(local_id: str) -> str:
    """`presentation-<24 hex>` -> `presentation:<24 hex>`.

    The body is carried across unchanged, so the two ids name the same
    presentation and either can be derived from the other. Anything that is not
    an AZ-06 presentation id is refused rather than prefixed: prefixing an
    arbitrary string would mint a well-formed reference to nothing.
    """

    match = _LOCAL_PRESENTATION_ID.fullmatch(local_id)
    if match is None:
        raise EffectProjectionRefused(
            f"{local_id!r} is not an AZ-06 presentation id; a typed reference "
            "cannot be minted from a value whose shape is unknown"
        )
    return f"presentation:{match.group('body')}"


def fabric_lifecycle_state_ref(local_id: str, lifecycle_state: str) -> str:
    """Mint the `lifecycle:` reference Fabric requires.

    Fabric asks for a reference to a lifecycle *state* record. **AZ-06 does not
    persist one separately** -- the snapshot is where its lifecycle facts live.
    So this reference resolves to the snapshot, and it carries the state in its
    body on purpose: a reference that did not would still look current after
    the presentation moved on, which is precisely the stale-reference failure
    the typed-ref scheme exists to make visible.
    """

    match = _LOCAL_PRESENTATION_ID.fullmatch(local_id)
    if match is None:
        raise EffectProjectionRefused(
            f"{local_id!r} is not an AZ-06 presentation id"
        )
    return f"lifecycle:{match.group('body')}.{lifecycle_state}"


def _require_projectable_refs(
    values: tuple[str, ...], kind: RefKind, *, field: str
) -> None:
    """Refuse a reference the pinned Fabric grammar will not accept.

    Rewriting it here is not an option, and it is worth being explicit about
    why: an identifier is a handle on something. `surface:http:8080` rewritten
    to `surface:http-8080` is a well-formed reference to a surface that does
    not exist. Refusing tells the truth; rewriting produces a record that
    validates and misleads.
    """

    for value in values:
        parsed, _ = parse_ref(value)
        if parsed is not kind:
            raise EffectProjectionRefused(
                f"{field} value {value!r} is not a {kind.value!r} reference the "
                "pinned Fabric grammar accepts, and AZ-06 will not rewrite a "
                "producer's identifier to make one fit"
            )


def project_presented_terrain(
    snapshot: PresentedTerrainSnapshotV0,
    *,
    presentation_version: int,
    expires_at: str | None = None,
    isolation_result_ref: str | None = None,
) -> ProjectedPresentedTerrain:
    """Render `snapshot` as a `PresentedTerrainRef`, or refuse and say why.

    `presentation_version` and `expires_at` are supplied by the caller because
    AZ-06 holds neither. They must come from something real -- a declared
    package bound, a caller-maintained revision -- and never from this module,
    which has no basis for either.
    """

    if not isinstance(snapshot, PresentedTerrainSnapshotV0):
        raise EffectProjectionRefused("a presented-terrain snapshot is required")

    authority = _AUTHORITY_BY_LIFECYCLE.get(snapshot.lifecycle_state)
    if authority is None:  # pragma: no cover - the literal type forbids it
        raise EffectProjectionRefused(
            f"lifecycle state {snapshot.lifecycle_state!r} has no authority mapping"
        )

    created_at = snapshot.started_at
    if not created_at:
        raise EffectProjectionRefused(
            "the snapshot records no start instant, and Fabric's record has no "
            "form for a presentation that did not start"
        )

    bound = expires_at or snapshot.expires_at
    if not bound:
        raise EffectProjectionRefused(
            "no expiry is declared for this presentation. Fabric requires a "
            "bounded one, and a bound invented here would report that AZ-06 "
            "time-boxed a presentation it did not"
        )

    assertions = snapshot.isolation_assertion_refs
    if not assertions:
        raise EffectProjectionRefused(
            "Fabric's record requires an isolation assertion and this snapshot "
            "carries none"
        )
    if len(assertions) > 1:
        raise EffectProjectionRefused(
            f"the snapshot carries {len(assertions)} isolation assertions and "
            "Fabric's record has room for one; dropping the rest would narrow "
            "the evidence without saying so"
        )

    _require_projectable_refs(
        snapshot.active_surface_refs, RefKind.SURFACE, field="active_surface_refs"
    )
    _require_projectable_refs(
        snapshot.synthetic_artifact_refs,
        RefKind.ARTIFACT,
        field="synthetic_artifact_refs",
    )

    ref = PresentedTerrainRef(
        presentation_id=fabric_presentation_id(snapshot.presentation_id),
        presentation_version=presentation_version,
        producer_product="azazel-deception",
        activation_decision_ref=snapshot.producer_decision_ref,
        lifecycle_state_ref=fabric_lifecycle_state_ref(
            snapshot.presentation_id, snapshot.lifecycle_state
        ),
        active_surface_refs=snapshot.active_surface_refs,
        synthetic_artifact_refs=snapshot.synthetic_artifact_refs,
        isolation_assertion_ref=assertions[0],
        isolation_result_ref=isolation_result_ref,
        created_at=created_at,
        expires_at=bound,
        evidence_refs=snapshot.evidence_refs,
        authority_class=authority,
    )
    return ProjectedPresentedTerrain(ref=ref, not_carried=NOT_CARRIED_INTO_FABRIC)
