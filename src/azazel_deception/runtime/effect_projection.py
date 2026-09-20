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

Observing against an effect, and what AZ-06 refuses to observe
---------------------------------------------------------------
`EffectObservation` is AZ-06's record to make -- AZ-06 is the materializer, and
"what a materializer observed" is its claim. It was **not producible** until
recently, for a reason outside this repository: it is keyed on an
`effect:`-typed id minted by whoever constructed the effect, and nothing in the
series minted one. Azazel-Edge#419 changed that, so this module now consumes a
`DefensiveEffectRef` and observes against it.

AZ-06 narrows what it will accept, and the narrowing is doctrine rather than
taste. **Deception materializes an Edge-approved environment; it does not
select, approve, or widen authority.** So:

*Only a decided effect.* `producer_decision_ref` is the one authority class
that names an approval. `advisory_inference` is advice and `planned_shadow` is
something a product considered; materializing either would make AZ-06 the thing
that turned a suggestion into an environment. Refused.

*Only redirection.* Presented Terrain has no meaning behind
`network_isolation` or `notify_only`. The same reasoning already governs
`producer_evidence`, which accepts a `redirection` mechanism and nothing else.

*Only within the effect's window.* A live status observed after the effect
expired is refused by Fabric's own
`assert_observation_within_effect_window`, and this module calls it rather than
re-deciding: a stale `active` observation is how a time-boxed environment
silently becomes an unbounded one.

`OutcomeObservationEnvelope` remains unproduced here. It correlates
`outcome_contracts` records across a window, which is a different job from
observing one materialization, and AZ-06 has no window to speak for.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from azazel_fabric.effect_contracts import (
    AuthorityClass,
    DefensiveEffectRef,
    EffectClass,
    EffectObservation,
    PresentedTerrainRef,
    RefKind,
    assert_effect_chain_consistent,
    assert_observation_within_effect_window,
    is_authoritative_decision_reference,
    parse_ref,
)

from azazel_deception.runtime.presented_terrain import PresentedTerrainSnapshotV0

__all__ = [
    "MATERIALIZABLE_EFFECT_CLASSES",
    "NOT_CARRIED_INTO_FABRIC",
    "EffectProjectionRefused",
    "EffectRefRejected",
    "ProjectedPresentedTerrain",
    "accept_defensive_effect_ref",
    "fabric_lifecycle_state_ref",
    "fabric_presentation_id",
    "observe_effect",
    "project_presented_terrain",
]


class EffectRefRejected(ValueError):
    """AZ-06 will not materialize or observe against this effect, and why.

    Distinct from `EffectProjectionRefused`, which means AZ-06 lacks a fact the
    contract needs. This one means the effect is well-formed and AZ-06 is
    declining it on doctrine: the two are different answers and collapsing them
    would make "we could not" indistinguishable from "we may not".
    """


#: The effect classes AZ-06 may materialize as Presented Terrain.
#:
#: One member, and the narrowness is the point. Presented Terrain is a surface
#: an adversary is redirected onto; there is nothing for AZ-06 to present
#: behind `network_isolation`, `rate_limit` or `notify_only`. A wider set here
#: would be AZ-06 offering to materialize effects nobody designed it for.
MATERIALIZABLE_EFFECT_CLASSES = frozenset({EffectClass.REDIRECT_TO_PRESENTED_TERRAIN})


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


def accept_defensive_effect_ref(payload: Mapping[str, Any]) -> Any:
    """Validate an effect reference AZ-06 received, or say why it is refused.

    The contract's shape, vocabulary and bounds are Azazel-Fabric's statement:
    the payload goes through `DefensiveEffectRef` and nothing here restates
    what that record is. What is local is AZ-06's narrowing, which is stricter
    than the contract in every case and never looser.

    Refuses, in order:

    *An effect nobody decided.* `is_authoritative_decision_reference` is the
    function an adversarial payload would want to fool, and it returns true for
    exactly one class. AZ-06 materializes an Edge-approved environment; an
    effect carrying `advisory_inference` or `planned_shadow` was advised or
    considered, not approved, and materializing one would make AZ-06 the step
    that turned a suggestion into an environment.

    *An effect class AZ-06 cannot present.* See
    `MATERIALIZABLE_EFFECT_CLASSES`.

    *A producer naming itself.* An effect AZ-06 minted for itself and then
    accepted as an instruction would be AZ-06 deciding, whatever the
    `authority_class` said.
    """

    if not isinstance(payload, Mapping):
        raise EffectRefRejected("an effect reference payload must be a mapping")

    effect = DefensiveEffectRef(**dict(payload))

    if not is_authoritative_decision_reference(effect.authority_class):
        raise EffectRefRejected(
            f"effect {effect.effect_id} claims {effect.authority_class.value!r}; "
            "AZ-06 materializes an Edge-approved environment and will not "
            "materialize advice or a shadow run"
        )
    if effect.effect_class not in MATERIALIZABLE_EFFECT_CLASSES:
        raise EffectRefRejected(
            f"effect {effect.effect_id} is {effect.effect_class.value!r}; "
            "Presented Terrain has no meaning behind it"
        )
    if effect.producer_product == "azazel-deception":
        raise EffectRefRejected(
            "AZ-06 will not accept an effect it produced itself; an effect that "
            "returns to its own producer as an instruction is that producer "
            "deciding, whatever authority class it carries"
        )
    return effect


def observe_effect(
    effect: Any,
    *,
    status: str,
    observed_at: str,
    execution_ref: str | None = None,
    termination_reason: str | None = None,
    evidence_refs: Sequence[str] = (),
    limitations: Sequence[str] = (),
) -> Any:
    """State what AZ-06 observed about an effect. A fact, not a request.

    `trace_id` is taken from the effect rather than accepted from the caller.
    An observation that could name its own trace could be attached to an
    incident it has nothing to do with, and the chain check would pass because
    both halves would agree with each other and with nothing else.

    The authority class is derived from the status for the same reason: Fabric
    requires `active_materialized` for a live status and forbids it otherwise,
    so a caller-supplied class could only ever agree or be rejected. Deriving
    it removes a field that has no correct value other than the derived one.
    """

    live = status in ("started", "active")
    observation = EffectObservation(
        observation_id=_observation_id(effect, status, observed_at),
        effect_ref=effect.effect_id,
        trace_id=effect.trace_id,
        status=status,
        observed_at=observed_at,
        materialization_producer="azazel-deception",
        execution_ref=execution_ref,
        termination_reason=termination_reason,
        evidence_refs=tuple(evidence_refs),
        limitations=tuple(limitations),
        authority_class=(
            AuthorityClass.ACTIVE_MATERIALIZED if live else AuthorityClass.OBSERVED_FACT
        ),
    )

    # Fabric's rule, applied by calling it. A replayed `active` observation
    # arriving after the effect expired is how a bounded environment silently
    # becomes an unbounded one, and AZ-06 does not re-decide that here.
    assert_observation_within_effect_window(effect, observation)

    # This one cannot fail as the function is written above -- both the trace
    # and the effect reference are read off `effect`. It is kept because it is
    # what notices if that stops being true, and that was measured rather than
    # assumed: making `trace_id` a caller-supplied parameter breaks 11 tests
    # with this call present and 3 without it. It is the guard that makes the
    # trace non-negotiable, not a backstop nobody reaches.
    assert_effect_chain_consistent(effect, observations=[observation])
    return observation


def _observation_id(effect: Any, status: str, observed_at: str) -> str:
    """Deterministic, and distinct per observation of one effect.

    The status and the instant are both in it: observing the same effect twice
    at different moments is two observations, and an id that collapsed them
    would make the later one look like a correction of the earlier.
    """

    import hashlib  # noqa: PLC0415

    material = "\x1f".join((str(effect.effect_id), status, observed_at))
    return "effect_observation:" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]
