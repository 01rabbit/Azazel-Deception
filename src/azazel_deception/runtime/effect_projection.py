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

*Binding a terrain to an effect.* Since `v0.9.0rc5` (Fabric#51) a terrain can
name the effect it was presented for (`source_effect_ref` + `trace_id`), which
is the only binding an effect with no decision has. AZ-06's default mode is a
shadow run, and until then its terrain could not be chained to its effect at
all. `project_presented_terrain(..., source_effect=...)` makes that binding and
refuses the ones that would be untrue: another trace, a decision that is not
the effect's, or a decision-less effect presented as live. Binding is not
accepting -- it widens nothing about what AZ-06 will materialize, and
`accept_defensive_effect_ref` still declines a shadow run.

`OutcomeObservationEnvelope` remains unproduced here. It correlates
`outcome_contracts` records across a window, which is a different job from
observing one materialization, and AZ-06 has no window to speak for.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from azazel_fabric.effect_contracts import (
    AuthorityClass,
    DefensiveEffectRef,
    EffectClass,
    EffectObservation,
    PresentedTerrainRef,
    RefKind,
    assert_effect_chain_consistent,
    assert_no_secret_material,
    assert_observation_within_effect_window,
    is_authoritative_decision_reference,
    parse_ref,
)

from azazel_deception.runtime.presented_terrain import PresentedTerrainSnapshotV0

__all__ = [
    "MAPPED_INTO_FABRIC",
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
#: `trace_id`, `synthetic_identity_refs` and `synthetic_credential_refs` used
#: to be listed here: `PresentedTerrainRef` had no slot for them until
#: `v0.9.0rc5` (Fabric#51). The guard above turned red when the pin moved,
#: which was its purpose, and they now live in `MAPPED_INTO_FABRIC`.
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
    }
)

#: Local snapshot field -> the `PresentedTerrainRef` slot it reaches.
#:
#: Pinned literally for the same reason as `NOT_CARRIED_INTO_FABRIC`, and
#: checked against both models by `tests/test_effect_contracts_producer.py`.
#: The two together must classify every local field exactly once.
#:
#: The three `v0.9.0rc5` additions are carried unchanged and typed-checked
#: rather than typed here: `synthetic_identity_refs` must already be
#: `identity:` references and `synthetic_credential_refs` `credential:` ones,
#: and a value that is not is refused. Prefixing it would mint a well-formed
#: reference to a record nobody wrote.
MAPPED_INTO_FABRIC: Mapping[str, str] = MappingProxyType(
    {
        "schema_version": "schema_version",
        "presentation_id": "presentation_id",
        "producer_product": "producer_product",
        "producer_decision_ref": "activation_decision_ref",
        "trace_id": "trace_id",
        "lifecycle_state": "lifecycle_state_ref",
        "active_surface_refs": "active_surface_refs",
        "synthetic_artifact_refs": "synthetic_artifact_refs",
        "synthetic_identity_refs": "synthetic_identity_refs",
        "synthetic_credential_refs": "synthetic_credential_refs",
        "isolation_assertion_refs": "isolation_assertion_ref",
        "started_at": "created_at",
        "expires_at": "expires_at",
        "evidence_refs": "evidence_refs",
        "authority_class": "authority_class",
    }
)

#: The only lifecycle a terrain bound to an effect nobody decided may carry.
#:
#: An allowlist, not a list of the states that say an environment ran.
#: `active`, `terminated` and `reset` say so outright; `failed` says a run was
#: attempted, and a failed live run recorded as a shadow run would erase the
#: attempt. `stale` is AZ-06 saying it could not verify a runtime, which is the
#: one local state compatible with "nothing was materialized".
_SHADOW_BINDABLE_LIFECYCLES = frozenset({"stale"})


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


def _require_opaque(value: object, *, field: str) -> None:
    """Refuse an empty value, or one carrying whitespace or a control character.

    Applied to **every** reference the projector emits -- typed or untyped,
    from the snapshot, from the caller or from a bound effect -- by the
    loop over emitted references in `project_presented_terrain`. Checked
    here rather than left to Fabric, because the pinned grammar does not
    check it: `OPAQUE_REF_PATTERN` ends in `$` and is applied with `.match`,
    so `credential:x\n` parses as a typed reference (Azazel-Fabric#65).
    AZ-06 does not rely on that. A reference is opaque because it has no
    structure a reader could act on, and a trailing newline is structure --
    a value that ends a line in a log or a header. An empty value is refused
    too, with its own message: it names nothing, and saying it carries
    whitespace would misreport why.
    """

    if isinstance(value, str) and not value:
        raise EffectProjectionRefused(
            f"{field} value is empty; a reference AZ-06 publishes must name "
            "something, and AZ-06 will not invent a value to fill it"
        )
    if not isinstance(value, str) or any(
        ch.isspace() or not ch.isprintable() for ch in value
    ):
        raise EffectProjectionRefused(
            f"{field} value {value!r} contains whitespace or a control character; "
            "a reference AZ-06 publishes is opaque, and AZ-06 will not strip it "
            "to make it fit"
        )


def _refuse_secret_material(values: tuple[str, ...], *, field: str) -> None:
    """Refuse a value that carries recognizable secret material.

    Fabric's record runs the same check and would raise too. It is called here
    first so the refusal is AZ-06's, named in AZ-06's terms, and so that no
    path exists on which the projector hands the material to a constructor at
    all. A credential that reached a contract would be a real credential
    wherever the contract went.
    """

    try:
        assert_no_secret_material(values, field=field)
    except ValueError as exc:
        raise EffectProjectionRefused(
            f"{field} carries secret material; AZ-06 publishes a reference to a "
            f"synthetic credential, never the credential ({exc})"
        ) from None


def _require_projectable_refs(
    values: tuple[str, ...], kind: RefKind, *, field: str
) -> None:
    """Refuse a reference the pinned Fabric grammar will not accept.

    Rewriting it here is not an option, and it is worth being explicit about
    why: an identifier is a handle on something. `surface:http:8080` rewritten
    to `surface:http-8080` is a well-formed reference to a surface that does
    not exist. Refusing tells the truth; rewriting produces a record that
    validates and misleads.

    The same holds for typing. An untyped `finance-clerk` in
    `synthetic_identity_refs` is not given an `identity:` prefix: the result
    would be a well-formed reference to an identity record nobody wrote.
    """

    for value in values:
        _require_opaque(value, field=field)
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
    source_effect: Any | None = None,
) -> ProjectedPresentedTerrain:
    """Render `snapshot` as a `PresentedTerrainRef`, or refuse and say why.

    `presentation_version` and `expires_at` are supplied by the caller because
    AZ-06 holds neither. They must come from something real -- a declared
    package bound, a caller-maintained revision -- and never from this module,
    which has no basis for either.

    `source_effect` is the `DefensiveEffectRef` this terrain was presented for,
    when there is one. Without it the terrain binds through its activation
    decision, as it always has. With it the terrain also names the effect,
    and that is the only binding an effect with no decision has -- a
    `planned_shadow` effect, AZ-06's default mode. See `_effect_binding`.
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
    _require_projectable_refs(
        snapshot.synthetic_identity_refs,
        RefKind.IDENTITY,
        field="synthetic_identity_refs",
    )
    _require_projectable_refs(
        snapshot.synthetic_credential_refs,
        RefKind.CREDENTIAL,
        field="synthetic_credential_refs",
    )

    activation_decision_ref, source_effect_ref, authority = _effect_binding(
        snapshot, source_effect, authority
    )

    emitted: tuple[tuple[str, tuple[str, ...]], ...] = (
        ("activation_decision_ref", _present(activation_decision_ref)),
        ("source_effect_ref", _present(source_effect_ref)),
        ("trace_id", (snapshot.trace_id,)),
        ("active_surface_refs", snapshot.active_surface_refs),
        ("synthetic_artifact_refs", snapshot.synthetic_artifact_refs),
        ("synthetic_identity_refs", snapshot.synthetic_identity_refs),
        ("synthetic_credential_refs", snapshot.synthetic_credential_refs),
        ("isolation_assertion_ref", (assertions[0],)),
        ("isolation_result_ref", _present(isolation_result_ref)),
        ("evidence_refs", snapshot.evidence_refs),
    )
    for field_name, values in emitted:
        for value in values:
            _require_opaque(value, field=field_name)
        _refuse_secret_material(values, field=field_name)

    ref = PresentedTerrainRef(
        presentation_id=fabric_presentation_id(snapshot.presentation_id),
        presentation_version=presentation_version,
        producer_product="azazel-deception",
        activation_decision_ref=activation_decision_ref,
        source_effect_ref=source_effect_ref,
        trace_id=snapshot.trace_id,
        lifecycle_state_ref=fabric_lifecycle_state_ref(
            snapshot.presentation_id, snapshot.lifecycle_state
        ),
        active_surface_refs=snapshot.active_surface_refs,
        synthetic_artifact_refs=snapshot.synthetic_artifact_refs,
        synthetic_identity_refs=snapshot.synthetic_identity_refs,
        synthetic_credential_refs=snapshot.synthetic_credential_refs,
        isolation_assertion_ref=assertions[0],
        isolation_result_ref=isolation_result_ref,
        created_at=created_at,
        expires_at=bound,
        evidence_refs=snapshot.evidence_refs,
        authority_class=authority,
    )
    return ProjectedPresentedTerrain(ref=ref, not_carried=NOT_CARRIED_INTO_FABRIC)


def _present(value: str | None) -> tuple[str, ...]:
    return () if value is None else (value,)


def _effect_binding(
    snapshot: PresentedTerrainSnapshotV0,
    source_effect: Any | None,
    authority: AuthorityClass,
) -> tuple[str | None, str | None, AuthorityClass]:
    """How the terrain names what put it there: `(decision, effect, authority)`.

    *No effect given.* The terrain names AZ-06's recorded decision, as before
    `v0.9.0rc5`. Nothing changes for a caller that does not ask.

    *An effect that names a decision.* It must be the decision AZ-06 recorded.
    The terrain then names both, so the chain check compares the effect too.

    *An effect that names none.* Only `planned_shadow`, the mode AZ-06 runs in
    by default. The terrain omits the decision -- whatever it named would not
    be the decision that activated it, because there was none -- and binds by
    effect and trace. Its authority is `planned_shadow`, not the lifecycle's.
    Only a `stale` presentation without active surfaces may be bound this
    way (`_SHADOW_BINDABLE_LIFECYCLES`): anything else says AZ-06 ran, or
    tried to run, an environment, and recording that as a shadow run would be
    the record of AZ-06 materializing one -- or would erase a failed attempt.

    In every case the trace must be the effect's. A terrain bound to an effect
    of another incident is the cross-trace collision typed references exist to
    stop, so it is refused here rather than left for a consumer's chain check.

    Each refusal states what was wrong. They are all `EffectRefRejected` --
    the effect is well-formed and AZ-06 declines to tie this terrain to it --
    except a non-effect, which is not a fact AZ-06 can bind to at all.
    """

    if source_effect is None:
        return snapshot.producer_decision_ref, None, authority

    if not isinstance(source_effect, DefensiveEffectRef):
        raise EffectProjectionRefused(
            "source_effect must be a validated DefensiveEffectRef; a terrain "
            "cannot be bound to a value whose shape is unknown"
        )
    effect = source_effect
    # Before any comparison: a reference with a trailing newline must not be
    # emitted, and must not be what two records are found to agree on either.
    _require_opaque(effect.effect_id, field="source_effect.effect_id")
    _require_opaque(effect.trace_id, field="source_effect.trace_id")
    if effect.decision_ref is not None:
        _require_opaque(effect.decision_ref, field="source_effect.decision_ref")
    if effect.trace_id != snapshot.trace_id:
        raise EffectRefRejected(
            f"effect {effect.effect_id} belongs to a different trace than this "
            "presentation; binding them would chain two unrelated incidents"
        )
    if effect.effect_class not in MATERIALIZABLE_EFFECT_CLASSES:
        raise EffectRefRejected(
            f"effect {effect.effect_id} is {effect.effect_class.value!r}; "
            "Presented Terrain has no meaning behind it"
        )
    if effect.producer_product == "azazel-deception":
        raise EffectRefRejected(
            "AZ-06 will not bind a terrain to an effect it produced itself"
        )

    if effect.decision_ref is not None:
        if effect.decision_ref != snapshot.producer_decision_ref:
            raise EffectRefRejected(
                f"effect {effect.effect_id} names a different decision than the "
                "one this presentation records"
            )
        return snapshot.producer_decision_ref, effect.effect_id, authority

    if effect.authority_class is not AuthorityClass.PLANNED_SHADOW:
        raise EffectRefRejected(
            f"effect {effect.effect_id} names no decision and claims "
            f"{effect.authority_class.value!r}; a decision-less terrain is "
            "bound only to a shadow run"
        )
    if snapshot.active_surface_refs:
        # The builder never produces this (surfaces are kept only when the
        # runtime was verified active), but the snapshot model does not forbid
        # it. A shadow terrain presenting live surfaces is a materialization.
        raise EffectRefRejected(
            f"effect {effect.effect_id} is a shadow run and this presentation "
            "carries active surfaces; that would record AZ-06 presenting a "
            "surface for an environment nobody approved"
        )
    if snapshot.lifecycle_state not in _SHADOW_BINDABLE_LIFECYCLES:
        raise EffectRefRejected(
            f"effect {effect.effect_id} is a shadow run and this presentation is "
            f"{snapshot.lifecycle_state!r}; only a 'stale' presentation can be a "
            "shadow run, and anything else would record AZ-06 having run, or "
            "tried to run, an environment nobody approved"
        )
    return None, effect.effect_id, AuthorityClass.PLANNED_SHADOW


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
