"""MIO objective -> observation feedback binding for AZ-06 (Deception#55).

Four things stay apart in everything this module returns, and none of them is
allowed to stand in for another:

* a **MIO objective** is advice. It starts, selects, extends and ends nothing.
* an **Edge decision** is the only authorization. It is HMAC-authenticated,
  one-shot and time-limited, and it is consumed by the existing
  ``DockerComposeAdapter.activate_environment`` -- not by this module.
* **runtime materialization / observed mechanism / interaction / outcome** are
  facts AZ-06 observed, each under its own key.
* a **tactical assessment** is never made here. It is always ``not_assessed``.

This module therefore has no path that calls ``activate_environment`` or
``terminate_environment``, and no function here widens, extends or withdraws
anything. Withdrawal happens only through an Edge termination decision handed
to the existing adapter by the caller. Isolation drift is *recorded* as a fact
(``EffectObservation.status == "failed"``); recording it withdraws nothing.

How an objective is bound to a decision (no Fabric type changes)
-----------------------------------------------------------------
MIO references are ``advisory:`` typed refs (``RefKind.ADVISORY``). When Edge
considered the objective it lists those refs in the signed activation decision's
``evidence_refs``. The HMAC covers the canonical bytes, so the listing is bound
by the signature. No refs in an authenticated, live, accepted decision means
the objective is retained as advice and nothing is exposed
(:class:`AdvisoryRetained`).

Tenant
------
Fabric ``v0.9.0rc5`` has no tenant field. ``node_id`` (from the recorded
runtime state and checked against the decision's ``target_node_id``) together
with ``trace_id`` (from the Edge effect) stands in for it. See
``docs/mio-objective-feedback.md``.

The bundle produced here is a **local container**. Its schema string says so.
Every wire object inside it is a Fabric type that was validated on the way in.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal, get_args

from azazel_fabric.deception_contracts import (
    EnvironmentActivationDecision,
    InteractionObservation,
    PlacementPlan,
    assert_no_effectiveness_verdict,
    assert_no_runtime_directives,
)
from azazel_fabric.deception_contracts.observation import (
    InteractionSurface,
    ObservationClass,
)
from azazel_fabric.effect_contracts import (
    AuthorityClass,
    DefensiveEffectRef,
    EffectObservation,
    OutcomeObservationEnvelope,
    PresentedTerrainRef,
    RefKind,
    assert_bounded_fact_payload,
    assert_effect_chain_consistent,
    assert_no_effect_authority_fields,
    assert_no_secret_material,
    parse_ref,
)

from azazel_deception import __version__ as _PRODUCT_VERSION
from azazel_deception.runtime.effect_projection import (
    EffectProjectionRefused,
    EffectRefRejected,
    accept_defensive_effect_ref,
    observe_effect,
    project_presented_terrain,
)
from azazel_deception.runtime.isolation_drift import recorded_drift
from azazel_deception.runtime.presented_terrain import (
    ProducerRedirectionEvidence,
    build_presented_terrain_snapshot,
)
from azazel_deception.runtime.producer_evidence import (
    producer_redirection_from_shared_mechanism,
)
from azazel_deception.runtime.state import RuntimeStateStore
from azazel_deception.runtime.transport import (
    DEFAULT_SIGNATURE_FIELD,
    canonical_decision_bytes,
)

__all__ = [
    "BINDING_REFUSED_CODES",
    "BUNDLE_SCHEMA",
    "AdmittedObjective",
    "AdvisoryRetained",
    "BindingRefused",
    "BoundObserver",
    "MioObservationObjective",
    "ObjectiveRejected",
    "ReferenceChain",
    "accept_mio_objective",
    "admit_objective",
    "bind_reference_chain",
    "bound_observer",
    "build_feedback_bundle",
    "knowledge_ingest_payload",
    "mio_deception_context",
    "reset_feedback",
    "verify_feedback_bundle",
]

BUNDLE_SCHEMA = "az06-mio-feedback-bundle/v0-local"

BINDING_REFUSED_CODES = frozenset(
    {
        "decision_unauthenticated",
        "decision_not_consumed",
        "decision_mismatch",
        "lease_expired",
        "lease_not_started",
        "environment_mismatch",
        "package_mismatch",
        "node_mismatch",
        "session_mismatch",
        "session_reset",
        "effect_decision_mismatch",
        "effect_rejected",
        "evidence_tampered",
        "stale",
        "interaction_unbound",
        "telemetry_missing",
    }
)

MAX_HYPOTHESES = 8
MAX_DESIRED_OBSERVATIONS = 16
MAX_INTERACTIONS = 256
_MAX_REF_LENGTH = 200
_UNTRUSTED_KEYS = ("untrusted_text_sha256", "untrusted_text_len")

_OBSERVATION_CLASSES = frozenset(get_args(ObservationClass))
_SURFACES = frozenset(get_args(InteractionSurface))
_EVIDENCE_CHAIN_KEYS = ("_evidence_seq", "_evidence_prev", "_evidence_hash")
_OBSERVATION_SCHEMA = "interaction-observation/v0.1"
_LIVE_STATES = frozenset({"active"})

_ALLOWED_OBJECTIVE_KEYS = frozenset(
    {
        "objective_ref",
        "hypothesis_refs",
        "frame_ref",
        "desired_observations",
        "authority",
        "executable",
    }
)
_REQUIRED_OBJECTIVE_KEYS = frozenset(
    {"objective_ref", "hypothesis_refs", "frame_ref", "desired_observations"}
)


class ObjectiveRejected(ValueError):
    """The MIO input itself is not an acceptable advisory objective."""


class BindingRefused(ValueError):
    """A reference chain does not hold. ``code`` is from a closed vocabulary."""

    def __init__(self, code: str, message: str = "") -> None:
        if code not in BINDING_REFUSED_CODES:  # pragma: no cover - programming error
            raise ValueError(f"unknown BindingRefused code: {code!r}")
        self.code = code
        super().__init__(f"{code}: {message}" if message else code)


# --------------------------------------------------------------------------
# small helpers


def _aware(value: datetime, *, name: str = "now") -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(f"{name} must be a datetime")
    if value.tzinfo is None:
        raise ValueError(f"{name} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return _utc(value).isoformat()


def _parse_ts(raw: Any) -> datetime:
    if isinstance(raw, datetime):
        return _utc(raw)
    text = str(raw)
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    return _utc(datetime.fromisoformat(text))


def _sha24(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:24]


def _decision_digest(decision: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_decision_bytes(decision)).hexdigest()


def _authenticated(decision: Any, authenticator: Any) -> bool:
    if not isinstance(decision, Mapping) or not callable(authenticator):
        return False
    try:
        return authenticator(decision) is True
    except Exception:
        return False


def _parse_activation(decision: Mapping[str, Any]) -> EnvironmentActivationDecision:
    contract = {k: v for k, v in decision.items() if k != DEFAULT_SIGNATURE_FIELD}
    return EnvironmentActivationDecision.model_validate(contract)


def _check_advisory_ref(value: Any, prefix: str, *, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ObjectiveRejected(f"{field_name} must be a non-empty string")
    kind, body = parse_ref(value)
    if kind is not RefKind.ADVISORY or value != f"advisory:{body}":
        raise ObjectiveRejected(f"{field_name} must be an advisory: typed reference")
    if len(body) > _MAX_REF_LENGTH or not body.startswith(prefix) or body == prefix:
        raise ObjectiveRejected(f"{field_name} must be advisory:{prefix}<id>")
    if any(ch.isspace() or not ch.isprintable() for ch in value):
        raise ObjectiveRejected(f"{field_name} must not contain whitespace or control characters")
    return value


# --------------------------------------------------------------------------
# objective


@dataclass(frozen=True)
class MioObservationObjective:
    """Local, non-wire receiver for a MIO observation objective.

    Exists until Fabric#72 gives the objective a typed home. It is advisory:
    ``authority`` can only be ``advisory_only``.
    """

    objective_ref: str
    hypothesis_refs: tuple[str, ...]
    frame_ref: str
    desired_observations: tuple[tuple[str, str], ...]
    authority: Literal["advisory_only"] = "advisory_only"

    def advisory_refs(self) -> tuple[str, ...]:
        return (self.objective_ref, *self.hypothesis_refs, self.frame_ref)


def accept_mio_objective(payload: Mapping[str, Any]) -> MioObservationObjective:
    """Validate a MIO objective, or raise :class:`ObjectiveRejected`.

    The key set is closed. Anything that names an action, an environment, a
    package, a decision, a budget or a lifetime is not an objective and is
    refused before any value is read.
    """

    if not isinstance(payload, Mapping):
        raise ObjectiveRejected("objective payload must be a mapping")
    if any(not isinstance(key, str) for key in payload):
        raise ObjectiveRejected("objective keys must be strings")
    unknown = set(payload) - _ALLOWED_OBJECTIVE_KEYS
    if unknown:
        raise ObjectiveRejected(
            "objective carries fields outside the advisory shape: "
            + ", ".join(sorted(unknown)[:8])
        )
    missing = _REQUIRED_OBJECTIVE_KEYS - set(payload)
    if missing:
        raise ObjectiveRejected("objective is missing: " + ", ".join(sorted(missing)))
    try:
        assert_no_runtime_directives(payload)
        assert_no_effect_authority_fields(payload)
        assert_no_secret_material(json.loads(json.dumps(payload, default=str)), field="objective")
    except ValueError as exc:
        raise ObjectiveRejected(str(exc)) from None

    authority = payload.get("authority", "advisory_only")
    if authority != "advisory_only":
        raise ObjectiveRejected("authority must be advisory_only")
    if "executable" in payload and payload["executable"] is not False:
        raise ObjectiveRejected("executable must be False")

    objective_ref = _check_advisory_ref(
        payload["objective_ref"], "mio-objective-", field_name="objective_ref"
    )
    frame_ref = _check_advisory_ref(payload["frame_ref"], "mio-frame-", field_name="frame_ref")

    raw_hypotheses = payload["hypothesis_refs"]
    if not isinstance(raw_hypotheses, (list, tuple)):
        raise ObjectiveRejected("hypothesis_refs must be a list")
    if not 1 <= len(raw_hypotheses) <= MAX_HYPOTHESES:
        raise ObjectiveRejected(f"hypothesis_refs must hold 1..{MAX_HYPOTHESES} entries")
    hypotheses = tuple(
        _check_advisory_ref(item, "mio-hypothesis-", field_name="hypothesis_refs")
        for item in raw_hypotheses
    )
    if len(set(hypotheses)) != len(hypotheses):
        raise ObjectiveRejected("hypothesis_refs must be unique")

    raw_desired = payload["desired_observations"]
    if not isinstance(raw_desired, (list, tuple)):
        raise ObjectiveRejected("desired_observations must be a list")
    if not 1 <= len(raw_desired) <= MAX_DESIRED_OBSERVATIONS:
        raise ObjectiveRejected(
            f"desired_observations must hold 1..{MAX_DESIRED_OBSERVATIONS} entries"
        )
    desired: list[tuple[str, str]] = []
    for item in raw_desired:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            raise ObjectiveRejected("desired_observations entries must be (class, surface)")
        observation_class, surface = item
        if observation_class not in _OBSERVATION_CLASSES or surface not in _SURFACES:
            raise ObjectiveRejected("desired_observations entry is outside the Fabric vocabulary")
        desired.append((observation_class, surface))
    if len(set(desired)) != len(desired):
        raise ObjectiveRejected("desired_observations must be unique")

    return MioObservationObjective(
        objective_ref=objective_ref,
        hypothesis_refs=hypotheses,
        frame_ref=frame_ref,
        desired_observations=tuple(desired),
    )


@dataclass(frozen=True)
class AdvisoryRetained:
    """The objective is kept as advice; nothing is exposed because of it."""

    objective: MioObservationObjective
    reason: str
    exposure: Literal["refused"] = "refused"
    authority: Literal["advisory_only"] = "advisory_only"


@dataclass(frozen=True)
class AdmittedObjective:
    """This objective may be bound to this decision. Not an exposure grant."""

    objective: MioObservationObjective
    decision_id: str
    decision_digest: str


def admit_objective(
    objective: MioObservationObjective,
    signed_activation_decision: Mapping[str, Any] | None,
    *,
    authenticator: Any,
    now: datetime,
) -> AdmittedObjective | AdvisoryRetained:
    """Pure check. Consumes nothing, activates nothing.

    The caller activates afterwards through the existing adapter, which is
    where the decision is consumed and every other gate runs.
    """

    now = _aware(now)
    if signed_activation_decision is None:
        return AdvisoryRetained(objective, "no_decision")
    if not _authenticated(signed_activation_decision, authenticator):
        return AdvisoryRetained(objective, "decision_unauthenticated")
    try:
        decision = _parse_activation(signed_activation_decision)
    except ValueError:
        return AdvisoryRetained(objective, "decision_not_accepted")
    if decision.status not in ("accepted", "modified"):
        return AdvisoryRetained(objective, "decision_not_accepted")
    if _utc(decision.expires_at) <= now:
        return AdvisoryRetained(objective, "decision_expired")
    if _utc(decision.effective_at) > now:
        return AdvisoryRetained(objective, "decision_not_accepted")
    if not set(objective.advisory_refs()) <= set(decision.evidence_refs):
        return AdvisoryRetained(objective, "objective_not_in_authenticated_decision")
    return AdmittedObjective(
        objective=objective,
        decision_id=decision.decision_id,
        decision_digest=_decision_digest(signed_activation_decision),
    )


# --------------------------------------------------------------------------
# reference chain


@dataclass(frozen=True)
class ReferenceChain:
    objective_ref: str
    hypothesis_refs: tuple[str, ...]
    frame_ref: str
    decision_id: str
    decision_digest: str
    lease_start: datetime
    lease_end: datetime
    trace_id: str
    effect_ref: str
    environment_id: str
    package_id: str
    package_digest: str
    node_id: str
    session_ref: str
    generation: int
    #: The accepted Edge effect, kept so observations can be chain-checked
    #: against it. Not part of identity or the serialized chain.
    effect: Any = field(default=None, repr=False, compare=False)

    def evidence_refs(self) -> tuple[str, ...]:
        refs = (
            self.objective_ref,
            *self.hypothesis_refs,
            self.frame_ref,
            f"decision:{self.decision_id}",
            self.session_ref,
            f"environment:{self.environment_id}",
        )
        return tuple(dict.fromkeys(refs))

    def to_dict(self) -> dict[str, Any]:
        return {
            "objective_ref": self.objective_ref,
            "hypothesis_refs": list(self.hypothesis_refs),
            "frame_ref": self.frame_ref,
            "decision_id": self.decision_id,
            "decision_digest": self.decision_digest,
            "lease_start": _iso(self.lease_start),
            "lease_end": _iso(self.lease_end),
            "trace_id": self.trace_id,
            "effect_ref": self.effect_ref,
            "environment_id": self.environment_id,
            "package_id": self.package_id,
            "package_digest": self.package_digest,
            "node_id": self.node_id,
            "session_ref": self.session_ref,
            "generation": self.generation,
        }


def _evidence(adapter: Any, environment_id: str) -> list[dict[str, Any]]:
    try:
        records = adapter.export_evidence(environment_id)
    except (OSError, ValueError):
        raise BindingRefused("evidence_tampered", "evidence unreadable") from None
    return [r for r in records if isinstance(r, dict)]


def _require_chain_intact(store: RuntimeStateStore, environment_id: str) -> None:
    if not store.verify_evidence_chain(environment_id):
        raise BindingRefused("evidence_tampered", "evidence hash chain does not verify")


def _last_activated(records: Sequence[Mapping[str, Any]]) -> Mapping[str, Any] | None:
    found = None
    for record in records:
        if (
            record.get("schema_version") == "environment-event/v0.1"
            and record.get("event_type") == "activated"
        ):
            found = record
    return found


def _session_ref_of(record: Mapping[str, Any]) -> str:
    return "session:" + str(record.get("_evidence_hash", ""))


def _read_state(adapter: Any, environment_id: str) -> dict[str, Any] | None:
    try:
        return adapter.state.read(environment_id)
    except (OSError, ValueError):
        raise BindingRefused("evidence_tampered", "runtime state unreadable") from None


def _coerce_effect(value: Any) -> DefensiveEffectRef:
    if isinstance(value, DefensiveEffectRef):
        payload: Any = value.model_dump(mode="json")
    elif isinstance(value, Mapping):
        payload = dict(value)
    else:
        raise BindingRefused("effect_rejected", "effect reference has an unknown shape")
    try:
        return accept_defensive_effect_ref(payload)
    except (EffectRefRejected, ValueError, TypeError) as exc:
        raise BindingRefused("effect_rejected", exc.__class__.__name__) from None


def bind_reference_chain(
    *,
    admitted: AdmittedObjective,
    signed_activation_decision: Mapping[str, Any],
    defensive_effect_ref: Any,
    adapter: Any,
    environment_id: str,
    now: datetime,
) -> ReferenceChain:
    """Tie objective, decision, effect and the activated session together.

    Precondition: the caller already ran ``adapter.activate_environment``.
    Nothing here activates, consumes or changes state.
    """

    now = _aware(now)
    if not isinstance(admitted, AdmittedObjective):
        raise BindingRefused("decision_mismatch", "an admitted objective is required")
    if not _authenticated(
        signed_activation_decision, getattr(adapter, "decision_authenticator", None)
    ):
        raise BindingRefused("decision_unauthenticated", "decision failed re-authentication")
    try:
        decision = _parse_activation(signed_activation_decision)
    except ValueError:
        raise BindingRefused("decision_mismatch", "decision is not an activation decision") from None
    if (
        decision.decision_id != admitted.decision_id
        or _decision_digest(signed_activation_decision) != admitted.decision_digest
    ):
        raise BindingRefused("decision_mismatch", "decision is not the admitted one")
    if not set(admitted.objective.advisory_refs()) <= set(decision.evidence_refs):
        raise BindingRefused("decision_mismatch", "objective refs are not in the decision")
    if not adapter.state.decision_consumed(decision.decision_id):
        raise BindingRefused("decision_not_consumed", "activation has not consumed the decision")

    lease_start, lease_end = _utc(decision.effective_at), _utc(decision.expires_at)
    if now < lease_start:
        raise BindingRefused("lease_not_started", "decision window has not opened")
    if now >= lease_end:
        raise BindingRefused("lease_expired", "decision window has closed")

    _require_chain_intact(adapter.state, environment_id)
    state = _read_state(adapter, environment_id)
    records = _evidence(adapter, environment_id)
    if state is None:
        resets = [r for r in records if r.get("event_type") == "reset_completed"]
        raise BindingRefused(
            "session_reset" if resets else "session_mismatch", "no runtime state for environment"
        )
    if str(state.get("environment_id") or environment_id) != environment_id:
        raise BindingRefused("environment_mismatch", "runtime state belongs to another environment")
    if state.get("state") not in _LIVE_STATES:
        raise BindingRefused("session_mismatch", "environment is not active")
    if str(state.get("decision_id") or "") != decision.decision_id:
        raise BindingRefused("decision_mismatch", "runtime state was activated by another decision")
    if (
        str(state.get("package_id") or "") != decision.package_id
        or str(state.get("package_digest") or "") != decision.package_digest
    ):
        raise BindingRefused("package_mismatch", "runtime package differs from the decision")
    if str(state.get("node_id") or "") != decision.target_node_id:
        raise BindingRefused("node_mismatch", "runtime node differs from the decision")

    activated = _last_activated(records)
    if activated is None:
        raise BindingRefused("evidence_tampered", "no activated evidence record")
    meta = activated.get("metadata") or {}
    if (
        meta.get("decision_id") != decision.decision_id
        or activated.get("environment_id") != environment_id
    ):
        raise BindingRefused("session_mismatch", "activated record belongs to another session")

    effect = _coerce_effect(defensive_effect_ref)
    if effect.decision_ref != f"decision:{decision.decision_id}":
        raise BindingRefused("effect_decision_mismatch", "effect names another decision")

    return ReferenceChain(
        objective_ref=admitted.objective.objective_ref,
        hypothesis_refs=admitted.objective.hypothesis_refs,
        frame_ref=admitted.objective.frame_ref,
        decision_id=decision.decision_id,
        decision_digest=admitted.decision_digest,
        lease_start=lease_start,
        lease_end=lease_end,
        trace_id=effect.trace_id,
        effect_ref=effect.effect_id,
        environment_id=environment_id,
        package_id=decision.package_id,
        package_digest=decision.package_digest,
        node_id=decision.target_node_id,
        session_ref=_session_ref_of(activated),
        generation=int(activated["_evidence_seq"]),
        effect=effect,
    )


def _check_live_session(
    adapter: Any, chain: ReferenceChain, *, at: datetime
) -> dict[str, Any]:
    """Refuse unless ``chain`` is still the live, in-lease session. Returns state."""

    _require_chain_intact(adapter.state, chain.environment_id)
    records = _evidence(adapter, chain.environment_id)
    for record in records:
        if (
            record.get("event_type") == "reset_completed"
            and int(record.get("_evidence_seq", -1)) > chain.generation
        ):
            raise BindingRefused("session_reset", "the session was reset")
    activated = _last_activated(records)
    if (
        activated is None
        or int(activated.get("_evidence_seq", -1)) != chain.generation
        or _session_ref_of(activated) != chain.session_ref
    ):
        raise BindingRefused("session_mismatch", "a different session is current")
    state = _read_state(adapter, chain.environment_id)
    if state is None:
        raise BindingRefused("session_mismatch", "no runtime state")
    _check_state_identity(state, chain)
    if state.get("state") not in _LIVE_STATES:
        raise BindingRefused("session_mismatch", "environment is not active")
    if at < chain.lease_start:
        raise BindingRefused("lease_not_started", "decision window has not opened")
    if at >= chain.lease_end:
        raise BindingRefused("lease_expired", "decision window has closed")
    return state


def _check_state_identity(state: Mapping[str, Any], chain: ReferenceChain) -> None:
    if str(state.get("environment_id") or chain.environment_id) != chain.environment_id:
        raise BindingRefused("environment_mismatch", "runtime state is for another environment")
    if str(state.get("decision_id") or "") != chain.decision_id:
        raise BindingRefused("decision_mismatch", "runtime state is for another decision")
    if (
        str(state.get("package_id") or "") != chain.package_id
        or str(state.get("package_digest") or "") != chain.package_digest
    ):
        raise BindingRefused("package_mismatch", "runtime package differs")
    if str(state.get("node_id") or "") != chain.node_id:
        raise BindingRefused("node_mismatch", "runtime node differs")


# --------------------------------------------------------------------------
# bound observer


class BoundObserver:
    """Records interactions through the existing observer, stamped with the chain."""

    def __init__(
        self, adapter: Any, chain: ReferenceChain, observer: Any, now_fn: Any
    ) -> None:
        self._adapter = adapter
        self._chain = chain
        self._observer = observer
        self._now_fn = now_fn

    @property
    def chain(self) -> ReferenceChain:
        return self._chain

    def record(
        self,
        *,
        observation_class: str,
        surface: str,
        reaction_kind: str | None = None,
        lure_id: str | None = None,
        first_contact_latency_ms: int | None = None,
        dwell_ms: int | None = None,
        attempt_count: int | None = None,
        confounder_tags: list[str] | None = None,
        evidence_refs: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        observed_at: datetime | None = None,
        untrusted_text: str | None = None,
    ) -> InteractionObservation:
        now = _aware(self._now_fn())
        when = _aware(observed_at) if observed_at is not None else now
        _check_live_session(self._adapter, self._chain, at=max(now, when))

        meta = dict(metadata or {})
        for key in _UNTRUSTED_KEYS:
            meta.pop(key, None)
        if untrusted_text is not None:
            if not isinstance(untrusted_text, str):
                raise TypeError("untrusted_text must be a string")
            raw = untrusted_text.encode("utf-8", errors="replace")
            # Only a digest and a length leave this function. The text itself
            # is never stored, logged or returned.
            meta["untrusted_text_sha256"] = hashlib.sha256(raw).hexdigest()
            meta["untrusted_text_len"] = len(untrusted_text)
        try:
            assert_no_secret_material(meta, field="metadata")
        except ValueError as exc:
            raise ValueError(str(exc)) from None

        refs = list(dict.fromkeys([*(evidence_refs or []), *self._chain.evidence_refs()]))
        return self._observer.record(
            observation_class=observation_class,
            surface=surface,
            reaction_kind=reaction_kind,
            lure_id=lure_id,
            first_contact_latency_ms=first_contact_latency_ms,
            dwell_ms=dwell_ms,
            attempt_count=attempt_count,
            confounder_tags=confounder_tags,
            evidence_refs=refs,
            metadata=meta,
            observed_at=when,
        )


def bound_observer(
    adapter: Any,
    chain: ReferenceChain,
    package: Any,
    placement: Any,
    *,
    now_fn: Any = None,
) -> BoundObserver:
    if now_fn is None:
        def now_fn() -> datetime:
            return datetime.now(timezone.utc)

    if isinstance(package, Mapping):
        package = adapter.validate_package(dict(package))
    if isinstance(placement, Mapping):
        placement = PlacementPlan.model_validate(dict(placement))
    observer = adapter.make_observer(chain.environment_id, package, placement)
    if getattr(observer, "node_id", chain.node_id) != chain.node_id:
        raise BindingRefused("node_mismatch", "placement node differs from the chain")
    if getattr(observer, "package_id", chain.package_id) != chain.package_id:
        raise BindingRefused("package_mismatch", "package differs from the chain")
    return BoundObserver(adapter, chain, observer, now_fn)


# --------------------------------------------------------------------------
# bundle


def _names(value: Any, *, name: str) -> list[str]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise BindingRefused("telemetry_missing", f"{name} must be a collection of names")
    out = []
    for item in value:
        if not isinstance(item, str) or not item or len(item) > 128:
            raise BindingRefused("telemetry_missing", f"{name} holds an invalid name")
        out.append(item)
    return sorted(set(out))


def _session_records(
    adapter: Any, chain: ReferenceChain
) -> tuple[list[dict[str, Any]], int]:
    """Bound interactions of this session, in order, plus count of unbound ones."""

    bound: list[dict[str, Any]] = []
    unbound = 0
    need = set(chain.evidence_refs())
    for record in _evidence(adapter, chain.environment_id):
        if record.get("schema_version") != _OBSERVATION_SCHEMA:
            continue
        if int(record.get("_evidence_seq", -1)) <= chain.generation:
            continue
        canonical = {k: v for k, v in record.items() if k not in _EVIDENCE_CHAIN_KEYS}
        try:
            observation = InteractionObservation.model_validate(canonical)
        except ValueError:
            raise BindingRefused("evidence_tampered", "stored interaction is invalid") from None
        if not need <= set(observation.evidence_refs):
            unbound += 1
            continue
        bound.append(observation.model_dump(mode="json"))
    return bound, unbound


def _runtime_mechanism(mechanism: Any, chain: ReferenceChain) -> ProducerRedirectionEvidence | None:
    if mechanism is None:
        return None
    try:
        if isinstance(mechanism, ProducerRedirectionEvidence):
            evidence = mechanism
        else:
            evidence = producer_redirection_from_shared_mechanism(mechanism)
    except ValueError:
        raise BindingRefused("effect_rejected", "mechanism evidence refused") from None
    if evidence.trace_id != chain.trace_id or evidence.decision_ref not in (
        f"decision:{chain.decision_id}",
        chain.effect.decision_ref if chain.effect is not None else None,
    ):
        raise BindingRefused(
            "effect_decision_mismatch", "mechanism evidence is for another trace or decision"
        )
    return evidence


def _terrain(
    *,
    chain: ReferenceChain,
    state: Mapping[str, Any],
    mechanism: ProducerRedirectionEvidence | None,
    assertions: tuple[str, ...],
    surfaces: tuple[str, ...],
    surfaces_attested: bool,
    now: datetime,
    evidence_refs: tuple[str, ...],
) -> dict[str, Any] | None:
    """Presented-terrain ref, or ``None`` when AZ-06 does not hold what it needs."""

    effect = chain.effect
    if not assertions:
        return None
    activated_at = state.get("activated_at")
    if not activated_at:
        return None
    expires = min(chain.lease_end, _parse_ts(effect.expires_at))
    try:
        if mechanism is not None:
            snapshot = build_presented_terrain_snapshot(
                environment_id=chain.environment_id,
                producer=mechanism,
                runtime_state=state,
                expected_package_id=chain.package_id,
                expected_package_digest=chain.package_digest,
                package_version="not_recorded",
                observed_at=_iso(now),
                active_surface_refs=surfaces,
                isolation_assertion_refs=assertions[:1],
                runtime_verified_active=surfaces_attested,
                expires_at=_iso(expires),
                evidence_refs=evidence_refs,
            )
            projected = project_presented_terrain(
                snapshot,
                presentation_version=chain.generation,
                expires_at=_iso(expires),
                source_effect=effect,
            )
            return projected.ref.model_dump(mode="json")

        lifecycle = {
            "active": "active" if surfaces_attested else "stale",
            "terminated": "terminated",
            "failed": "failed",
        }.get(str(state.get("state")), "stale")
        authority = {
            "active": AuthorityClass.ACTIVE_MATERIALIZED,
            "terminated": AuthorityClass.OBSERVED_FACT,
            "failed": AuthorityClass.OBSERVED_FACT,
            "stale": AuthorityClass.STALE_OR_UNKNOWN,
        }[lifecycle]
        body = _sha24(chain.environment_id, chain.trace_id, chain.package_digest, chain.session_ref)
        ref = PresentedTerrainRef(
            presentation_id=f"presentation:{body}",
            presentation_version=chain.generation,
            producer_product="azazel-deception",
            activation_decision_ref=effect.decision_ref,
            source_effect_ref=effect.effect_id,
            trace_id=chain.trace_id,
            lifecycle_state_ref=f"lifecycle:{body}.{lifecycle}",
            active_surface_refs=surfaces if lifecycle == "active" else (),
            isolation_assertion_ref=assertions[0],
            created_at=_iso(_parse_ts(activated_at)),
            expires_at=_iso(expires),
            evidence_refs=evidence_refs,
            authority_class=authority,
        )
        return ref.model_dump(mode="json")
    except EffectRefRejected:
        raise BindingRefused(
            "effect_decision_mismatch", "terrain cannot be bound to this effect"
        ) from None
    except (EffectProjectionRefused, ValueError):
        return None


def build_feedback_bundle(
    adapter: Any,
    chain: ReferenceChain,
    *,
    now: datetime,
    max_age: float,
    expected_telemetry: Iterable[str],
    observed_telemetry: Iterable[str],
    mechanism: Any = None,
    isolation_assertion_refs: Sequence[str] = (),
    active_surface_refs: Sequence[str] = (),
) -> dict[str, Any]:
    """Collect what AZ-06 observed into a local, bounded, verdict-free container."""

    now = _aware(now)
    expected = _names(expected_telemetry, name="expected_telemetry")
    observed = _names(observed_telemetry, name="observed_telemetry")
    if not expected:
        raise BindingRefused(
            "telemetry_missing", "expected_telemetry must say what coverage was expected"
        )
    gaps = sorted(set(expected) - set(observed))

    store: RuntimeStateStore = adapter.state
    _require_chain_intact(store, chain.environment_id)
    records = _evidence(adapter, chain.environment_id)
    for record in records:
        if (
            record.get("event_type") == "reset_completed"
            and int(record.get("_evidence_seq", -1)) > chain.generation
        ):
            raise BindingRefused("session_reset", "the session was reset; use reset_feedback")
    activated = _last_activated(records)
    if (
        activated is None
        or int(activated.get("_evidence_seq", -1)) != chain.generation
        or _session_ref_of(activated) != chain.session_ref
    ):
        raise BindingRefused("session_mismatch", "a different session is current")
    state = _read_state(adapter, chain.environment_id)
    if state is None:
        raise BindingRefused("session_mismatch", "no runtime state")
    _check_state_identity(state, chain)
    env_state = str(state.get("state") or "unknown")
    if env_state in _LIVE_STATES:
        if now < chain.lease_start:
            raise BindingRefused("lease_not_started", "decision window has not opened")
        if now >= chain.lease_end:
            raise BindingRefused("lease_expired", "decision window has closed")

    effect: DefensiveEffectRef = chain.effect
    if effect is None:
        raise BindingRefused("effect_rejected", "chain carries no effect")
    mech = _runtime_mechanism(mechanism, chain)

    assertions = tuple(dict.fromkeys(isolation_assertion_refs))
    surfaces = tuple(dict.fromkeys(active_surface_refs))
    if len(assertions) > 64 or len(surfaces) > 128:
        raise ValueError("too many isolation assertion or surface references")
    assert_no_secret_material(list(assertions) + list(surfaces), field="refs")

    interactions, unbound = _session_records(adapter, chain)
    truncated = len(interactions) > MAX_INTERACTIONS
    interactions = interactions[:MAX_INTERACTIONS]

    drift = [
        r for r in recorded_drift(store, chain.environment_id)
        if int(r.get("_evidence_seq", -1)) > chain.generation
    ]
    isolation_status = (
        "drift_observed" if drift else "asserted" if assertions else "unknown"
    )

    anchor = _parse_ts(activated["observed_at"]) if activated.get("observed_at") else chain.lease_start
    if interactions:
        anchor = max(_parse_ts(i["observed_at"]) for i in interactions)
    age = max(0.0, (now - anchor).total_seconds())
    fresh = age <= float(max_age)

    head = store.evidence_head_hash(chain.environment_id)
    chain_verified = store.verify_evidence_chain(chain.environment_id)
    evidence_ref_list = list(chain.evidence_refs())
    if head:
        evidence_ref_list.append(f"evidence:{head}")

    limitations = ["virtual_or_local_evidence_not_hil", "tenant_substituted_by_node_id_and_trace_id"]
    if not interactions:
        limitations.append("no_interaction_observed_is_not_evidence_of_safety")
    limitations.extend(f"telemetry_gap:{gap}" for gap in gaps)
    if not fresh:
        limitations.append("stale")
    if mech is not None:
        limitations.append("redirection_does_not_imply_diversion")
    if drift:
        limitations.append("isolation_drift_observed")
    if isolation_status == "unknown":
        limitations.append("isolation_not_asserted")
    if truncated:
        limitations.append("interactions_truncated")
    if unbound:
        limitations.append(f"unbound_interactions_excluded:{unbound}")
    if env_state in _LIVE_STATES:
        limitations.append("runtime_state_not_independently_reverified")

    # EffectObservation: a fact about what AZ-06 materialized.
    if drift:
        status, reason = "failed", "isolation_drift_observed"
    elif env_state == "active":
        status, reason = "active", None
    elif env_state == "terminated":
        status, reason = "terminated", str(state.get("termination_reason") or "environment_terminated")[:200]
    else:
        status, reason = "failed", "environment_" + env_state[:64]
    try:
        effect_observation = observe_effect(
            effect,
            status=status,
            observed_at=_iso(now),
            execution_ref=mech.execution_ref if mech is not None else None,
            termination_reason=reason,
            evidence_refs=evidence_ref_list,
            limitations=limitations,
        )
    except ValueError:
        raise BindingRefused("lease_expired", "effect window does not cover this observation") from None

    terrain = _terrain(
        chain=chain,
        state=state,
        mechanism=mech,
        assertions=assertions,
        surfaces=surfaces,
        surfaces_attested=bool(surfaces) and env_state == "active" and not drift and fresh and chain_verified,
        now=now,
        evidence_refs=tuple(evidence_ref_list[:100]),
    )
    if terrain is None:
        limitations.append("presented_terrain_not_projected")

    confounders = sorted({tag for i in interactions for tag in i.get("confounder_tags", [])})
    window_start = chain.lease_start
    window_end = max(window_start, min(now, chain.lease_end))
    try:
        envelope = OutcomeObservationEnvelope(
            envelope_id="envelope:" + _sha24(
                chain.environment_id, chain.trace_id, chain.effect_ref, chain.session_ref, _iso(now)
            ),
            producer_product="azazel-deception",
            producer_node=chain.node_id,
            producer_version=str(_PRODUCT_VERSION)[:64],
            trace_id=chain.trace_id,
            decision_ref=effect.decision_ref,
            effect_ref=chain.effect_ref,
            environment_ref=f"environment:{chain.environment_id}",
            presentation_ref=terrain["presentation_id"] if terrain else None,
            window_start=_iso(window_start),
            window_end=_iso(window_end),
            observation_class="interaction",
            telemetry_coverage={"expected": expected, "observed": observed},
            coverage_complete=not gaps,
            telemetry_gaps=tuple(gaps),
            confounders=tuple(confounders),
            impact_observations={
                "interaction_count": len(interactions),
                "drift_count": len(drift),
            },
            evidence_refs=tuple(evidence_ref_list),
            observed_at=_iso(now),
            authority_class=AuthorityClass.OBSERVED_FACT,
        )
        terrain_model = PresentedTerrainRef.model_validate(terrain) if terrain else None
        assert_effect_chain_consistent(
            effect, observations=[effect_observation], envelope=envelope, terrain=terrain_model
        )
    except ValueError:
        raise BindingRefused("effect_decision_mismatch", "outcome chain is inconsistent") from None

    bundle: dict[str, Any] = {
        "schema": BUNDLE_SCHEMA,
        "contract_status": "local_container_not_a_contract",
        "reference_chain": chain.to_dict(),
        "decision": {
            "decision_ref": f"decision:{chain.decision_id}",
            "lease": {"start": _iso(chain.lease_start), "end": _iso(chain.lease_end)},
        },
        "execution_request": {
            "kind": "edge_activation_decision",
            "ref": f"decision:{chain.decision_id}",
        },
        "runtime_materialization": {
            "environment_state": env_state,
            "effect_observation": effect_observation.model_dump(mode="json"),
            "presented_terrain": terrain,
        },
        "observed_mechanism": (
            {
                "status": "observed",
                "mechanism_kind": mech.mechanism_kind,
                "producer_product": mech.producer_product,
                "producer_node": mech.producer_node,
                "trace_id": mech.trace_id,
                "decision_ref": mech.decision_ref,
                "execution_ref": mech.execution_ref,
                "mechanism_observation_ref": mech.mechanism_observation_ref,
            }
            if mech is not None
            else {"status": "not_observed_by_az06"}
        ),
        "interactions": interactions,
        "interactions_truncated": truncated,
        "outcome": envelope.model_dump(mode="json"),
        "tactical_assessment": {"status": "not_assessed", "owner": "outside_az06"},
        "freshness": {
            "observed_at": _iso(anchor),
            "age_seconds": age,
            "max_age_seconds": float(max_age),
            "fresh": fresh,
        },
        "isolation": {
            "status": isolation_status,
            "assertion_refs": list(assertions),
            "drift_count": len(drift),
        },
        "limitations": list(dict.fromkeys(limitations)),
        "evidence": {"head_hash": head, "chain_verified": chain_verified},
    }
    _assert_bundle_clean(bundle)
    return bundle


def _assert_bundle_clean(bundle: Mapping[str, Any]) -> None:
    safe = json.loads(json.dumps(bundle, default=str))
    try:
        assert_no_runtime_directives(safe)
        assert_no_effectiveness_verdict(safe)
        assert_no_secret_material(safe, field="bundle")
        for key in (
            "reference_chain", "decision", "execution_request", "observed_mechanism",
            "tactical_assessment", "freshness", "isolation", "evidence", "limitations",
        ):
            assert_bounded_fact_payload(safe[key] if key != "limitations" else {"limitations": safe[key]})
    except ValueError as exc:
        raise BindingRefused("evidence_tampered", f"bundle failed validation: {exc}") from None


# --------------------------------------------------------------------------
# verification


_CHAIN_FIELD_CODE = {
    "objective_ref": "decision_mismatch",
    "hypothesis_refs": "decision_mismatch",
    "frame_ref": "decision_mismatch",
    "decision_id": "decision_mismatch",
    "decision_digest": "decision_mismatch",
    "lease_start": "decision_mismatch",
    "lease_end": "decision_mismatch",
    "trace_id": "effect_decision_mismatch",
    "effect_ref": "effect_decision_mismatch",
    "environment_id": "environment_mismatch",
    "package_id": "package_mismatch",
    "package_digest": "package_mismatch",
    "node_id": "node_mismatch",
    "session_ref": "session_mismatch",
    "generation": "session_mismatch",
}


def verify_feedback_bundle(
    bundle: Mapping[str, Any],
    *,
    expected_chain: ReferenceChain,
    state: Any,
    now: datetime,
    max_age: float,
) -> None:
    """Raise :class:`BindingRefused` unless the bundle still matches the chain and evidence."""

    now = _aware(now)
    store: RuntimeStateStore = getattr(state, "state", state)
    if not isinstance(bundle, Mapping) or bundle.get("schema") != BUNDLE_SCHEMA:
        raise BindingRefused("evidence_tampered", "not a feedback bundle")
    try:
        declared = bundle["reference_chain"]
        expected = expected_chain.to_dict()
        for key, code in _CHAIN_FIELD_CODE.items():
            if declared.get(key) != expected[key]:
                raise BindingRefused(code, f"reference_chain.{key} differs")
        env = expected_chain.environment_id

        if bundle.get("tactical_assessment") != {"status": "not_assessed", "owner": "outside_az06"}:
            raise BindingRefused("evidence_tampered", "tactical assessment must be not_assessed")
        _assert_bundle_clean(bundle)

        materialization = bundle["runtime_materialization"]
        outcome = bundle["outcome"]
        if "telemetry_gaps" not in outcome or "coverage_complete" not in outcome:
            raise BindingRefused("telemetry_missing", "outcome carries no coverage statement")
        try:
            observation = EffectObservation.model_validate(materialization["effect_observation"])
            envelope = OutcomeObservationEnvelope.model_validate(outcome)
            terrain_raw = materialization.get("presented_terrain")
            terrain = PresentedTerrainRef.model_validate(terrain_raw) if terrain_raw else None
        except ValueError:
            raise BindingRefused("evidence_tampered", "bundle wire object invalid") from None
        if expected_chain.effect is not None:
            try:
                assert_effect_chain_consistent(
                    expected_chain.effect,
                    observations=[observation],
                    envelope=envelope,
                    terrain=terrain,
                )
            except ValueError:
                raise BindingRefused("effect_decision_mismatch", "outcome chain inconsistent") from None
        elif observation.effect_ref != expected_chain.effect_ref or envelope.trace_id != expected_chain.trace_id:
            raise BindingRefused("effect_decision_mismatch", "outcome chain inconsistent")

        # Evidence: the chain verifies and the bundle's head is one we wrote.
        if not store.verify_evidence_chain(env):
            raise BindingRefused("evidence_tampered", "evidence hash chain does not verify")
        evidence_decl = bundle["evidence"]
        head = evidence_decl.get("head_hash")
        records = _read_records(store, env)
        if head is not None and head not in {r.get("_evidence_hash") for r in records}:
            raise BindingRefused("evidence_tampered", "bundle evidence head is not in the chain")

        live_claim = observation.status in ("started", "active")
        if live_claim:
            for record in records:
                if (
                    record.get("event_type") == "reset_completed"
                    and int(record.get("_evidence_seq", -1)) > expected_chain.generation
                ):
                    raise BindingRefused("session_reset", "the session was reset")
            activated = _last_activated(records)
            if (
                activated is None
                or _session_ref_of(activated) != expected_chain.session_ref
                or int(activated.get("_evidence_seq", -1)) != expected_chain.generation
            ):
                raise BindingRefused("session_mismatch", "a different session is current")
            if now >= expected_chain.lease_end:
                raise BindingRefused("lease_expired", "decision window has closed")
            if now < expected_chain.lease_start:
                raise BindingRefused("lease_not_started", "decision window has not opened")

        # Interactions must be bound and must be exactly what the chain holds.
        by_id = {}
        for record in records:
            if record.get("schema_version") == _OBSERVATION_SCHEMA:
                by_id[record.get("observation_id")] = {
                    k: v for k, v in record.items() if k not in _EVIDENCE_CHAIN_KEYS
                }
        need = set(expected_chain.evidence_refs())
        for item in bundle["interactions"]:
            if not isinstance(item, Mapping) or not need <= set(item.get("evidence_refs") or ()):
                raise BindingRefused("interaction_unbound", "interaction carries no chain refs")
            if item.get("environment_id") != env:
                raise BindingRefused("environment_mismatch", "interaction is for another environment")
            if item.get("node_id") != expected_chain.node_id:
                raise BindingRefused("node_mismatch", "interaction is for another node")
            if item.get("package_id") != expected_chain.package_id:
                raise BindingRefused("package_mismatch", "interaction is for another package")
            stored = by_id.get(item.get("observation_id"))
            if stored is None:
                raise BindingRefused("evidence_tampered", "interaction is not in the evidence chain")
            try:
                canon = InteractionObservation.model_validate(stored).model_dump(mode="json")
            except ValueError:
                raise BindingRefused("evidence_tampered", "stored interaction invalid") from None
            if canon != dict(item):
                raise BindingRefused("evidence_tampered", "interaction differs from the chain")

        freshness = bundle["freshness"]
        age = (now - _parse_ts(freshness["observed_at"])).total_seconds()
        if age > float(max_age):
            raise BindingRefused("stale", "bundle observations are older than max_age")
    except BindingRefused:
        raise
    except (KeyError, TypeError, AttributeError, ValueError):
        raise BindingRefused("evidence_tampered", "bundle is malformed") from None


def _read_records(store: RuntimeStateStore, environment_id: str) -> list[dict[str, Any]]:
    path = store.evidence_path(environment_id)
    if not path.exists():
        return []
    out = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                record = json.loads(line)
                if isinstance(record, dict):
                    out.append(record)
    except (OSError, ValueError):
        raise BindingRefused("evidence_tampered", "evidence unreadable") from None
    return out


# --------------------------------------------------------------------------
# consumers


def knowledge_ingest_payload(bundle: Mapping[str, Any]) -> dict[str, Any]:
    """The existing Knowledge ``POST /v1/deception-observations`` envelope."""

    items = [
        InteractionObservation.model_validate(item).model_dump(mode="json")
        for item in bundle["interactions"]
    ]
    return {"environment_id": bundle["reference_chain"]["environment_id"], "items": items}


_MIO_OBSERVATION_REFS_CAP = 8


def mio_deception_context(bundle: Mapping[str, Any]) -> dict[str, Any]:
    """A mapping ``MioDeceptionContext.coerce`` accepts (MIO 7a35288 vocabulary).

    Lifecycle is deliberately conservative: anything AZ-06 cannot vouch for
    (drift, a stale bundle, a failed environment) is ``unknown``, never
    ``active``.
    """

    chain = bundle["reference_chain"]
    materialization = bundle["runtime_materialization"]
    env_state = materialization.get("environment_state")
    if not bundle["freshness"]["fresh"] or bundle["isolation"]["status"] == "drift_observed":
        lifecycle = "unknown"
    else:
        lifecycle = {
            "active": "active",
            "terminated": "terminated",
            "reset": "inactive",
        }.get(str(env_state), "unknown")
    refs = [i["observation_id"] for i in bundle["interactions"]][-_MIO_OBSERVATION_REFS_CAP:]
    return {
        "environment_id": chain["environment_id"],
        "package_id": chain["package_id"],
        "node_id": chain["node_id"],
        "lifecycle_state": lifecycle,
        "observation_refs": refs,
    }


# --------------------------------------------------------------------------
# reset


def reset_feedback(adapter: Any, chain: ReferenceChain, *, now: datetime) -> dict[str, Any]:
    """After terminate and reset: confirm the evidence and say what is and is not known.

    Does not terminate or reset anything. Both already happened, through an
    Edge termination decision and ``adapter.reset_environment``.
    """

    now = _aware(now)
    _require_chain_intact(adapter.state, chain.environment_id)
    records = _evidence(adapter, chain.environment_id)
    after = [r for r in records if int(r.get("_evidence_seq", -1)) > chain.generation]
    terminated = [r for r in after if r.get("event_type") == "terminated"]
    resets = [r for r in after if r.get("event_type") == "reset_completed"]
    if not resets or not terminated:
        raise BindingRefused("session_mismatch", "terminate and reset have not both completed")
    if _read_state(adapter, chain.environment_id) is not None:
        raise BindingRefused("session_mismatch", "runtime state still present after reset")
    if chain.effect is None:
        raise BindingRefused("effect_rejected", "chain carries no effect")

    reset_hash = str(resets[-1].get("_evidence_hash", ""))
    reason = str((terminated[-1].get("metadata") or {}).get("reason") or "environment_terminated")
    limitations = [
        "no_interaction_observed_is_not_evidence_of_safety",
        "virtual_or_local_evidence_not_hil",
        "tenant_substituted_by_node_id_and_trace_id",
        "session_ended_observations_after_reset_are_a_new_session",
    ]
    try:
        observation = observe_effect(
            chain.effect,
            status="terminated",
            observed_at=_iso(now),
            termination_reason=reason[:200],
            evidence_refs=[*chain.evidence_refs(), f"evidence:{reset_hash}"],
            limitations=limitations,
        )
    except ValueError:
        raise BindingRefused("effect_decision_mismatch", "effect rejected the observation") from None
    return {
        "reference_chain": chain.to_dict(),
        "effect_observation": observation.model_dump(mode="json"),
        "environment_state": "reset",
        "reset_evidence_seq": int(resets[-1]["_evidence_seq"]),
        "limitations": limitations,
        "tactical_assessment": {"status": "not_assessed", "owner": "outside_az06"},
        "evidence": {
            "head_hash": adapter.state.evidence_head_hash(chain.environment_id),
            "chain_verified": True,
        },
    }
