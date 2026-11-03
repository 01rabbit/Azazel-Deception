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
import hmac
import json
import math
import os
import re
import secrets
import stat
import threading
import dataclasses
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
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
    "mio_frame_inputs",
    "objective_digest",
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
_UNTRUSTED_KEYS = ("untrusted_text_hmac", "untrusted_text_len")
CLOCK_SKEW = timedelta(seconds=5)
MAX_INTERACTION_BYTES = 8192
MAX_BUNDLE_BYTES = 2_500_000
MAX_EXTRA_EVIDENCE_REFS = 16
MAX_METADATA_KEYS = 16
#: The only metadata keys a caller may set. Anything else is attacker-shaped
#: until proven otherwise. ``outside_lease`` and the untrusted keys are set by this module only.
ALLOWED_METADATA_KEYS = frozenset(
    {
        "protocol", "port", "service_kind", "request_count", "byte_count",
        "duration_ms", "status_class", "sensor_id",
    }
)
_METADATA_STRING = re.compile(r"[A-Za-z0-9._:-]{1,64}")
_TELEMETRY_NAME = re.compile(r"[A-Za-z0-9._:-]{1,64}")
_SAFE_ENV = re.compile(r"[A-Za-z0-9._-]{1,128}")
_OBJECTIVE_DIGEST_PREFIX = "mio-objective-digest-"
_OPAQUE = re.compile(r"[A-Za-z0-9._~@=+:-]{1,200}")

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
    if body.startswith(_OBJECTIVE_DIGEST_PREFIX):
        raise ObjectiveRejected(f"{field_name} must not look like an objective digest reference")
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


def objective_digest(objective: MioObservationObjective) -> str:
    """Canonical content digest of an objective (``sha256:<hex64>``)."""

    canonical = json.dumps(
        {
            "objective_ref": objective.objective_ref,
            "hypothesis_refs": list(objective.hypothesis_refs),
            "frame_ref": objective.frame_ref,
            "desired_observations": [list(item) for item in objective.desired_observations],
            "authority": objective.authority,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _digest_ref(digest: str) -> str:
    return f"advisory:{_OBJECTIVE_DIGEST_PREFIX}{digest.split(':', 1)[1][:32]}"


@dataclass(frozen=True)
class AdmittedObjective:
    """This objective may be bound to this decision. Not an exposure grant.

    ``objective_content_bound`` is True only when the signed decision carried a
    digest reference matching this objective's content. Otherwise only the
    reference names are bound, not what the objective asks for.
    """

    objective: MioObservationObjective
    decision_id: str
    decision_digest: str
    objective_digest: str = ""
    objective_content_bound: bool = False


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
    digest = objective_digest(objective)
    digest_refs = [r for r in decision.evidence_refs if r.startswith(f"advisory:{_OBJECTIVE_DIGEST_PREFIX}")]
    if digest_refs and _digest_ref(digest) not in digest_refs:
        return AdvisoryRetained(objective, "objective_not_in_authenticated_decision")
    return AdmittedObjective(
        objective=objective,
        decision_id=decision.decision_id,
        decision_digest=_decision_digest(signed_activation_decision),
        objective_digest=digest,
        objective_content_bound=bool(digest_refs),
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
    #: Content digest of the admitted objective, and whether the signed
    #: decision bound that content (a digest ref) or only the reference names.
    objective_digest: str = ""
    objective_content_bound: bool = False
    #: The accepted Edge effect, kept so observations can be chain-checked
    #: against it. Not part of identity or the serialized chain. Note the
    #: effect's ``trace_id`` is not authenticated by the decision HMAC.
    effect: Any = field(default=None, repr=False, compare=False)
    #: Keyed seal (HMAC, per-session key) over ``to_dict()``, set only by
    #: ``bind_reference_chain``. Every consumer re-derives it, so a chain whose
    #: fields were changed by ``dataclasses.replace`` or direct construction is
    #: refused. Not part of the serialized chain or the wire format.
    seal: str = field(default="", repr=False, compare=False)

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
            "objective_digest": self.objective_digest,
            "objective_content_bound": self.objective_content_bound,
        }


def _read_records(store: RuntimeStateStore, environment_id: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    try:
        snapshot = store.read_evidence_snapshot(environment_id)
        if snapshot is None:
            return []
        for line in snapshot.splitlines():
            if line.strip():
                record = json.loads(line)
                if isinstance(record, dict):
                    out.append(record)
    except (OSError, ValueError):
        raise BindingRefused("evidence_tampered", "evidence unreadable") from None
    return out


def _evidence(adapter: Any, environment_id: str) -> list[dict[str, Any]]:
    return _read_records(adapter.state, environment_id)


def _seq(record: Mapping[str, Any]) -> int:
    try:
        return int(record.get("_evidence_seq", -1))
    except (TypeError, ValueError):
        return -1


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
    Nothing here activates or consumes anything, and the runtime state is never
    written. The one thing it records is which effect this decision was bound
    to, as an exclusively-created file under ``mio_bindings/``, so that a
    decision binds one effect only even when two binds race.
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
    digest = objective_digest(admitted.objective)
    if admitted.objective_digest and admitted.objective_digest != digest:
        raise BindingRefused("decision_mismatch", "objective content changed after admission")
    # Binding is derived from the authenticated decision, never from the
    # caller-supplied AdmittedObjective flag: a directly constructed admission
    # cannot claim content binding the signed decision does not carry.
    signed_digest_refs = [
        r for r in decision.evidence_refs if r.startswith(f"advisory:{_OBJECTIVE_DIGEST_PREFIX}")
    ]
    content_bound = bool(signed_digest_refs)
    if content_bound and _digest_ref(digest) not in signed_digest_refs:
        raise BindingRefused("decision_mismatch", "decision does not bind this objective content")
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
    if state.get("environment_id") != environment_id:
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
    _bind_effect_once(adapter.state, decision.decision_id, effect.effect_id)

    chain = ReferenceChain(
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
        objective_digest=digest,
        objective_content_bound=content_bound,
        effect=effect,
    )
    seal = _chain_seal(adapter.state, chain, create=True)
    return dataclasses.replace(chain, seal=seal)


def _chain_seal(store: RuntimeStateStore, chain: ReferenceChain, *, create: bool) -> str:
    """HMAC of the chain's serialized fields under the per-session protected key."""

    # Exactly Fabric's DefensiveEffectRef: a subclass or duck-typed stand-in can
    # reproduce model_dump() while its attributes (read by consumers) differ.
    if type(chain.effect) is not DefensiveEffectRef:
        raise BindingRefused("evidence_tampered", "reference chain effect is not a Fabric effect")
    effect = chain.effect.model_dump(mode="json")
    payload = "mio_chain_seal_v1\n" + _canon({"chain": chain.to_dict(), "effect": effect})
    key = _untrusted_key(store, chain, create=create)
    return hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def _require_sealed(store: RuntimeStateStore, chain: Any) -> None:
    """Refuse any chain not exactly as ``bind_reference_chain`` sealed it.

    Covers caller-mutated fields (``dataclasses.replace`` keeps the old seal),
    hand-built chains (no seal), and a missing session key. Fail closed.
    """

    if not isinstance(chain, ReferenceChain) or not isinstance(chain.seal, str) or not chain.seal:
        raise BindingRefused("evidence_tampered", "reference chain is not sealed")
    try:
        expected = _chain_seal(store, chain, create=False)
    except BindingRefused:
        raise
    except (AttributeError, OSError, TypeError, ValueError) as exc:
        raise BindingRefused("evidence_tampered", "reference chain cannot be verified") from exc
    if not hmac.compare_digest(expected, chain.seal):
        raise BindingRefused("evidence_tampered", "reference chain was altered")


def _private_dir(path: Path, *, create: bool = True) -> None:
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        info = os.lstat(path)
    except OSError:
        raise BindingRefused("evidence_tampered", f"private directory missing: {path.name}") from None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise BindingRefused("evidence_tampered", f"{path.name} is not a plain directory")
    if info.st_uid != os.getuid():
        raise BindingRefused(
            "evidence_tampered", f"{path.name} is owned by another user (chown it to the service user)"
        )
    if stat.S_IMODE(info.st_mode) != 0o700:
        raise BindingRefused(
            "evidence_tampered",
            f"{path.name} mode is {oct(stat.S_IMODE(info.st_mode))}, expected 0o700 (chmod 700)",
        )


def _create_once(path: Path, data: bytes) -> bool:
    """Atomically create ``path`` (0600) with complete content; False if it exists."""

    tmp = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as exc:
        raise BindingRefused("evidence_tampered", f"cannot create private file: {exc.strerror}") from None
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(tmp, path)
        except FileExistsError:
            return False
        return True
    except OSError as exc:
        raise BindingRefused(
            "evidence_tampered", f"cannot create private file (hard links required): {exc.strerror}"
        ) from None
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _read_private(path: Path) -> bytes:
    info = os.lstat(path)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise BindingRefused("evidence_tampered", "private file has unexpected type, owner or mode")
    return path.read_bytes()


def _bind_effect_once(store: RuntimeStateStore, decision_id: str, effect_id: str) -> None:
    directory = store.root / "mio_bindings"
    _private_dir(directory)
    path = directory / hashlib.sha256(decision_id.encode("utf-8")).hexdigest()[:32]
    if _create_once(path, effect_id.encode("utf-8")):
        return
    if _read_private(path).decode("utf-8", errors="replace") != effect_id:
        raise BindingRefused("effect_rejected", "this decision is already bound to another effect")


def _check_state_identity(state: Mapping[str, Any], chain: ReferenceChain) -> None:
    if state.get("environment_id") != chain.environment_id:
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


def _check_live_session(adapter: Any, chain: ReferenceChain) -> Mapping[str, Any]:
    """Refuse unless ``chain`` is still the live session. Returns the activated record.

    The lease is deliberately not checked here: an observation outside the
    lease is recorded and marked, not refused.
    """

    _require_chain_intact(adapter.state, chain.environment_id)
    records = _evidence(adapter, chain.environment_id)
    for record in records:
        if record.get("event_type") == "reset_completed" and _seq(record) > chain.generation:
            raise BindingRefused("session_reset", "the session was reset")
    activated = _last_activated(records)
    if (
        activated is None
        or _seq(activated) != chain.generation
        or _session_ref_of(activated) != chain.session_ref
    ):
        raise BindingRefused("session_mismatch", "a different session is current")
    state = _read_state(adapter, chain.environment_id)
    if state is None:
        raise BindingRefused("session_mismatch", "no runtime state")
    _check_state_identity(state, chain)
    if state.get("state") not in _LIVE_STATES:
        raise BindingRefused("session_mismatch", "environment is not active")
    return activated


# --------------------------------------------------------------------------
# bound observer


def _untrusted_key(store: RuntimeStateStore, chain: ReferenceChain, *, create: bool = True) -> bytes:
    """Per-session random key, kept beside (not in) the evidence chain.

    Created atomically with complete content, read back only if it is a regular
    0600 file of ours holding exactly 32 bytes. It is never discarded on reset:
    digests recorded earlier must stay checkable.
    """

    if not _SAFE_ENV.fullmatch(chain.environment_id):
        raise ValueError("environment id is not usable as a key file name")
    directory = store.root / "mio_feedback_keys"
    if not create and not directory.exists():
        raise BindingRefused("evidence_tampered", "session key missing")
    _private_dir(directory, create=create)
    path = directory / f"{chain.environment_id}.s{chain.generation}.key"
    if create:
        _create_once(path, secrets.token_hex(32).encode("ascii"))
    elif not path.exists():
        raise BindingRefused("evidence_tampered", "session key missing")
    raw = _read_private(path).strip()
    try:
        key = bytes.fromhex(raw.decode("ascii"))
    except (ValueError, UnicodeDecodeError):
        raise BindingRefused("evidence_tampered", "session key is malformed") from None
    if len(key) != 32:
        raise BindingRefused("evidence_tampered", "session key has the wrong length")
    return key


def _clean_metadata(metadata: Mapping[str, Any] | None) -> dict[str, Any]:
    meta: dict[str, Any] = {}
    for key, value in dict(metadata or {}).items():
        if key in _UNTRUSTED_KEYS:
            continue  # reserved: set only from untrusted_text
        if key not in ALLOWED_METADATA_KEYS:
            raise ValueError(f"metadata key {key!r} is not in the allow-list")
        if isinstance(value, bool):
            pass
        elif isinstance(value, int):
            if abs(value) > 10**15:
                raise ValueError("metadata integer out of range")
        elif isinstance(value, float):
            if not math.isfinite(value) or abs(value) > 1e15:
                raise ValueError("metadata number out of range")
        elif isinstance(value, str):
            if not _METADATA_STRING.fullmatch(value):
                raise ValueError("metadata string must match [A-Za-z0-9._:-]{1,64}")
        else:
            raise ValueError("metadata values must be bool, number or a short token")
        meta[key] = value
    if len(meta) > MAX_METADATA_KEYS:
        raise ValueError("too many metadata keys")
    return meta


def _package_lure_ids(package: Any) -> frozenset[str]:
    credentials = (
        package.get("credentials") if isinstance(package, Mapping) else getattr(package, "credentials", None)
    )
    ids = set()
    for item in credentials or ():
        value = item.get("credential_id") if isinstance(item, Mapping) else getattr(item, "credential_id", None)
        if isinstance(value, str):
            ids.add(value)
    return frozenset(ids)


_RECORD_LOCKS_GUARD = threading.Lock()
_RECORD_LOCKS: dict[str, threading.Lock] = {}


class BoundObserver:
    """Records interactions through the existing observer, stamped with the chain."""

    def __init__(
        self, adapter: Any, chain: ReferenceChain, observer: Any, now_fn: Any, lure_ids: frozenset[str]
    ) -> None:
        _require_sealed(adapter.state, chain)
        self._adapter = adapter
        self._chain = chain
        self._observer = observer
        self._now_fn = now_fn
        self._lure_ids = lure_ids
        # Ids come from the session and the evidence sequence, never from a
        # per-observer counter: two observers (or a re-created one) cannot
        # collide, and a reset/re-activation is a different session.
        observer._next_observation_id = self._next_id

    @property
    def chain(self) -> ReferenceChain:
        return self._chain

    def _next_id(self) -> str:
        records = _evidence(self._adapter, self._chain.environment_id)
        nxt = (_seq(records[-1]) + 1) if records else 0
        return f"{self._chain.environment_id}-s{self._chain.generation}-obs-{nxt:06d}"

    def _locked(self) -> Any:
        key = os.path.realpath(self._adapter.state.evidence_path(self._chain.environment_id))
        with _RECORD_LOCKS_GUARD:
            return _RECORD_LOCKS.setdefault(key, threading.Lock())

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
        when = _aware(observed_at, name="observed_at") if observed_at is not None else now
        activated = _check_live_session(self._adapter, self._chain)
        if when > now + CLOCK_SKEW:
            raise BindingRefused("stale", "observed_at is in the future")
        if when < _parse_ts(activated["observed_at"]) - CLOCK_SKEW:
            raise BindingRefused("session_mismatch", "observed_at precedes this session")

        meta = _clean_metadata(metadata)
        if lure_id is not None and (
            not isinstance(lure_id, str)
            or not _METADATA_STRING.fullmatch(lure_id)
            or lure_id not in self._lure_ids
        ):
            raise ValueError("lure_id does not name a lure of this package")
        if untrusted_text is not None:
            if not isinstance(untrusted_text, str):
                raise TypeError("untrusted_text must be a string")
            meta["untrusted_text_len"] = len(untrusted_text)
            if surface != "credential_lure":
                # Keyed, so a low-entropy secret cannot be recovered from the
                # evidence by hashing guesses. A lure surface keeps no digest.
                key = _untrusted_key(self._adapter.state, self._chain)
                meta["untrusted_text_hmac"] = hmac.new(
                    key, untrusted_text.encode("utf-8", errors="replace"), hashlib.sha256
                ).hexdigest()
        outside = when < self._chain.lease_start or max(now, when) >= self._chain.lease_end
        if outside:
            meta["outside_lease"] = True
        assert_no_secret_material(meta, field="metadata")

        extra = list(evidence_refs or [])
        if len(extra) > MAX_EXTRA_EVIDENCE_REFS or any(
            not isinstance(ref, str) or not _OPAQUE.fullmatch(ref) for ref in extra
        ):
            raise ValueError("evidence_refs must be at most 16 short opaque references")
        assert_no_secret_material(extra, field="evidence_refs")
        refs = list(dict.fromkeys([*extra, *self._chain.evidence_refs()]))
        # Numbering and appending happen under one lock, so concurrent records
        # of this process cannot draw the same evidence sequence.
        with self._locked():
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

    _require_sealed(adapter.state, chain)
    if isinstance(package, Mapping):
        package = adapter.validate_package(dict(package))
    if isinstance(placement, Mapping):
        placement = PlacementPlan.model_validate(dict(placement))
    observer = adapter.make_observer(chain.environment_id, package, placement)
    # A missing attribute is a mismatch, not a pass.
    if getattr(observer, "node_id", None) != chain.node_id:
        raise BindingRefused("node_mismatch", "placement node differs from the chain")
    if getattr(observer, "package_id", None) != chain.package_id:
        raise BindingRefused("package_mismatch", "package differs from the chain")
    return BoundObserver(adapter, chain, observer, now_fn, _package_lure_ids(package))


# --------------------------------------------------------------------------
# bundle derivation (shared by build and verify)


def _names(value: Any, *, name: str) -> list[str]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise BindingRefused("telemetry_missing", f"{name} must be a collection of names")
    out = []
    for item in value:
        if not isinstance(item, str) or not _TELEMETRY_NAME.fullmatch(item):
            raise BindingRefused("telemetry_missing", f"{name} holds an invalid name")
        out.append(item)
    return sorted(set(out))


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
    effect_decision = chain.effect.decision_ref if chain.effect is not None else None
    if evidence.trace_id != chain.trace_id or evidence.decision_ref not in (
        f"decision:{chain.decision_id}",
        effect_decision,
    ):
        raise BindingRefused(
            "effect_decision_mismatch", "mechanism evidence is for another trace or decision"
        )
    return evidence


def _terrain(
    *,
    chain: ReferenceChain,
    env_state: str,
    activated_at: str,
    ended_at: str | None,
    reset_ref: str | None,
    mechanism: ProducerRedirectionEvidence | None,
    assertions: tuple[str, ...],
    now: datetime,
    evidence_refs: tuple[str, ...],
) -> dict[str, Any] | None:
    """Presented-terrain ref, or ``None`` when AZ-06 does not hold what it needs."""

    effect = chain.effect
    if not assertions:
        return None
    expires = min(chain.lease_end, _parse_ts(effect.expires_at))
    if mechanism is None:
        # Without Edge mechanism evidence there is no #31 snapshot/projection gate to
        # pass, so no terrain is claimed: never ACTIVE_MATERIALIZED or active surfaces
        # built from caller-declared strings.
        return None
    try:
        runtime_state = {
            "environment_id": chain.environment_id,
            "state": env_state,
            "package_id": chain.package_id,
            "package_digest": chain.package_digest,
            "node_id": chain.node_id,
            "activated_at": activated_at,
        }
        if env_state in ("terminated", "reset"):
            runtime_state["terminated_at"] = ended_at
        snapshot = build_presented_terrain_snapshot(
            environment_id=chain.environment_id,
            producer=mechanism,
            runtime_state=runtime_state,
            expected_package_id=chain.package_id,
            expected_package_digest=chain.package_digest,
            package_version="not_recorded",
            observed_at=_iso(now),
            # Caller-declared surfaces are not carried on this unverified path.
            active_surface_refs=(),
            isolation_assertion_refs=assertions[:1],
            reset_ref=reset_ref if env_state == "reset" else None,
            # Current mechanism evidence alone does not independently verify
            # runtime or isolation, and AZ-06 has no real verifier input yet. A
            # persisted "active" therefore projects as a stale snapshot
            # (runtime_active_not_independently_verified) with no active surfaces.
            runtime_verified_active=False,
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
    except EffectRefRejected:
        raise BindingRefused(
            "effect_decision_mismatch", "terrain cannot be bound to this effect"
        ) from None
    except (EffectProjectionRefused, ValueError):
        return None


def _objective_coverage(
    objective: MioObservationObjective | None,
    chain: ReferenceChain,
    interactions: list[dict[str, Any]],
    *,
    observed: list[str],
    surface_telemetry: Mapping[str, str],
) -> dict[str, Any]:
    counts: dict[str, int] = {}
    confounders: dict[str, int] = {}
    for item in interactions:
        key = f"{item['observation_class']}:{item['surface']}"
        counts[key] = counts.get(key, 0) + 1
        for tag in item.get("confounder_tags", []):
            confounders[tag] = confounders.get(tag, 0) + 1
    section: dict[str, Any] = {
        "coverage_basis": "caller_declared",
        "counts_by_class_surface": dict(sorted(counts.items())),
        "confounder_counts": dict(sorted(confounders.items())),
    }
    if objective is None:
        section["status"] = "objective_not_supplied"
        section["entries"] = []
        section["desired_observations"] = []
        return section
    entries = []
    for hypothesis in objective.hypothesis_refs:
        for observation_class, surface in objective.desired_observations:
            matching = [
                i
                for i in interactions
                if i["observation_class"] == observation_class and i["surface"] == surface
            ]
            ids = [i["observation_id"] for i in matching]
            confounded = [i for i in matching if i.get("confounder_tags")]
            outside_lease = [i for i in matching if i.get("metadata", {}).get("outside_lease") is True]
            clean = [i for i in matching if i not in confounded and i not in outside_lease]
            if clean:
                status = "observed"
            elif matching:
                # Contact happened, but never in a form that can be read as the
                # desired observation: noise-tagged, or outside the lease.
                inside = [i for i in matching if i not in outside_lease]
                status = "observed_confounded_only" if inside else "observed_outside_lease_only"
            else:
                name = surface_telemetry.get(surface)
                if name is None:
                    status = f"undeterminable_unmapped_surface:{surface}"
                elif name in observed:
                    status = "not_observed_with_coverage"
                else:
                    status = f"undeterminable_telemetry_gap:{name}"
            entries.append(
                {
                    "hypothesis_ref": hypothesis,
                    "observation_class": observation_class,
                    "surface": surface,
                    "status": status,
                    "observed_count": len(matching),
                    "confounded_count": len(confounded),
                    "outside_lease_count": len(outside_lease),
                    "observation_ids": ids[:8],
                    "truncated": len(ids) > 8,
                }
            )
    section["status"] = "evaluated"
    section["objective_ref"] = objective.objective_ref
    section["frame_ref"] = objective.frame_ref
    section["desired_observations"] = [list(item) for item in objective.desired_observations]
    section["entries"] = entries
    section["limitations"] = ["desired_observations_not_hypothesis_specific"]
    return section


def _declared_mac(
    store: RuntimeStateStore, chain: ReferenceChain, declared: Mapping[str, Any], *, create: bool = True
) -> str:
    """HMAC over the caller's declarations, under the session key.

    It detects a declaration rewritten after build. It cannot say the
    declaration was true: that was the build caller's word.
    """

    canonical = json.dumps(declared, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(_untrusted_key(store, chain, create=create), canonical, hashlib.sha256).hexdigest()


def _derive(
    store: RuntimeStateStore,
    chain: ReferenceChain,
    *,
    now: datetime,
    max_age: float,
    expected: list[str],
    observed: list[str],
    assertions: tuple[str, ...],
    surfaces: tuple[str, ...],
    surface_telemetry: Mapping[str, str],
    objective: MioObservationObjective | None,
    mech: ProducerRedirectionEvidence | None,
    upto_seq: int | None,
) -> dict[str, Any]:
    """Rebuild the bundle from evidence alone (plus the caller-declared inputs)."""

    effect: DefensiveEffectRef | None = chain.effect
    if effect is None:
        raise BindingRefused("effect_rejected", "chain carries no effect")
    env = chain.environment_id
    all_records = _read_records(store, env)
    records = [r for r in all_records if upto_seq is None or _seq(r) <= upto_seq]
    if not records:
        raise BindingRefused("evidence_tampered", "no evidence")
    head = str(records[-1].get("_evidence_hash") or "")

    activated = next((r for r in records if _seq(r) == chain.generation), None)
    if (
        activated is None
        or activated.get("event_type") != "activated"
        or _session_ref_of(activated) != chain.session_ref
        or activated.get("environment_id") != env
        or (activated.get("metadata") or {}).get("decision_id") != chain.decision_id
    ):
        raise BindingRefused("session_mismatch", "this session is not in the evidence chain")
    activated_ts = _parse_ts(activated.get("observed_at"))
    activated_at = _iso(activated_ts)  # 3.10 cannot parse the "Z" Fabric dumps

    post = [r for r in records if _seq(r) > chain.generation]
    if any(r.get("event_type") == "activated" for r in post):
        raise BindingRefused("session_mismatch", "the environment was activated again")
    terminated = [r for r in post if r.get("event_type") == "terminated"]
    resets = [r for r in post if r.get("event_type") == "reset_completed"]
    lifecycle_failures = [
        r for r in post
        if r.get("event_type") == "failure"
        and (r.get("metadata") or {}).get("stage") in ("activation", "termination")
    ]
    if resets:
        env_state = "reset"
    elif terminated:
        env_state = "terminated"
    elif lifecycle_failures:
        env_state = "failed"
    else:
        env_state = "active"

    # interactions: bound ones only, ids unique, times inside the session.
    need = set(chain.evidence_refs())
    interactions: list[dict[str, Any]] = []
    unbound = 0
    seen_ids: set[str] = set()
    for record in post:
        if record.get("schema_version") != _OBSERVATION_SCHEMA:
            continue
        canonical = {k: v for k, v in record.items() if k not in _EVIDENCE_CHAIN_KEYS}
        try:
            observation = InteractionObservation.model_validate(canonical)
        except ValueError:
            raise BindingRefused("evidence_tampered", "stored interaction is invalid") from None
        if not need <= set(observation.evidence_refs):
            unbound += 1
            continue
        dumped = observation.model_dump(mode="json")
        if len(json.dumps(dumped, separators=(",", ":"))) > MAX_INTERACTION_BYTES:
            raise BindingRefused("evidence_tampered", "stored interaction exceeds its byte bound")
        if observation.observation_id in seen_ids:
            raise BindingRefused("evidence_tampered", "duplicate observation id")
        seen_ids.add(observation.observation_id)
        at = _utc(observation.observed_at)
        if at < activated_ts - CLOCK_SKEW or at > now + CLOCK_SKEW:
            raise BindingRefused("evidence_tampered", "interaction time is outside the session")
        interactions.append(dumped)
    truncated = len(interactions) > MAX_INTERACTIONS
    interactions = interactions[:MAX_INTERACTIONS]
    outside = sum(1 for i in interactions if i.get("metadata", {}).get("outside_lease") is True)

    drift = [
        r for r in recorded_drift(store, env)
        if chain.generation < _seq(r) and (upto_seq is None or _seq(r) <= upto_seq)
    ]
    isolation_status = "drift_observed" if drift else "asserted" if assertions else "unknown"

    anchor = max([activated_ts, *[_utc(_parse_ts(i["observed_at"])) for i in interactions]])
    raw_age = (now - anchor).total_seconds()
    if raw_age < -CLOCK_SKEW.total_seconds():
        raise BindingRefused("stale", "newest evidence is in the future")
    age = max(0.0, raw_age)
    fresh = age <= float(max_age)

    gaps = sorted(set(expected) - set(observed))
    lease_closed = now >= chain.lease_end
    if env_state == "active" and now < chain.lease_start:
        raise BindingRefused("lease_not_started", "decision window has not opened")
    lease_overrun = env_state == "active" and lease_closed

    evidence_ref_list = list(chain.evidence_refs()) + [f"evidence:{head}"]
    limitations = ["virtual_or_local_evidence_not_hil", "tenant_substituted_by_node_id_and_trace_id"]
    if not chain.objective_content_bound:
        limitations.append("objective_content_not_bound")
    if objective is None:
        limitations.append("objective_not_supplied")
    else:
        limitations.append("desired_observations_not_hypothesis_specific")
    if not interactions:
        limitations.append("no_interaction_observed_is_not_evidence_of_safety")
    limitations.extend(f"telemetry_gap:{gap}" for gap in gaps)
    if not fresh:
        limitations.append("stale")
    if lease_closed:
        limitations.append("lease_expired")
    if lease_overrun:
        limitations.append("runtime_active_after_lease_end")
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
    if outside:
        limitations.append(f"interactions_outside_lease:{outside}")
    if env_state == "active":
        limitations.append("runtime_state_not_independently_reverified")
    # Persisted "active" with no drift and no lease overrun: no independent runtime
    # verifier exists, so no effect observation is emitted (not even "active" or an
    # unknown stand-in). The bundle carries an explicit limitation instead.
    if env_state == "active" and not drift and not lease_overrun:
        limitations.append("effect_observation_withheld_not_independently_verified")
    if env_state == "reset":
        limitations.append("session_ended_new_observations_belong_to_a_new_session")

    terminated_reason = (
        str((terminated[-1].get("metadata") or {}).get("reason") or "environment_terminated")[:200]
        if terminated else None
    )
    ended_at = _iso(_parse_ts((resets or terminated)[-1]["observed_at"])) if (resets or terminated) else None
    reset_ref = f"evidence:{resets[-1].get('_evidence_hash')}" if resets else None
    terrain = _terrain(
        chain=chain, env_state=env_state, activated_at=activated_at, ended_at=ended_at,
        reset_ref=reset_ref, mechanism=mech, assertions=assertions,
        now=now, evidence_refs=tuple(evidence_ref_list[:100]),
    )
    if terrain is None:
        limitations.append("presented_terrain_not_projected")

    # None only for a persisted "active" with no failure fact (no drift, no lease overrun).
    status: str | None
    reason: str | None
    if drift:
        status, reason = "failed", "isolation_drift_observed"
    elif lease_overrun:
        status, reason = "failed", "lease_expired_runtime_still_active"
    elif env_state == "active":
        status, reason = None, None
    elif env_state in ("terminated", "reset"):
        status, reason = "terminated", terminated_reason or "environment_reset"
    else:
        status, reason = "failed", "environment_failed"
    effect_observation = None
    if status is not None:
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
            raise BindingRefused("effect_rejected", "effect window does not cover this observation") from None
    elif now > _parse_ts(effect.expires_at):
        # Withhold the live observation, but preserve the effect's own expiry
        # boundary. Previously observe_effect rejected this same live status.
        raise BindingRefused("effect_rejected", "effect window does not cover this observation")

    coverage = _objective_coverage(
        objective, chain, interactions, observed=observed, surface_telemetry=surface_telemetry
    )
    confounders = sorted({tag for i in interactions for tag in i.get("confounder_tags", [])})
    window_start = chain.lease_start
    window_end = max(window_start, min(now, chain.lease_end))
    try:
        envelope = OutcomeObservationEnvelope(
            envelope_id="envelope:" + _sha24(env, chain.trace_id, chain.effect_ref, chain.session_ref, _iso(now)),
            producer_product="azazel-deception",
            producer_node=chain.node_id,
            producer_version=str(_PRODUCT_VERSION)[:64],
            trace_id=chain.trace_id,
            decision_ref=effect.decision_ref,
            effect_ref=chain.effect_ref,
            environment_ref=f"environment:{env}",
            presentation_ref=terrain["presentation_id"] if terrain else None,
            window_start=_iso(window_start),
            window_end=_iso(window_end),
            observation_class="interaction",
            telemetry_coverage={"expected": expected, "observed": observed},
            coverage_complete=not gaps,
            telemetry_gaps=tuple(gaps),
            confounders=tuple(confounders),
            impact_observations={"interaction_count": len(interactions), "drift_count": len(drift)},
            evidence_refs=tuple(evidence_ref_list),
            observed_at=_iso(now),
            authority_class=AuthorityClass.OBSERVED_FACT,
        )
        terrain_model = PresentedTerrainRef.model_validate(terrain) if terrain else None
        assert_effect_chain_consistent(
            effect,
            observations=[] if effect_observation is None else [effect_observation],
            envelope=envelope,
            terrain=terrain_model,
        )
    except ValueError:
        raise BindingRefused("effect_decision_mismatch", "outcome chain is inconsistent") from None

    caller_declared = {
        "expected_telemetry": expected,
        "observed_telemetry": observed,
        "isolation_assertion_refs": list(assertions),
        "active_surface_refs": list(surfaces),
        "surface_telemetry": dict(sorted(surface_telemetry.items())),
    }
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
            "activated_evidence_seq": chain.generation,
            "activated_evidence_hash": str(activated.get("_evidence_hash")),
        },
        "caller_declared": caller_declared,
        "caller_declared_mac": _declared_mac(store, chain, caller_declared),
        "runtime_materialization": {
            "environment_state": env_state,
            "effect_observation": (
                None if effect_observation is None else effect_observation.model_dump(mode="json")
            ),
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
        "objective_coverage": coverage,
        "outcome": envelope.model_dump(mode="json"),
        "tactical_assessment": {"status": "not_assessed", "owner": "outside_az06"},
        "freshness": {
            "observed_at": _iso(anchor),
            "age_seconds": age,
            "max_age_seconds": float(max_age),
            "fresh": fresh,
            "anchor_kind": "last_interaction" if interactions else "activation",
        },
        "isolation": {
            "status": isolation_status,
            "assertion_refs": list(assertions),
            "drift_count": len(drift),
        },
        "limitations": list(dict.fromkeys(limitations)),
        "evidence": {"head_hash": head, "chain_verified": True},
    }
    _assert_bundle_clean(bundle)
    return bundle


def _assert_bundle_clean(bundle: Mapping[str, Any]) -> None:
    safe = json.loads(json.dumps(bundle, default=str))
    if len(json.dumps(safe, separators=(",", ":"))) > MAX_BUNDLE_BYTES:
        raise BindingRefused("evidence_tampered", "bundle exceeds its byte bound")
    try:
        assert_no_runtime_directives(safe)
        assert_no_effectiveness_verdict(safe)
        assert_no_secret_material(safe, field="bundle")
        for key, value in safe.items():
            if key == "interactions":
                for item in value:
                    assert_bounded_fact_payload(item)
            elif isinstance(value, (dict, list)):
                assert_bounded_fact_payload(value if isinstance(value, dict) else {key: value})
    except ValueError as exc:
        raise BindingRefused("evidence_tampered", f"bundle failed validation: {exc}") from None


def _surface_map(value: Mapping[str, str] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for surface, name in dict(value or {}).items():
        if surface not in _SURFACES or not isinstance(name, str) or not _TELEMETRY_NAME.fullmatch(name):
            raise BindingRefused("telemetry_missing", "surface_telemetry holds an invalid entry")
        out[surface] = name
    return out


def _ref_tuple(values: Sequence[str], limit: int, name: str) -> tuple[str, ...]:
    out = tuple(dict.fromkeys(values))
    if len(out) > limit or any(not isinstance(v, str) or not _OPAQUE.fullmatch(v) for v in out):
        raise ValueError(f"{name} must hold at most {limit} short opaque references")
    assert_no_secret_material(list(out), field=name)
    return out


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
    objective: MioObservationObjective | None = None,
    surface_telemetry: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Collect what AZ-06 observed into a local, bounded, verdict-free container.

    ``surface_telemetry`` maps a desired surface to the telemetry name that
    would have shown it. It is declared by the caller (``coverage_basis`` says
    so); AZ-06 cannot verify what the sensors cover.
    """

    now = _aware(now)
    expected = _names(expected_telemetry, name="expected_telemetry")
    observed = _names(observed_telemetry, name="observed_telemetry")
    if not expected:
        raise BindingRefused(
            "telemetry_missing", "expected_telemetry must say what coverage was expected"
        )
    store: RuntimeStateStore = adapter.state
    _require_sealed(store, chain)
    _require_chain_intact(store, chain.environment_id)
    records = _read_records(store, chain.environment_id)
    # Identity against the runtime state while it exists; after reset it is gone.
    state = _read_state(adapter, chain.environment_id)
    if state is not None:
        _check_state_identity(state, chain)
    elif not any(r.get("event_type") == "reset_completed" and _seq(r) > chain.generation for r in records):
        raise BindingRefused("session_mismatch", "no runtime state")
    if objective is not None and objective_digest(objective) != chain.objective_digest:
        raise BindingRefused("decision_mismatch", "objective is not the one admitted")
    mech = _runtime_mechanism(mechanism, chain)
    bundle = _derive(
        store, chain, now=now, max_age=max_age, expected=expected, observed=observed,
        assertions=_ref_tuple(isolation_assertion_refs, 64, "isolation_assertion_refs"),
        surfaces=_ref_tuple(active_surface_refs, 128, "active_surface_refs"),
        surface_telemetry=_surface_map(surface_telemetry), objective=objective, mech=mech,
        upto_seq=None,
    )
    if state is not None and state.get("state") != bundle["runtime_materialization"]["environment_state"]:
        raise BindingRefused("evidence_tampered", "runtime state disagrees with the evidence")
    return bundle


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
    "objective_digest": "decision_mismatch",
    "objective_content_bound": "decision_mismatch",
    "trace_id": "effect_decision_mismatch",
    "effect_ref": "effect_decision_mismatch",
    "environment_id": "environment_mismatch",
    "package_id": "package_mismatch",
    "package_digest": "package_mismatch",
    "node_id": "node_mismatch",
    "session_ref": "session_mismatch",
    "generation": "session_mismatch",
}


def _canon(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _claims_live(bundle: Mapping[str, Any]) -> bool:
    """Whether the bundle asserts a live session, judged from persisted state.

    Uses ``environment_state`` (never the effect observation, which is absent for
    a persisted ``active`` state). A live claim requires persisted ``active`` with
    no recorded drift and no lease overrun; those two are failure facts, not claims.
    """

    if bundle["runtime_materialization"]["environment_state"] != "active":
        return False
    if bundle["isolation"]["status"] == "drift_observed":
        return False
    return "lease_expired" not in bundle["limitations"]


def verify_feedback_bundle(
    bundle: Mapping[str, Any],
    *,
    expected_chain: ReferenceChain,
    state: Any,
    now: datetime,
    max_age: float,
    mechanism: Any = None,
    allow_historical: bool = False,
) -> None:
    """Raise :class:`BindingRefused` unless the bundle is what the evidence says.

    The bundle's head must be the chain's current head: evidence appended after
    the bundle was built (a drift, a new contact) makes it ``stale``. For audit
    only, ``allow_historical=True`` accepts an earlier head, but never for a
    bundle that claims a live effect. The consumers cannot ask for it.

    Nothing the bundle declares about itself is trusted. The bundle is rebuilt
    from the evidence chain (cut at the head it names), the chain, and the
    inputs the caller declared, then compared in full. ``mechanism`` is the
    Edge mechanism evidence, supplied again by the caller: a bundle that claims
    an observed mechanism it cannot be shown is refused.
    """

    now = _aware(now)
    store: RuntimeStateStore = getattr(state, "state", state)
    _require_sealed(store, expected_chain)
    try:
        if not isinstance(bundle, Mapping) or bundle.get("schema") != BUNDLE_SCHEMA:
            raise BindingRefused("evidence_tampered", "not a feedback bundle")
        declared_chain = bundle["reference_chain"]
        expected = expected_chain.to_dict()
        for key, code in _CHAIN_FIELD_CODE.items():
            if declared_chain.get(key) != expected[key]:
                raise BindingRefused(code, f"reference_chain.{key} differs")
        env = expected_chain.environment_id
        outcome = bundle["outcome"]
        if "telemetry_gaps" not in outcome or "coverage_complete" not in outcome:
            raise BindingRefused("telemetry_missing", "outcome carries no coverage statement")
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

        if not store.verify_evidence_chain(env):
            raise BindingRefused("evidence_tampered", "evidence hash chain does not verify")
        head = bundle["evidence"].get("head_hash")
        if not isinstance(head, str) or not head:
            raise BindingRefused("evidence_tampered", "bundle names no evidence head")
        records = _read_records(store, env)
        head_record = next((r for r in records if r.get("_evidence_hash") == head), None)
        if head_record is None:
            raise BindingRefused("evidence_tampered", "bundle evidence head is not in the chain")

        current_head = store.evidence_head_hash(env)
        if head != current_head:
            if not allow_historical:
                raise BindingRefused("stale", "evidence was appended after this bundle was built")
            if _claims_live(bundle):
                raise BindingRefused("stale", "a historical bundle may not claim a live effect")

        caller = bundle["caller_declared"]
        mac = bundle.get("caller_declared_mac")
        if not isinstance(mac, str) or not hmac.compare_digest(
            mac, _declared_mac(store, expected_chain, caller, create=False)
        ):
            raise BindingRefused("evidence_tampered", "caller_declared was changed after build")
        coverage = bundle["objective_coverage"]
        objective = None
        if coverage.get("status") == "evaluated":
            objective = MioObservationObjective(
                objective_ref=expected_chain.objective_ref,
                hypothesis_refs=expected_chain.hypothesis_refs,
                frame_ref=expected_chain.frame_ref,
                desired_observations=tuple(tuple(x) for x in coverage["desired_observations"]),
            )
            if objective_digest(objective) != expected_chain.objective_digest:
                raise BindingRefused("decision_mismatch", "objective content is not the admitted one")
        if bundle["observed_mechanism"].get("status") == "observed" and mechanism is None:
            raise BindingRefused("evidence_tampered", "observed mechanism cannot be corroborated")
        mech = _runtime_mechanism(mechanism, expected_chain)
        built_at = _parse_ts(outcome["observed_at"])
        rebuilt = _derive(
            store, expected_chain, now=built_at,
            max_age=float(bundle["freshness"]["max_age_seconds"]),
            expected=_names(caller["expected_telemetry"], name="expected_telemetry"),
            observed=_names(caller["observed_telemetry"], name="observed_telemetry"),
            assertions=_ref_tuple(caller["isolation_assertion_refs"], 64, "isolation_assertion_refs"),
            surfaces=_ref_tuple(caller["active_surface_refs"], 128, "active_surface_refs"),
            surface_telemetry=_surface_map(caller["surface_telemetry"]),
            objective=objective, mech=mech, upto_seq=_seq(head_record),
        )
        given = json.loads(_canon(bundle))
        for key, value in json.loads(_canon(rebuilt)).items():
            if given.get(key) != value:
                raise BindingRefused("evidence_tampered", f"bundle.{key} differs from the evidence")
        if set(given) != set(rebuilt):
            raise BindingRefused("evidence_tampered", "bundle carries undeclared keys")

        # Time, relative to this verification.
        if built_at > now + CLOCK_SKEW:
            raise BindingRefused("stale", "bundle is dated in the future")
        anchor = _parse_ts(bundle["freshness"]["observed_at"])
        if (now - anchor).total_seconds() > float(max_age):
            raise BindingRefused("stale", "bundle observations are older than max_age")

        if _claims_live(bundle):
            for record in records:
                if record.get("event_type") == "reset_completed" and _seq(record) > expected_chain.generation:
                    raise BindingRefused("session_reset", "the session was reset")
                if record.get("event_type") in ("terminated", "activated") and _seq(record) > expected_chain.generation:
                    raise BindingRefused("session_mismatch", "the session is no longer live")
            if now >= expected_chain.lease_end:
                raise BindingRefused("lease_expired", "decision window has closed")
            if now < expected_chain.lease_start:
                raise BindingRefused("lease_not_started", "decision window has not opened")
    except BindingRefused:
        raise
    except (KeyError, TypeError, AttributeError, ValueError):
        raise BindingRefused("evidence_tampered", "bundle is malformed") from None


# --------------------------------------------------------------------------
# consumers (each verifies first)


def _verified(bundle: Mapping[str, Any], expected_chain: ReferenceChain, state: Any, now: datetime,
              max_age: float, mechanism: Any) -> None:
    verify_feedback_bundle(
        bundle, expected_chain=expected_chain, state=state, now=now, max_age=max_age,
        mechanism=mechanism,
    )


def knowledge_ingest_payload(
    bundle: Mapping[str, Any],
    *,
    expected_chain: ReferenceChain,
    state: Any,
    now: datetime,
    max_age: float,
    mechanism: Any = None,
) -> dict[str, Any]:
    """The existing Knowledge ``POST /v1/deception-observations`` envelope.

    Only a bundle that passed :func:`verify_feedback_bundle` is emitted.
    """

    _verified(bundle, expected_chain, state, now, max_age, mechanism)
    items = [
        InteractionObservation.model_validate(item).model_dump(mode="json")
        for item in bundle["interactions"]
    ]
    return {"environment_id": bundle["reference_chain"]["environment_id"], "items": items}


_MIO_OBSERVATION_REFS_CAP = 8


def _age_at(bundle: Mapping[str, Any], now: datetime) -> float:
    """Age of the bundle's newest evidence at consumption time ``now``."""

    anchor = _parse_ts(bundle["freshness"]["observed_at"])
    return max(0.0, (_aware(now) - anchor).total_seconds())


def _context(bundle: Mapping[str, Any], *, now: datetime, max_age: float) -> dict[str, Any]:
    chain = bundle["reference_chain"]
    env_state = bundle["runtime_materialization"].get("environment_state")
    limitations = set(bundle["limitations"])
    # Freshness is judged at consumption time, not at build time.
    fresh_now = bool(bundle["freshness"]["fresh"]) and _age_at(bundle, now) <= float(max_age)
    if (
        not fresh_now
        or bundle["isolation"]["status"] == "drift_observed"
        or "lease_expired" in limitations and env_state == "active"
        # "active" in the persisted evidence log is not an independent runtime
        # verification; without one the context cannot claim active.
        or (env_state == "active" and "runtime_state_not_independently_reverified" in limitations)
    ):
        lifecycle = "unknown"
    else:
        lifecycle = {"active": "active", "terminated": "terminated", "reset": "inactive"}.get(
            str(env_state), "unknown"
        )
    refs = [i["observation_id"] for i in bundle["interactions"]][-_MIO_OBSERVATION_REFS_CAP:]
    return {
        "environment_id": chain["environment_id"],
        "package_id": chain["package_id"],
        "node_id": chain["node_id"],
        "lifecycle_state": lifecycle,
        "observation_refs": refs,
    }


def mio_deception_context(
    bundle: Mapping[str, Any],
    *,
    expected_chain: ReferenceChain,
    state: Any,
    now: datetime,
    max_age: float,
    mechanism: Any = None,
) -> dict[str, Any]:
    """A mapping ``MioDeceptionContext.coerce`` accepts (MIO ce9c2c9 vocabulary).

    Lifecycle is conservative: anything AZ-06 cannot vouch for (drift, a stale
    bundle, an overrun lease, a failed environment) is ``unknown``, never
    ``active``. The bundle is verified first.
    """

    _verified(bundle, expected_chain, state, now, max_age, mechanism)
    return _context(bundle, now=now, max_age=max_age)


def _marker(name: str) -> str:
    return re.sub(r"[^A-Z0-9]+", "_", name.upper()).strip("_")[:100]


def mio_frame_inputs(
    bundle: Mapping[str, Any],
    *,
    expected_chain: ReferenceChain,
    state: Any,
    now: datetime,
    max_age: float,
    mechanism: Any = None,
) -> dict[str, Any]:
    """Inputs for ``MioSituationFrameBuilder.build`` (MIO ce9c2c9), verified first.

    The builder takes ``deception_context`` and ``explicit_unknowns`` (the
    ``unknowns`` key carries the same list for ``MioSituationFrame.build``);
    ``freshness_seconds`` and ``evidence_refs`` are for ``MioSituationFrame.build``
    directly, since the builder derives those from its own events. Unknown
    markers are upper-case tokens in the style of MIO's own (``EVIDENCE_STALE``).
    Hypothesis-level judgement stays MIO's: ``objective_coverage`` in the bundle
    says what was and was not observable, never which hypothesis is right.
    """

    _verified(bundle, expected_chain, state, now, max_age, mechanism)
    limitations = set(bundle["limitations"])
    unknowns: list[str] = []
    known_facts: list[str] = []
    for gap in bundle["outcome"]["telemetry_gaps"]:
        unknowns.append(f"DECEPTION_TELEMETRY_GAP_{_marker(gap)}")
    for entry in bundle["objective_coverage"].get("entries", []):
        status = entry["status"]
        suffix = f"{_marker(entry['observation_class'])}_{_marker(entry['surface'])}"
        if status.startswith("undeterminable_telemetry_gap:"):
            unknowns.append(f"DECEPTION_TELEMETRY_GAP_{_marker(status.split(':', 1)[1])}")
        elif status.startswith("undeterminable_unmapped_surface:"):
            unknowns.append(f"DECEPTION_UNMAPPED_SURFACE_{_marker(status.split(':', 1)[1])}")
        elif status == "observed":
            known_facts.append(f"DECEPTION_DESIRED_OBSERVED_{suffix}")
        elif status == "not_observed_with_coverage":
            # Coverage is caller-declared (surface_telemetry/observed_telemetry), so
            # "not observed" is an explicit unknown, never a known fact.
            unknowns.append(f"DECEPTION_DESIRED_NOT_OBSERVED_CALLER_DECLARED_COVERAGE_{suffix}")
        elif status == "observed_confounded_only":
            unknowns.append(f"DECEPTION_DESIRED_OBSERVED_CONFOUNDED_ONLY_{suffix}")
        elif status == "observed_outside_lease_only":
            unknowns.append(f"DECEPTION_DESIRED_OBSERVED_OUTSIDE_LEASE_ONLY_{suffix}")
    if "stale" in limitations:
        unknowns.append("DECEPTION_EVIDENCE_STALE")
    if bundle["isolation"]["status"] == "unknown":
        unknowns.append("DECEPTION_ISOLATION_NOT_ASSERTED")
    if bundle["isolation"]["status"] == "drift_observed":
        unknowns.append("DECEPTION_ISOLATION_DRIFT_OBSERVED")
    if "no_interaction_observed_is_not_evidence_of_safety" in limitations:
        unknowns.append("DECEPTION_NO_INTERACTION_NOT_SAFETY")
    if "lease_expired" in limitations:
        unknowns.append("DECEPTION_LEASE_EXPIRED")
    if "objective_content_not_bound" in limitations:
        unknowns.append("DECEPTION_OBJECTIVE_CONTENT_NOT_BOUND")
    unknowns = list(dict.fromkeys(unknowns))
    return {
        "deception_context": _context(bundle, now=now, max_age=max_age),
        "deception_status": "available",
        "known_facts": list(dict.fromkeys(known_facts)),
        "unknowns": unknowns,
        "explicit_unknowns": list(unknowns),
        "freshness_seconds": int(_age_at(bundle, now)),
        "evidence_refs": [i["observation_id"] for i in bundle["interactions"]][-32:],
    }


# --------------------------------------------------------------------------
# reset


def reset_feedback(adapter: Any, chain: ReferenceChain, *, now: datetime) -> dict[str, Any]:
    """After terminate and reset: confirm the evidence and say what is and is not known.

    Does not terminate or reset anything. Both already happened, through an
    Edge termination decision and ``adapter.reset_environment``. A read-only
    bundle for the ended session is available from ``build_feedback_bundle``
    (``environment_state == "reset"``).
    """

    now = _aware(now)
    _require_sealed(adapter.state, chain)
    _require_chain_intact(adapter.state, chain.environment_id)
    records = _evidence(adapter, chain.environment_id)
    after = [r for r in records if _seq(r) > chain.generation]
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
        "session_ended_new_observations_belong_to_a_new_session",
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
        raise BindingRefused("effect_rejected", "effect rejected the observation") from None
    return {
        "reference_chain": chain.to_dict(),
        "effect_observation": observation.model_dump(mode="json"),
        "environment_state": "reset",
        "reset_evidence_seq": _seq(resets[-1]),
        "limitations": limitations,
        "tactical_assessment": {"status": "not_assessed", "owner": "outside_az06"},
        "evidence": {
            "head_hash": adapter.state.evidence_head_hash(chain.environment_id),
            "chain_verified": True,
        },
    }
