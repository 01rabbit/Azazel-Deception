"""Fact-only Presented Terrain evidence projection.

This module deliberately sits *after* an observed redirection mechanism. It
never selects DIVERT, never authorizes materialization, and never infers attacker
belief. The existing runtime remains the only local lifecycle authority.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, model_validator

# Fabric#14's canonical vocabulary, consumed as a *validator* (Deception#28
# AC-7). AZ-06 never enumerates the five values -- it asks Fabric whether a
# producer's report is one of them, and records the answer. A copy of the list
# here would be a second definition free to drift, and
# `tests/test_defensive_state_boundary.py` fails if one ever appears.
from azazel_fabric.schema.defensive_state import coerce_defensive_state


class _StrictFact(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _require_reference(label: str, value: str, *, prefix: str | None = None) -> None:
    if not value or value != value.strip():
        raise ValueError(f"{label} must be a non-empty trimmed reference")
    if any(ch.isspace() for ch in value) or "=" in value:
        raise ValueError(f"{label} must be an opaque reference, not secret material")
    if prefix is not None and not value.startswith(prefix):
        raise ValueError(f"{label} must use {prefix} reference namespace")


def _classify_producer_defensive_state(state: str | None, claimed_canonical: bool) -> bool:
    """Return whether `state` is canonical, refusing a claim made without one.

    Shared by every model that carries a producer-reported Defensive State so
    that the flag is computed identically wherever it appears. A model that
    merely copies the pair from another model is not exempt: the snapshot is
    the artifact an auditor reads, so a snapshot built directly must not be
    able to claim canonical for a word Fabric does not know.

    The coercion *value* is deliberately discarded. Fabric lands an
    unrecognized state on the weakest one so a consumer deciding what to do
    fails safe; AZ-06 is not that consumer. Substituting it would turn "the
    producer said something we do not know" into "the producer said OBSERVE"
    -- AZ-06 asserting another product's posture, which is the one thing this
    boundary exists to prevent.
    """

    if state is None:
        if claimed_canonical:
            raise ValueError(
                "producer_defensive_state_is_canonical cannot be true with no state"
            )
        return False
    _, recognized = coerce_defensive_state(state)
    return recognized


class ProducerRedirectionEvidence(_StrictFact):
    """Opaque producer linkage proving only that REDIRECTION was observed."""

    schema_version: Literal["deception-producer-mechanism/v0.1"] = (
        "deception-producer-mechanism/v0.1"
    )
    producer_product: str = Field(min_length=1, max_length=64)
    producer_node: str = Field(min_length=1, max_length=128)
    trace_id: str = Field(min_length=1, max_length=256)
    decision_ref: str = Field(min_length=1, max_length=256)
    execution_ref: str = Field(min_length=1, max_length=256)
    mechanism_observation_ref: str = Field(min_length=1, max_length=256)
    mechanism_kind: Literal["redirection"] = "redirection"
    status: Literal["observed"] = "observed"
    evidence_refs: tuple[str, ...] = Field(min_length=1, max_length=64)

    #: The Defensive State the **producer** reported for itself, if it said.
    #:
    #: Named for its owner on purpose. An unqualified `defensive_state` field
    #: would be ambiguous about whose state it is, and that ambiguity is what
    #: lets two namespaces merge. This one is unmistakably the producer's, and
    #: it sits beside AZ-06's own `lifecycle_state` on the snapshot without
    #: either becoming the other (Deception#28 AC-5).
    #:
    #: Recording it does not let AZ-06 act on it. There is no parameter
    #: anywhere in the runtime through which a reported state reaches
    #: activation, transition, or termination -- that is asserted structurally
    #: in `tests/test_defensive_state_boundary.py`, and this field changes
    #: nothing about it. This is audit correlation, not an input.
    producer_defensive_state: str | None = Field(default=None, max_length=64)
    #: Whether `producer_defensive_state` is in Fabric's canonical vocabulary.
    #:
    #: Computed, never supplied: a producer cannot assert that its own word is
    #: canonical. `False` with a value present means the producer spoke a
    #: vocabulary AZ-06's pinned Fabric does not know, which is a fact worth
    #: keeping rather than a reason to drop the report.
    producer_defensive_state_is_canonical: bool = False

    @model_validator(mode="after")
    def _classify_producer_state(self) -> "ProducerRedirectionEvidence":
        object.__setattr__(
            self,
            "producer_defensive_state_is_canonical",
            _classify_producer_defensive_state(
                self.producer_defensive_state, self.producer_defensive_state_is_canonical
            ),
        )
        return self


class PresentedTerrainSnapshotV0(_StrictFact):
    """Descriptive snapshot of a Deception presentation.

    ``lifecycle_state=active`` means the runtime and isolation were independently
    verified for this projection. Persisted state alone can only produce a
    ``stale`` snapshot after restart/reconciliation uncertainty.
    """

    schema_version: Literal["presented-terrain-snapshot/v0.1"] = (
        "presented-terrain-snapshot/v0.1"
    )
    presentation_id: str = Field(min_length=1, max_length=256)
    environment_id: str = Field(min_length=1, max_length=256)
    producer_product: str = Field(min_length=1, max_length=64)
    producer_node: str = Field(min_length=1, max_length=128)
    trace_id: str = Field(min_length=1, max_length=256)
    producer_decision_ref: str = Field(min_length=1, max_length=256)
    producer_execution_ref: str = Field(min_length=1, max_length=256)
    producer_mechanism_ref: str = Field(min_length=1, max_length=256)
    producer_mechanism_kind: Literal["redirection"] = "redirection"
    #: Carried through from the producer's evidence for audit correlation.
    #: Distinct from `lifecycle_state` below, which is AZ-06's own namespace.
    producer_defensive_state: str | None = Field(default=None, max_length=64)
    producer_defensive_state_is_canonical: bool = False

    package_id: str = Field(min_length=1, max_length=256)
    package_version: str = Field(min_length=1, max_length=128)
    package_digest: str = Field(min_length=1, max_length=256)
    runtime_node_id: str = Field(min_length=1, max_length=256)
    lifecycle_state: Literal["active", "terminated", "reset", "failed", "stale"]

    active_surface_refs: tuple[str, ...] = Field(default_factory=tuple, max_length=128)
    synthetic_artifact_refs: tuple[str, ...] = Field(default_factory=tuple, max_length=128)
    synthetic_identity_refs: tuple[str, ...] = Field(default_factory=tuple, max_length=128)
    synthetic_credential_refs: tuple[str, ...] = Field(default_factory=tuple, max_length=128)

    started_at: str | None = Field(default=None, max_length=64)
    expires_at: str | None = Field(default=None, max_length=64)
    ended_at: str | None = Field(default=None, max_length=64)
    isolation_assertion_refs: tuple[str, ...] = Field(default_factory=tuple, max_length=64)
    reset_ref: str | None = Field(default=None, max_length=256)
    evidence_refs: tuple[str, ...] = Field(default_factory=tuple, max_length=128)
    limitations: tuple[str, ...] = Field(default_factory=tuple, max_length=128)
    observed_at: str = Field(min_length=1, max_length=64)
    authority_class: Literal["deception_presentation_fact"] = "deception_presentation_fact"
    executable: Literal[False] = False

    @model_validator(mode="after")
    def _classify_producer_state(self) -> "PresentedTerrainSnapshotV0":
        # Recomputed rather than trusted. The snapshot is the artifact an
        # auditor reads, and it can be constructed directly -- not only by
        # copying a validated `ProducerRedirectionEvidence`. Accepting the
        # flag here would let a caller mark any word canonical by asserting it.
        object.__setattr__(
            self,
            "producer_defensive_state_is_canonical",
            _classify_producer_defensive_state(
                self.producer_defensive_state, self.producer_defensive_state_is_canonical
            ),
        )
        return self

    @model_validator(mode="after")
    def _lifecycle_invariants(self) -> "PresentedTerrainSnapshotV0":
        for ref in self.synthetic_credential_refs:
            _require_reference("synthetic_credential_ref", ref, prefix="credential:")
        for label, refs in (
            ("active_surface_ref", self.active_surface_refs),
            ("synthetic_artifact_ref", self.synthetic_artifact_refs),
            ("synthetic_identity_ref", self.synthetic_identity_refs),
            ("isolation_assertion_ref", self.isolation_assertion_refs),
            ("evidence_ref", self.evidence_refs),
        ):
            for ref in refs:
                _require_reference(label, ref)
        if self.lifecycle_state == "active":
            if not self.started_at:
                raise ValueError("active presentation requires started_at")
            if not self.active_surface_refs:
                raise ValueError("active presentation requires active surface evidence")
            if not self.isolation_assertion_refs:
                raise ValueError("active presentation requires isolation assertion evidence")
        if self.lifecycle_state in {"terminated", "reset"} and not self.ended_at:
            raise ValueError("terminal presentation requires ended_at")
        if self.lifecycle_state == "reset" and not self.reset_ref:
            raise ValueError("reset presentation requires reset evidence reference")
        if self.reset_ref is not None:
            _require_reference("reset_ref", self.reset_ref)
        return self


def _stable_presentation_id(
    environment_id: str,
    producer: ProducerRedirectionEvidence,
    package_digest: str,
) -> str:
    material = "|".join(
        (
            environment_id,
            producer.producer_node,
            producer.trace_id,
            producer.execution_ref,
            producer.mechanism_observation_ref,
            package_digest,
        )
    )
    return "presentation-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]


def build_presented_terrain_snapshot(
    *,
    environment_id: str,
    producer: ProducerRedirectionEvidence,
    runtime_state: Mapping[str, Any],
    expected_package_id: str,
    expected_package_digest: str,
    package_version: str,
    observed_at: str,
    active_surface_refs: tuple[str, ...] = (),
    synthetic_artifact_refs: tuple[str, ...] = (),
    synthetic_identity_refs: tuple[str, ...] = (),
    synthetic_credential_refs: tuple[str, ...] = (),
    isolation_assertion_refs: tuple[str, ...] = (),
    reset_ref: str | None = None,
    runtime_verified_active: bool = False,
    expires_at: str | None = None,
    evidence_refs: tuple[str, ...] = (),
    limitations: tuple[str, ...] = (),
) -> PresentedTerrainSnapshotV0:
    """Project existing runtime state into a non-authoritative evidence fact.

    Persisted ``state=active`` is not sufficient after restart: callers must
    independently verify the runtime and set ``runtime_verified_active=True``.
    The runtime's package identity must also match external package provenance;
    runtime state is not allowed to vouch for itself.
    """

    if not isinstance(runtime_state, Mapping):
        raise ValueError("runtime_state must be a mapping")
    package_id = str(runtime_state.get("package_id") or "")
    package_digest = str(runtime_state.get("package_digest") or "")
    runtime_node = str(runtime_state.get("node_id") or "")
    recorded_environment = str(runtime_state.get("environment_id") or "")
    if not package_id or not package_digest or not runtime_node:
        raise ValueError("runtime state lacks package/runtime provenance")
    if package_id != expected_package_id or package_digest != expected_package_digest:
        raise ValueError("runtime package provenance does not match verified package")
    if recorded_environment and recorded_environment != environment_id:
        raise ValueError("runtime state environment does not match presentation")

    state = str(runtime_state.get("state") or "failed")
    lifecycle: Literal["active", "terminated", "reset", "failed", "stale"]
    local_limitations = list(limitations)
    if state == "active":
        if runtime_verified_active:
            lifecycle = "active"
        else:
            lifecycle = "stale"
            local_limitations.append("runtime_active_not_independently_verified")
    elif state == "terminated":
        lifecycle = "terminated"
    elif state == "reset":
        lifecycle = "reset"
    elif state == "failed":
        lifecycle = "failed"
    else:
        lifecycle = "stale"
        local_limitations.append("unknown_runtime_state")

    started_at = str(runtime_state.get("activated_at") or "") or None
    ended_at = str(
        runtime_state.get("terminated_at") or runtime_state.get("reset_at") or ""
    ) or None
    all_evidence = tuple(dict.fromkeys((*producer.evidence_refs, *evidence_refs)))

    return PresentedTerrainSnapshotV0(
        presentation_id=_stable_presentation_id(environment_id, producer, package_digest),
        environment_id=environment_id,
        producer_product=producer.producer_product,
        producer_node=producer.producer_node,
        trace_id=producer.trace_id,
        producer_decision_ref=producer.decision_ref,
        producer_execution_ref=producer.execution_ref,
        producer_mechanism_ref=producer.mechanism_observation_ref,
        producer_defensive_state=producer.producer_defensive_state,
        producer_defensive_state_is_canonical=producer.producer_defensive_state_is_canonical,
        package_id=package_id,
        package_version=package_version,
        package_digest=package_digest,
        runtime_node_id=runtime_node,
        lifecycle_state=lifecycle,
        active_surface_refs=active_surface_refs if lifecycle == "active" else (),
        synthetic_artifact_refs=synthetic_artifact_refs,
        synthetic_identity_refs=synthetic_identity_refs,
        synthetic_credential_refs=synthetic_credential_refs,
        started_at=started_at,
        expires_at=expires_at,
        ended_at=ended_at,
        isolation_assertion_refs=isolation_assertion_refs,
        reset_ref=reset_ref,
        evidence_refs=all_evidence,
        limitations=tuple(dict.fromkeys(local_limitations)),
        observed_at=observed_at,
    )


def canonical_snapshot_json(snapshot: PresentedTerrainSnapshotV0) -> str:
    return json.dumps(
        snapshot.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
