"""Fact-only Presented Terrain evidence projection.

This module deliberately sits *after* an observed redirection mechanism.  It
never selects DIVERT, never authorizes materialization, and never infers attacker
belief.  The existing runtime remains the only local lifecycle authority.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, model_validator


class _StrictFact(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ProducerRedirectionEvidence(_StrictFact):
    """Opaque producer linkage proving only that REDIRECTION was observed."""

    schema_version: Literal["deception-producer-mechanism/v0.1"] = (
        "deception-producer-mechanism/v0.1"
    )
    producer_product: str = Field(min_length=1, max_length=64)
    trace_id: str = Field(min_length=1, max_length=256)
    decision_ref: str = Field(min_length=1, max_length=256)
    execution_ref: str = Field(min_length=1, max_length=256)
    mechanism_observation_ref: str = Field(min_length=1, max_length=256)
    mechanism_kind: Literal["redirection"] = "redirection"
    status: Literal["observed"] = "observed"
    evidence_refs: tuple[str, ...] = Field(min_length=1, max_length=64)


class PresentedTerrainSnapshotV0(_StrictFact):
    """Descriptive snapshot of a Deception presentation.

    ``lifecycle_state=active`` means the runtime was independently verified
    active for this projection.  Persisted state alone can only produce a
    ``stale`` snapshot after restart/reconciliation uncertainty.
    """

    schema_version: Literal["presented-terrain-snapshot/v0.1"] = (
        "presented-terrain-snapshot/v0.1"
    )
    presentation_id: str = Field(min_length=1, max_length=256)
    environment_id: str = Field(min_length=1, max_length=256)
    producer_product: str = Field(min_length=1, max_length=64)
    trace_id: str = Field(min_length=1, max_length=256)
    producer_decision_ref: str = Field(min_length=1, max_length=256)
    producer_execution_ref: str = Field(min_length=1, max_length=256)
    producer_mechanism_ref: str = Field(min_length=1, max_length=256)
    producer_mechanism_kind: Literal["redirection"] = "redirection"

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
    def _lifecycle_invariants(self) -> "PresentedTerrainSnapshotV0":
        if self.lifecycle_state == "active":
            if not self.started_at:
                raise ValueError("active presentation requires started_at")
            if not self.active_surface_refs:
                raise ValueError("active presentation requires active surface evidence")
        if self.lifecycle_state in {"terminated", "reset"} and not self.ended_at:
            raise ValueError("terminal presentation requires ended_at")
        if self.lifecycle_state == "reset" and not self.reset_ref:
            raise ValueError("reset presentation requires reset evidence reference")
        return self


def _stable_presentation_id(
    environment_id: str,
    producer: ProducerRedirectionEvidence,
    package_digest: str,
) -> str:
    material = "|".join(
        (environment_id, producer.trace_id, producer.execution_ref, producer.mechanism_observation_ref, package_digest)
    )
    return "presentation-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]


def build_presented_terrain_snapshot(
    *,
    environment_id: str,
    producer: ProducerRedirectionEvidence,
    runtime_state: Mapping[str, Any],
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
    Otherwise the projection is intentionally ``stale``.
    """

    if not isinstance(runtime_state, Mapping):
        raise ValueError("runtime_state must be a mapping")
    package_id = str(runtime_state.get("package_id") or "")
    package_digest = str(runtime_state.get("package_digest") or "")
    runtime_node = str(runtime_state.get("node_id") or "")
    recorded_environment = str(runtime_state.get("environment_id") or "")
    if not package_id or not package_digest or not runtime_node:
        raise ValueError("runtime state lacks package/runtime provenance")
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
    ended_at = (
        str(runtime_state.get("terminated_at") or runtime_state.get("reset_at") or "") or None
    )
    all_evidence = tuple(dict.fromkeys((*producer.evidence_refs, *evidence_refs)))

    return PresentedTerrainSnapshotV0(
        presentation_id=_stable_presentation_id(environment_id, producer, package_digest),
        environment_id=environment_id,
        producer_product=producer.producer_product,
        trace_id=producer.trace_id,
        producer_decision_ref=producer.decision_ref,
        producer_execution_ref=producer.execution_ref,
        producer_mechanism_ref=producer.mechanism_observation_ref,
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
