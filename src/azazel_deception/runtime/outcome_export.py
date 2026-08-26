"""Non-authoritative projection from Presented Terrain facts to shared Outcome evidence.

The exported record says what Deception presented/observed. It does not claim
DIVERT, deception success, attacker belief, causality, or execution authority.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any, Literal

from azazel_deception.runtime.presented_terrain import PresentedTerrainSnapshotV0


_FORBIDDEN = {
    "success", "successful", "effect_class", "tactical_effect", "attacker_belief",
    "attacker_intent", "model_recommendation", "execute", "approve", "override",
    "provider_command", "command", "commands",
}
_MAX_DEPTH = 5
_MAX_ITEMS = 96
_MAX_STRING = 2048


def _normalize_key(value: str) -> str:
    normalized = "".join(ch.lower() if ch.isalnum() else "_" for ch in value.strip())
    while "__" in normalized:
        normalized = normalized.replace("__", "_")
    return normalized.strip("_")


def _validate_bounded(value: Any, depth: int = 0) -> None:
    if depth > _MAX_DEPTH:
        raise ValueError("outcome export exceeds maximum depth")
    if value is None or isinstance(value, (bool, int, float)):
        return
    if isinstance(value, str):
        if len(value) > _MAX_STRING:
            raise ValueError("outcome export contains oversized string")
        return
    if isinstance(value, Mapping):
        if len(value) > _MAX_ITEMS:
            raise ValueError("outcome export map too large")
        for key, child in value.items():
            if not isinstance(key, str):
                raise ValueError("outcome export keys must be strings")
            normalized = _normalize_key(key)
            if normalized in _FORBIDDEN or "attacker_belief" in normalized or "tactical_effect" in normalized or "effect_class" in normalized:
                raise ValueError(f"forbidden outcome claim/authority field: {key}")
            _validate_bounded(child, depth + 1)
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if len(value) > _MAX_ITEMS:
            raise ValueError("outcome export list too large")
        for child in value:
            _validate_bounded(child, depth + 1)
        return
    raise ValueError(f"unsupported outcome export type: {type(value).__name__}")


def _stable_observation_id(snapshot: PresentedTerrainSnapshotV0, phase: str, observed_at: str, values: Mapping[str, Any]) -> str:
    material = json.dumps(
        {
            "presentation_id": snapshot.presentation_id,
            "producer_mechanism_ref": snapshot.producer_mechanism_ref,
            "phase": phase,
            "observed_at": observed_at,
            "values": values,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return "deception-outcome-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]


def presented_terrain_lifecycle_outcome(
    snapshot: PresentedTerrainSnapshotV0,
    *,
    observed_at: str,
    telemetry_coverage: Mapping[str, Any] | None = None,
    resource_impact: Mapping[str, Any] | None = None,
    confounders: tuple[str, ...] = (),
    evidence_refs: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Project one Presented Terrain snapshot into ``OutcomeObservationV0`` wire shape.

    This is lifecycle/materialization evidence only. Interaction with a decoy is not
    proof the adversary believed the presentation, and no such field exists here.

    ``stale`` cannot be faithfully represented by the shared before/during/after
    phase vocabulary: stale means current liveness is unknown, not that the
    presentation ended. It therefore fails closed instead of being rounded to after.
    """

    if not observed_at.strip():
        raise ValueError("observed_at is required")
    if snapshot.lifecycle_state == "stale":
        raise ValueError("stale Presented Terrain cannot be projected into a terminal shared phase")
    phase: Literal["during", "after"] = "during" if snapshot.lifecycle_state == "active" else "after"
    values: dict[str, Any] = {
        "presentation_id": snapshot.presentation_id,
        "environment_id": snapshot.environment_id,
        "lifecycle_state": snapshot.lifecycle_state,
        "package_id": snapshot.package_id,
        "package_version": snapshot.package_version,
        "package_digest": snapshot.package_digest,
        "runtime_node_id": snapshot.runtime_node_id,
        "active_surface_refs": list(snapshot.active_surface_refs),
        "isolation_assertion_refs": list(snapshot.isolation_assertion_refs),
        "reset_ref": snapshot.reset_ref,
        "limitations": list(snapshot.limitations),
    }
    coverage = dict(telemetry_coverage or {"presentation_snapshot": True})
    resources = dict(resource_impact or {})
    _validate_bounded(values)
    _validate_bounded(coverage)
    _validate_bounded(resources)
    _validate_bounded(confounders)

    start = snapshot.started_at or observed_at
    end = snapshot.ended_at or observed_at
    combined_refs = tuple(dict.fromkeys((*snapshot.evidence_refs, *evidence_refs)))
    payload = {
        "schema_version": "outcome-observation/v0.1",
        "observation_id": _stable_observation_id(snapshot, phase, observed_at, values),
        "producer_product": "azazel-deception",
        "producer_node": snapshot.runtime_node_id,
        "trace_id": snapshot.trace_id,
        "decision_ref": snapshot.producer_decision_ref,
        "execution_ref": snapshot.producer_execution_ref,
        "mechanism_observation_ref": snapshot.producer_mechanism_ref,
        "subject_ref": snapshot.presentation_id,
        "window_start": start,
        "window_end": end,
        "phase": phase,
        "observation_class": "presented_terrain_lifecycle",
        "observation_values": values,
        "telemetry_coverage": coverage,
        "confounders": list(confounders),
        "resource_impact": resources,
        "evidence_refs": list(combined_refs),
        "observed_at": observed_at,
        "authority_class": "producer_outcome_fact",
    }
    _validate_bounded(payload)
    return payload


def canonical_outcome_json(payload: Mapping[str, Any]) -> str:
    _validate_bounded(payload)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
