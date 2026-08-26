"""Adapter from the shared Outcome-as-Evidence mechanism wire shape.

Deception consumes an already-observed REDIRECTION mechanism fact. The adapter
intentionally discards provider parameters and cannot turn the fact into new
routing or materialization authority.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

from azazel_deception.runtime.presented_terrain import ProducerRedirectionEvidence

_EXPECTED_FIELDS = {
    "schema_version",
    "observation_id",
    "producer_product",
    "producer_node",
    "trace_id",
    "decision_ref",
    "execution_ref",
    "mechanism_kind",
    "status",
    "observed_parameters",
    "observed_at",
    "evidence_refs",
    "limitations",
    "authority_class",
}
_BANNED_KEYS = {
    "execute",
    "execution_command",
    "provider_command",
    "command",
    "commands",
    "approve",
    "approval",
    "override",
    "arbiter_override",
    "auto_execute",
    "select_action",
    "selected_action",
    "model_recommendation",
    "attacker_belief",
    "success",
    "successful",
    "effect_class",
    "tactical_effect",
}
_MAX_DEPTH = 6
_MAX_MAP_ITEMS = 64
_MAX_SEQUENCE_ITEMS = 128
_MAX_STRING = 2048
_MAX_CANONICAL_BYTES = 64 * 1024


def _normalized_key(raw: str) -> str:
    normalized = "".join(ch.lower() if ch.isalnum() else "_" for ch in raw.strip())
    while "__" in normalized:
        normalized = normalized.replace("__", "_")
    return normalized.strip("_")


def _is_forbidden_key(raw: str) -> bool:
    key = _normalized_key(raw)
    return (
        key in _BANNED_KEYS
        or "provider_command" in key
        or key.endswith("_command")
        or key.startswith("command_")
        or key.startswith("success_")
        or key.endswith("_success")
        or "attacker_belief" in key
        or "model_recommendation" in key
        or "effect_class" in key
        or "tactical_effect" in key
    )


def _validate_bounded_fact(value: Any, *, depth: int = 0) -> None:
    if depth > _MAX_DEPTH:
        raise ValueError("producer mechanism payload exceeds maximum nesting depth")
    if isinstance(value, str):
        if len(value) > _MAX_STRING:
            raise ValueError("producer mechanism payload contains oversized string")
        return
    if value is None or isinstance(value, (bool, int, float)):
        return
    if isinstance(value, Mapping):
        if len(value) > _MAX_MAP_ITEMS:
            raise ValueError("producer mechanism payload map exceeds maximum item count")
        for raw_key, child in value.items():
            if not isinstance(raw_key, str):
                raise ValueError("producer mechanism payload keys must be strings")
            if len(raw_key) > 128:
                raise ValueError("producer mechanism payload contains oversized key")
            if _is_forbidden_key(raw_key):
                raise ValueError(f"forbidden authority/tactical field: {raw_key}")
            _validate_bounded_fact(child, depth=depth + 1)
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if len(value) > _MAX_SEQUENCE_ITEMS:
            raise ValueError("producer mechanism payload sequence exceeds maximum item count")
        for child in value:
            _validate_bounded_fact(child, depth=depth + 1)
        return
    raise ValueError(f"unsupported producer mechanism payload type: {type(value).__name__}")


def _require_text(payload: Mapping[str, Any], field: str, *, max_length: int) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError(f"producer mechanism {field} must be a non-empty trimmed string")
    if len(value) > max_length:
        raise ValueError(f"producer mechanism {field} is oversized")
    return value


def _require_string_list(
    value: Any,
    *,
    label: str,
    max_items: int,
    non_empty: bool = False,
) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"producer mechanism {label} must be a list")
    if non_empty and not value:
        raise ValueError(f"producer mechanism requires {label}")
    if len(value) > max_items:
        raise ValueError(f"producer mechanism {label} exceeds maximum item count")
    for item in value:
        if not isinstance(item, str) or not item.strip() or item != item.strip():
            raise ValueError(f"producer mechanism {label} must contain non-empty trimmed strings")
        if len(item) > _MAX_STRING:
            raise ValueError(f"producer mechanism {label} contains oversized entry")
    return value


def producer_redirection_from_shared_mechanism(
    payload: Mapping[str, Any],
) -> ProducerRedirectionEvidence:
    """Validate a Fabric-compatible mechanism fact and project only safe refs."""

    if not isinstance(payload, Mapping):
        raise ValueError("producer mechanism evidence must be a mapping")
    if set(payload) != _EXPECTED_FIELDS:
        raise ValueError("producer mechanism evidence fields do not match shared v0.1 contract")
    if payload.get("schema_version") != "outcome-mechanism/v0.1":
        raise ValueError("unsupported producer mechanism schema")
    if payload.get("mechanism_kind") != "redirection":
        raise ValueError("Deception Presented Terrain requires observed redirection mechanism")
    if payload.get("status") != "observed":
        raise ValueError("redirection mechanism is not independently observed")
    if payload.get("authority_class") != "producer_mechanism_fact":
        raise ValueError("invalid producer mechanism authority class")

    observed_parameters = payload.get("observed_parameters")
    if not isinstance(observed_parameters, Mapping):
        raise ValueError("observed_parameters must be a mapping")
    _validate_bounded_fact(observed_parameters)

    evidence_refs = _require_string_list(
        payload.get("evidence_refs"),
        label="evidence refs",
        max_items=64,
        non_empty=True,
    )
    _require_string_list(
        payload.get("limitations"),
        label="limitations",
        max_items=64,
    )

    field_limits = {
        "observation_id": 256,
        "producer_product": 64,
        "producer_node": 128,
        "trace_id": 256,
        "decision_ref": 256,
        "execution_ref": 256,
        "observed_at": 64,
    }
    for field, max_length in field_limits.items():
        _require_text(payload, field, max_length=max_length)

    # Bound the complete upstream object too, even though provider parameters and
    # limitations are intentionally discarded before local lifecycle projection.
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    if len(encoded.encode("utf-8")) > _MAX_CANONICAL_BYTES:
        raise ValueError("producer mechanism payload exceeds maximum canonical size")

    return ProducerRedirectionEvidence(
        producer_product=str(payload["producer_product"]),
        producer_node=str(payload["producer_node"]),
        trace_id=str(payload["trace_id"]),
        decision_ref=str(payload["decision_ref"]),
        execution_ref=str(payload["execution_ref"]),
        mechanism_observation_ref=str(payload["observation_id"]),
        mechanism_kind="redirection",
        status="observed",
        evidence_refs=tuple(evidence_refs),
    )
