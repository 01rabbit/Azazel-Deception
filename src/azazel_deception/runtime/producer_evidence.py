"""Adapter from the shared Outcome-as-Evidence mechanism wire shape.

Deception consumes an already-observed REDIRECTION mechanism fact.  The adapter
intentionally discards provider parameters and cannot turn the fact into new
routing or materialization authority.
"""

from __future__ import annotations

from collections.abc import Mapping
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
    if not isinstance(payload.get("observed_parameters"), Mapping):
        raise ValueError("observed_parameters must be a mapping")
    evidence_refs = payload.get("evidence_refs")
    limitations = payload.get("limitations")
    if not isinstance(evidence_refs, list) or not evidence_refs:
        raise ValueError("producer mechanism requires evidence refs")
    if not isinstance(limitations, list):
        raise ValueError("producer mechanism limitations must be a list")
    if any(not isinstance(item, str) or not item.strip() for item in evidence_refs):
        raise ValueError("producer evidence refs must be non-empty strings")
    for field in (
        "observation_id",
        "producer_product",
        "producer_node",
        "trace_id",
        "decision_ref",
        "execution_ref",
        "observed_at",
    ):
        value = payload.get(field)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"producer mechanism {field} must be a non-empty string")

    # Provider parameters and limitations are descriptive upstream facts. They
    # are intentionally not propagated into local lifecycle authority.
    return ProducerRedirectionEvidence(
        producer_product=str(payload["producer_product"]),
        producer_node=str(payload["producer_node"]),
        trace_id=str(payload["trace_id"]),
        decision_ref=str(payload["decision_ref"]),
        execution_ref=str(payload["execution_ref"]),
        mechanism_observation_ref=str(payload["observation_id"]),
        mechanism_kind="redirection",
        status="observed",
        evidence_refs=tuple(str(item) for item in evidence_refs),
    )
