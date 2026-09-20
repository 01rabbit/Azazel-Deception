"""Adapter from the shared Outcome-as-Evidence mechanism wire shape.

Deception consumes an already-observed REDIRECTION mechanism fact, produced by
whichever product decided and enforced the redirection. The adapter
intentionally discards provider parameters and cannot turn the fact into new
routing or materialization authority.

**The contract's shape, vocabulary and bounds are Azazel-Fabric's statement,
not this module's.** The payload is validated with
`outcome_contracts.MechanismObservationV0`; nothing here restates what that
record is.

It used to restate it. This module carried its own 14-name field list, its own
copy of Fabric's banned-key set, and five bound constants that matched
Fabric's byte-for-byte -- "by coincidence of maintenance rather than by
construction", which is Azazel-Edge#413's phrase about the same contract on
the producer side. The copy had already drifted: Fabric had added
`effectiveness` and `initiative_score` to its tactical-claim refusals and this
module had not, so a producer barred from writing `tactical_effect` into
`observed_parameters` could have written `effectiveness: 0.9` and meant the
same thing. Azazel-Knowledge's independent copy of the same rules was missing
the same two keys. Two products, the same gap, because both were maintaining a
second statement of somebody else's contract.

Fabric is a core dependency here (`pyproject.toml`, exact-tag pinned), so this
is fixed by construction and there is deliberately no fallback: a fact Fabric
did not validate must not become Presented Terrain linkage.

What stays local is AZ-06's own narrowing, which is policy rather than
contract, and is stricter than the contract in every case -- never looser:

* the mechanism must be specifically `redirection` and specifically
  `observed`, because Presented Terrain has no meaning behind any other
  mechanism or any unverified one;
* every reference must be present and trimmed, because a ref AZ-06 cannot
  attribute is a ref it cannot use;
* `evidence_refs` must be non-empty, for the same reason;
* the field set must be exact, rather than letting Fabric's defaults stand in
  for a field the producer did not send.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from azazel_fabric.outcome_contracts import MechanismObservationV0, canonical_fact_json

from azazel_deception.runtime.presented_terrain import ProducerRedirectionEvidence

#: Derived from the contract, never listed here. A hand-kept copy of these
#: names is exactly what this module stopped carrying: a list that agrees with
#: the contract today and has nothing keeping it that way tomorrow.
_EXPECTED_FIELDS = frozenset(MechanismObservationV0.model_fields)

#: The references AZ-06 carries forward, and the only fields it reads off the
#: fact at all. Everything else the producer sent -- its parameters, its
#: limitations, its timestamps -- is discarded after validation.
_REFERENCE_FIELDS = (
    "observation_id",
    "producer_product",
    "producer_node",
    "trace_id",
    "decision_ref",
    "execution_ref",
)


def _require_trimmed_reference(payload: Mapping[str, Any], field: str) -> str:
    """AZ-06's own requirement, not the contract's.

    Fabric accepts `" decision-1 "` -- its bound is a length, not a shape. A
    reference with edge whitespace would compare unequal to the same reference
    sent without it, which turns one evidence chain into two that look
    unrelated. AZ-06 refuses it rather than silently normalizing, because
    normalizing would mean this module deciding what the producer meant.
    """

    value = payload[field]
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError(f"producer mechanism {field} must be a non-empty trimmed string")
    return value


def producer_redirection_from_shared_mechanism(
    payload: Mapping[str, Any],
) -> ProducerRedirectionEvidence:
    """Validate a Fabric mechanism fact and project only safe refs."""

    if not isinstance(payload, Mapping):
        raise ValueError("producer mechanism evidence must be a mapping")
    if set(payload) != _EXPECTED_FIELDS:
        raise ValueError("producer mechanism evidence fields do not match shared v0.1 contract")
    # Checked before the model so a wrong version reads as an unsupported
    # version rather than as a failed `Literal`, which is what it is.
    if payload.get("schema_version") != "outcome-mechanism/v0.1":
        raise ValueError("unsupported producer mechanism schema")
    if payload.get("mechanism_kind") != "redirection":
        raise ValueError("Deception Presented Terrain requires observed redirection mechanism")
    if payload.get("status") != "observed":
        raise ValueError("redirection mechanism is not independently observed")
    if payload.get("authority_class") != "producer_mechanism_fact":
        raise ValueError("invalid producer mechanism authority class")

    # The contract decides the rest: field types and bounds, the closed
    # vocabularies, the runtime-directive refusal, and the tactical-claim
    # refusal inside `observed_parameters` -- which `extra="forbid"` cannot
    # reach, because that field is a free-form `dict[str, Any]`.
    #
    # `ValidationError` is a `ValueError`, so a contract violation surfaces to
    # callers exactly as this module's own refusals do.
    MechanismObservationV0.model_validate(payload)

    # Bounds the *whole* upstream object, not just the fact maps the model
    # walks: provider parameters and limitations are discarded below, but an
    # oversized payload is refused before anything is read out of it. The
    # canonical bytes themselves are not kept -- AZ-06 stores no copy of
    # somebody else's fact.
    canonical_fact_json(payload)

    references = {field: _require_trimmed_reference(payload, field) for field in _REFERENCE_FIELDS}

    evidence_refs = payload["evidence_refs"]
    if not evidence_refs:
        raise ValueError("producer mechanism requires evidence refs")
    for item in evidence_refs:
        if not isinstance(item, str) or not item.strip() or item != item.strip():
            raise ValueError(
                "producer mechanism evidence refs must contain non-empty trimmed strings"
            )

    return ProducerRedirectionEvidence(
        producer_product=references["producer_product"],
        producer_node=references["producer_node"],
        trace_id=references["trace_id"],
        decision_ref=references["decision_ref"],
        execution_ref=references["execution_ref"],
        mechanism_observation_ref=references["observation_id"],
        mechanism_kind="redirection",
        status="observed",
        evidence_refs=tuple(evidence_refs),
    )
