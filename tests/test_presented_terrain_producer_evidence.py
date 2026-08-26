from __future__ import annotations

import pytest

from azazel_deception.runtime.producer_evidence import (
    producer_redirection_from_shared_mechanism,
)


def shared_redirection(**overrides):
    payload = {
        "schema_version": "outcome-mechanism/v0.1",
        "observation_id": "mechanism-1",
        "producer_product": "azazel-edge",
        "producer_node": "edge-1",
        "trace_id": "trace-1",
        "decision_ref": "decision-1",
        "execution_ref": "execution-1",
        "mechanism_kind": "redirection",
        "status": "observed",
        "observed_parameters": {"route_readback": "present"},
        "observed_at": "2026-08-26T00:00:01Z",
        "evidence_refs": ["nft:readback:1"],
        "limitations": [],
        "authority_class": "producer_mechanism_fact",
    }
    payload.update(overrides)
    return payload


def test_shared_redirection_projects_only_opaque_chain_refs():
    projected = producer_redirection_from_shared_mechanism(shared_redirection())
    assert projected.mechanism_kind == "redirection"
    assert projected.status == "observed"
    assert projected.mechanism_observation_ref == "mechanism-1"
    assert projected.evidence_refs == ("nft:readback:1",)
    assert not hasattr(projected, "observed_parameters")


def test_non_observed_or_non_redirection_mechanism_fails_closed():
    with pytest.raises(ValueError, match="observed redirection"):
        producer_redirection_from_shared_mechanism(shared_redirection(mechanism_kind="traffic_shaping"))
    with pytest.raises(ValueError, match="not independently observed"):
        producer_redirection_from_shared_mechanism(shared_redirection(status="unverified"))


@pytest.mark.parametrize(
    "field",
    ["effect_class", "effect-class", "tactical_effect", "tactical-effect"],
)
def test_tactical_claim_cannot_be_smuggled_in_discarded_parameters(field):
    with pytest.raises(ValueError, match="tactical"):
        producer_redirection_from_shared_mechanism(
            shared_redirection(observed_parameters={"nested": {field: "divert"}})
        )


@pytest.mark.parametrize(
    "field",
    ["provider_command", "provider-command", "success", "attacker belief", "model-recommendation"],
)
def test_authority_or_overclaim_cannot_be_smuggled_in_parameters(field):
    with pytest.raises(ValueError, match="forbidden"):
        producer_redirection_from_shared_mechanism(
            shared_redirection(observed_parameters={"nested": {field: "value"}})
        )


def test_oversized_shared_payload_is_rejected_even_when_discarded():
    with pytest.raises(ValueError, match="oversized string"):
        producer_redirection_from_shared_mechanism(
            shared_redirection(observed_parameters={"note": "x" * 2049})
        )
    with pytest.raises(ValueError, match="maximum item count"):
        producer_redirection_from_shared_mechanism(
            shared_redirection(observed_parameters={f"k{i}": i for i in range(65)})
        )


def test_unknown_or_extra_shared_fields_fail_closed():
    with pytest.raises(ValueError, match="fields do not match"):
        producer_redirection_from_shared_mechanism(
            {**shared_redirection(), "effect_class": "DIVERT"}
        )
    with pytest.raises(ValueError, match="unsupported"):
        producer_redirection_from_shared_mechanism(
            shared_redirection(schema_version="outcome-mechanism/v9")
        )
