"""AZ-06 exchanges `outcome_contracts` with Azazel-Fabric's models, not with copies.

Deception sits on both sides of this contract family:

* it **consumes** an already-observed REDIRECTION mechanism fact produced by
  whichever product decided and enforced the redirection
  (`runtime/producer_evidence.py`);
* it **produces** a Presented Terrain lifecycle observation that joins that
  producer's evidence chain (`runtime/outcome_export.py`).

Both sides used to agree with Fabric by coincidence of maintenance rather than
by construction -- the consumer restated the contract's field list, banned-key
set and five bound constants, and the producer assembled the wire shape by
hand. The copy had already drifted: Fabric had added `effectiveness` and
`initiative_score` to its tactical-claim refusals and this repository had not.
Azazel-Knowledge's independent copy of the same rules was missing the same two
keys, which is what a second statement of somebody else's contract costs.

These tests hold the fix in place. They are deliberately **behavioural** where
they can be: a structural comparison between this module and Fabric would pass
the moment both sides were wrong in the same way, which is the exact failure
being removed.
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from azazel_fabric.outcome_contracts import MechanismObservationV0, OutcomeObservationV0
from azazel_deception.runtime.outcome_export import presented_terrain_lifecycle_outcome
from azazel_deception.runtime.producer_evidence import (
    producer_redirection_from_shared_mechanism,
)
from azazel_deception.runtime.presented_terrain import PresentedTerrainSnapshotV0


def shared_redirection(**overrides) -> dict:
    """A valid mechanism fact, built through Fabric's own model.

    Built from the contract rather than written out as JSON: a hand-written
    wire shape in a test that exists to remove hand-written wire shapes would
    drift from the contract with nothing to catch it.
    """

    fact = MechanismObservationV0(
        observation_id="mechanism-1",
        producer_product="azazel-edge",
        producer_node="edge-1",
        trace_id="trace-1",
        decision_ref="decision-1",
        execution_ref="execution-1",
        mechanism_kind="redirection",
        status="observed",
        observed_parameters={"route_readback": "present"},
        observed_at="2026-08-26T00:00:01Z",
        evidence_refs=("nft:readback:1",),
        limitations=(),
    )
    payload = fact.model_dump(mode="json")
    payload.update(overrides)
    return payload


def snapshot(**overrides) -> PresentedTerrainSnapshotV0:
    values = dict(
        presentation_id="presentation-1",
        environment_id="env-1",
        producer_product="azazel-edge",
        producer_node="edge-1",
        trace_id="trace-1",
        producer_decision_ref="decision-1",
        producer_execution_ref="execution-1",
        producer_mechanism_ref="mechanism-1",
        producer_mechanism_kind="redirection",
        package_id="municipal-linux-v1",
        package_version="1.0.0",
        package_digest="sha256:abc123",
        runtime_node_id="deception-1",
        lifecycle_state="active",
        active_surface_refs=("surface:http:8080",),
        synthetic_artifact_refs=(),
        synthetic_identity_refs=(),
        synthetic_credential_refs=(),
        started_at="2026-08-26T00:00:00Z",
        expires_at=None,
        ended_at=None,
        isolation_assertion_refs=("isolation:proof:1",),
        reset_ref=None,
        evidence_refs=("runtime:inspect:1",),
        limitations=(),
        observed_at="2026-08-26T00:00:01Z",
    )
    values.update(overrides)
    return PresentedTerrainSnapshotV0(**values)


# --------------------------------------------------------------------------
# the consumer side: a fact Fabric built is a fact AZ-06 accepts
# --------------------------------------------------------------------------


def test_a_mechanism_fact_fabric_built_is_accepted():
    projected = producer_redirection_from_shared_mechanism(shared_redirection())

    assert projected.mechanism_observation_ref == "mechanism-1"
    assert projected.decision_ref == "decision-1"
    assert projected.execution_ref == "execution-1"
    assert not hasattr(projected, "observed_parameters")


@pytest.mark.parametrize(
    "key",
    ["effectiveness", "initiative_score", "redirect_effectiveness", "initiative_score_v2"],
)
def test_the_tactical_claims_the_local_copy_had_missed_are_refused(key):
    """The drift this change removed, pinned as behaviour.

    Fabric added these to its tactical-claim refusals; this module's own copy
    of that set had not picked them up. A producer barred from writing
    `tactical_effect` into `observed_parameters` could write
    `effectiveness: 0.9` and mean the same thing. The affix variants matter
    too -- `redirect_effectiveness` is the same claim with a mechanism name
    glued to the front.
    """

    with pytest.raises(ValueError):
        producer_redirection_from_shared_mechanism(
            shared_redirection(observed_parameters={"nested": {key: 1}})
        )


def test_the_contract_is_what_refuses_them_not_this_module():
    """If the model stopped refusing, nothing local would catch it.

    This module no longer carries a tactical-claim set of its own, on purpose.
    That is only safe while `MechanismObservationV0` keeps walking its own
    free-form `observed_parameters` -- so this asserts the contract does,
    directly, rather than inferring it from the adapter passing.
    """

    with pytest.raises(ValidationError):
        MechanismObservationV0(
            **{
                **shared_redirection(observed_parameters={"effectiveness": 1}),
                "schema_version": "outcome-mechanism/v0.1",
            }
        )


@pytest.mark.parametrize("field", ["decision_ref", "execution_ref", "observation_id", "trace_id"])
def test_a_reference_with_edge_whitespace_is_refused(field):
    """AZ-06's own requirement, stricter than the contract's length bound.

    Fabric accepts `" decision-1 "`. That reference would compare unequal to
    the same one sent without the spaces, turning one evidence chain into two
    that look unrelated. AZ-06 refuses rather than normalizing, because
    normalizing means deciding what the producer meant.
    """

    assert MechanismObservationV0(
        **{**shared_redirection(), field: f" {shared_redirection()[field]} "}
    ), "the contract itself accepts this; the refusal below must be AZ-06's own"

    with pytest.raises(ValueError, match="trimmed"):
        producer_redirection_from_shared_mechanism(
            shared_redirection(**{field: f" {shared_redirection()[field]} "})
        )


def test_a_field_the_contract_defaults_must_still_be_sent():
    """Exact field set, not "whatever Fabric can fill in".

    `limitations` and `evidence_refs` have defaults in the contract, so Fabric
    would accept a payload with neither. AZ-06 will not: a producer that did
    not say is not the same as a producer that said nothing applies.
    """

    payload = shared_redirection()
    del payload["limitations"]
    assert MechanismObservationV0(**payload), "the contract accepts the omission"

    with pytest.raises(ValueError, match="fields do not match"):
        producer_redirection_from_shared_mechanism(payload)


def test_empty_evidence_refs_are_refused_though_the_contract_allows_them():
    assert MechanismObservationV0(**shared_redirection(evidence_refs=[]))

    with pytest.raises(ValueError, match="evidence refs"):
        producer_redirection_from_shared_mechanism(shared_redirection(evidence_refs=[]))


@pytest.mark.parametrize(
    ("overrides", "match"),
    [
        ({"mechanism_kind": "traffic_shaping"}, "observed redirection"),
        ({"status": "unverified"}, "not independently observed"),
        ({"schema_version": "outcome-mechanism/v9"}, "unsupported"),
        ({"authority_class": "arbiter_decision"}, "authority class"),
    ],
)
def test_az06_narrowing_still_fails_closed(overrides, match):
    """The narrowing is policy, and policy did not move.

    Delegating the contract to Fabric must not quietly widen what Presented
    Terrain will stand behind: Fabric's vocabulary has six mechanisms and six
    statuses, and AZ-06 accepts exactly one of each.
    """

    with pytest.raises(ValueError, match=match):
        producer_redirection_from_shared_mechanism(shared_redirection(**overrides))


def test_reading_a_mechanism_fact_grants_no_authority():
    """Consuming is not selecting.

    The projected evidence carries references and nothing actionable: no
    provider parameters, no command, no target, no mechanism AZ-06 could
    apply. `ProducerRedirectionEvidence` has nowhere to put one.
    """

    projected = producer_redirection_from_shared_mechanism(
        shared_redirection(observed_parameters={"route_readback": "present", "next_hop": "10.0.0.1"})
    )
    carried = projected.model_dump(mode="json")

    assert "observed_parameters" not in carried
    assert "next_hop" not in json.dumps(carried)
    for banned in ("command", "execute", "approve", "target", "apply"):
        assert not any(banned in key for key in carried), carried


# --------------------------------------------------------------------------
# the producer side: what AZ-06 emits is a record Fabric built
# --------------------------------------------------------------------------


def test_the_exported_observation_is_a_fabric_record():
    payload = presented_terrain_lifecycle_outcome(snapshot(), observed_at="2026-08-26T00:00:02Z")

    # Round-tripping through the model must be a no-op. Anything this module
    # added, dropped or spelled differently shows up here.
    assert OutcomeObservationV0(**payload).model_dump(mode="json") == payload
    assert payload["schema_version"] == "outcome-observation/v0.1"
    assert payload["authority_class"] == "producer_outcome_fact"
    assert payload["producer_product"] == "azazel-deception"


def test_the_exported_observation_joins_the_producers_evidence_chain():
    """Why AZ-06 reads the mechanism fact at all.

    The observation it emits names the consumed fact's decision, execution and
    mechanism. Those refs now come from a record Fabric validated rather than
    from three strings taken on trust.
    """

    fact = producer_redirection_from_shared_mechanism(shared_redirection())
    payload = presented_terrain_lifecycle_outcome(
        snapshot(
            producer_decision_ref=fact.decision_ref,
            producer_execution_ref=fact.execution_ref,
            producer_mechanism_ref=fact.mechanism_observation_ref,
        ),
        observed_at="2026-08-26T00:00:02Z",
    )

    assert payload["decision_ref"] == "decision-1"
    assert payload["execution_ref"] == "execution-1"
    assert payload["mechanism_observation_ref"] == "mechanism-1"
    assert payload["trace_id"] == "trace-1"


@pytest.mark.parametrize("key", ["effectiveness", "initiative_score", "tactical_effect"])
def test_a_tactical_claim_in_caller_supplied_coverage_is_refused(key):
    """`telemetry_coverage` and `resource_impact` come from the caller.

    They are free-form `dict[str, Any]` in the contract, so `extra="forbid"`
    does not look inside them. A verdict smuggled there would ride out on a
    record whose whole purpose is to carry no verdict.
    """

    with pytest.raises(ValueError):
        presented_terrain_lifecycle_outcome(
            snapshot(), observed_at="2026-08-26T00:00:02Z", telemetry_coverage={key: 1}
        )
    with pytest.raises(ValueError):
        presented_terrain_lifecycle_outcome(
            snapshot(), observed_at="2026-08-26T00:00:02Z", resource_impact={key: 1}
        )


def test_attacker_intent_stays_refused_though_the_contract_does_not_name_it():
    """AZ-06's refusal set is kept, not replaced.

    Fabric refuses `attacker_belief` but not `attacker_intent`. What an
    adversary *intended* is the claim this lane exists to not make, so AZ-06
    keeps refusing it whether or not the shared contract ever names it.
    """

    from azazel_fabric.outcome_contracts import validation as fabric_validation

    assert not fabric_validation._is_forbidden_key("attacker_intent"), (
        "the contract now names this; the local refusal is no longer the only one"
    )
    with pytest.raises(ValueError, match="forbidden"):
        presented_terrain_lifecycle_outcome(
            snapshot(),
            observed_at="2026-08-26T00:00:02Z",
            telemetry_coverage={"attacker_intent": "recon"},
        )


def _nested(levels: int) -> dict:
    value: object = "leaf"
    for index in range(levels):
        value = {f"l{levels - index}": value}
    return value  # type: ignore[return-value]


def test_the_stricter_of_the_two_depth_limits_applies():
    """Both walks run, so the effective limit is whichever is tighter.

    AZ-06 caps nesting at 5 where the contract allows 6, counted from the same
    root. Five levels is therefore the one depth that distinguishes them, and
    it is the only depth this test can use: at six both refuse, and a test
    written there would pass with AZ-06's ceiling raised or removed.
    """

    # Four levels: inside both limits, so the fixture is not simply invalid.
    assert presented_terrain_lifecycle_outcome(
        snapshot(), observed_at="2026-08-26T00:00:02Z", telemetry_coverage=_nested(4)
    )

    with pytest.raises(ValueError, match="depth"):
        presented_terrain_lifecycle_outcome(
            snapshot(), observed_at="2026-08-26T00:00:02Z", telemetry_coverage=_nested(5)
        )


def test_the_whole_consumed_payload_is_size_bounded_not_only_its_fact_maps():
    """The contract bounds `observed_parameters`; AZ-06 bounds the record.

    `MechanismObservationV0` caps the fact map at 64 KiB and caps
    `evidence_refs` at 64 entries of 2048 characters each -- which is about
    128 KiB that the model accepts and this adapter must not. The refusal has
    to come before anything is read out of the payload, since the parameters
    are discarded and would otherwise never be weighed at all.
    """

    huge = shared_redirection(evidence_refs=["x" * 2048] * 64)
    assert MechanismObservationV0(**huge), "the contract itself accepts this"

    with pytest.raises(ValueError, match="canonical size"):
        producer_redirection_from_shared_mechanism(huge)


def test_the_exported_observation_carries_no_success_or_belief():
    payload = presented_terrain_lifecycle_outcome(snapshot(), observed_at="2026-08-26T00:00:02Z")
    encoded = json.dumps(payload).lower()

    for claim in ("tactical_effect", "effect_class", "attacker_belief", '"success"', "divert"):
        assert claim not in encoded, claim
