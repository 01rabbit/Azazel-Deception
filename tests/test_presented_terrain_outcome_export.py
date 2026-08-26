from __future__ import annotations

import json

import pytest

from azazel_deception.runtime.outcome_export import (
    canonical_outcome_json,
    presented_terrain_lifecycle_outcome,
)
from azazel_deception.runtime.presented_terrain import PresentedTerrainSnapshotV0


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


def test_active_snapshot_projects_during_lifecycle_fact_without_divert_claim():
    payload = presented_terrain_lifecycle_outcome(
        snapshot(), observed_at="2026-08-26T00:00:02Z"
    )
    assert payload["schema_version"] == "outcome-observation/v0.1"
    assert payload["phase"] == "during"
    assert payload["mechanism_observation_ref"] == "mechanism-1"
    encoded = canonical_outcome_json(payload).lower()
    assert "tactical_effect" not in encoded
    assert "effect_class" not in encoded
    assert "attacker_belief" not in encoded
    assert '"success"' not in encoded


def test_terminal_snapshot_projects_after_and_preserves_reset_proof():
    payload = presented_terrain_lifecycle_outcome(
        snapshot(
            lifecycle_state="reset",
            active_surface_refs=(),
            ended_at="2026-08-26T00:10:00Z",
            reset_ref="reset:proof:1",
        ),
        observed_at="2026-08-26T00:10:01Z",
    )
    assert payload["phase"] == "after"
    assert payload["window_end"] == "2026-08-26T00:10:00Z"
    assert payload["observation_values"]["reset_ref"] == "reset:proof:1"


def test_stale_snapshot_is_not_rounded_to_after():
    with pytest.raises(ValueError, match="stale Presented Terrain"):
        presented_terrain_lifecycle_outcome(
            snapshot(
                lifecycle_state="stale",
                active_surface_refs=(),
                limitations=("runtime_active_not_independently_verified",),
            ),
            observed_at="2026-08-26T00:00:02Z",
        )


def test_nested_tactical_or_belief_claim_is_rejected():
    with pytest.raises(ValueError, match="forbidden"):
        presented_terrain_lifecycle_outcome(
            snapshot(),
            observed_at="2026-08-26T00:00:02Z",
            telemetry_coverage={"nested": {"attacker-belief": "fooled"}},
        )
    with pytest.raises(ValueError, match="forbidden"):
        presented_terrain_lifecycle_outcome(
            snapshot(),
            observed_at="2026-08-26T00:00:02Z",
            resource_impact={"nested": {"tactical-effect": "divert"}},
        )


def test_same_input_is_byte_deterministic():
    payload = presented_terrain_lifecycle_outcome(
        snapshot(), observed_at="2026-08-26T00:00:02Z"
    )
    first = canonical_outcome_json(payload)
    second = canonical_outcome_json(json.loads(first))
    assert first == second
