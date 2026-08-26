from __future__ import annotations

import json
from pathlib import Path

from azazel_deception.runtime.outcome_export import presented_terrain_lifecycle_outcome
from azazel_deception.runtime.presented_terrain import PresentedTerrainSnapshotV0


FIXTURE = Path(__file__).parent / "fixtures" / "outcome" / "cross_product_presented_terrain_outcome_v0.json"


def test_presented_terrain_export_matches_cross_product_fixture_exactly():
    snapshot = PresentedTerrainSnapshotV0(
        presentation_id="presentation-golden-1",
        environment_id="env-golden-1",
        producer_product="azazel-edge",
        producer_node="edge-golden-1",
        trace_id="trace-golden-redirect-1",
        producer_decision_ref="decision-golden-redirect-1",
        producer_execution_ref="execution-golden-redirect-1",
        producer_mechanism_ref="mechanism-golden-redirection-1",
        producer_mechanism_kind="redirection",
        package_id="municipal-linux-v1",
        package_version="1.0.0",
        package_digest="sha256:goldenabc123",
        runtime_node_id="deception-golden-1",
        lifecycle_state="active",
        active_surface_refs=("surface:http:8080",),
        synthetic_artifact_refs=(),
        synthetic_identity_refs=(),
        synthetic_credential_refs=(),
        started_at="2026-08-26T06:10:02Z",
        isolation_assertion_refs=("isolation:golden:1",),
        evidence_refs=("deception:runtime:golden:1",),
        observed_at="2026-08-26T06:10:03Z",
    )
    actual = presented_terrain_lifecycle_outcome(
        snapshot,
        observed_at="2026-08-26T06:10:03Z",
    )
    expected = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert actual == expected
    assert actual["phase"] == "during"
    encoded = json.dumps(actual).lower()
    assert "divert" not in encoded
    assert "attacker_belief" not in encoded
    assert '"success"' not in encoded
