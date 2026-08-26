from __future__ import annotations

import pytest
from pydantic import ValidationError

from azazel_deception.runtime.presented_terrain import (
    PresentedTerrainSnapshotV0,
    ProducerRedirectionEvidence,
    build_presented_terrain_snapshot,
    canonical_snapshot_json,
)


def producer(**overrides):
    data = {
        "producer_product": "azazel-edge",
        "trace_id": "trace-1",
        "decision_ref": "decision-1",
        "execution_ref": "execution-1",
        "mechanism_observation_ref": "mechanism-1",
        "mechanism_kind": "redirection",
        "status": "observed",
        "evidence_refs": ["edge:nft:1"],
    }
    data.update(overrides)
    return ProducerRedirectionEvidence(**data)


def active_state():
    return {
        "environment_id": "env-1",
        "state": "active",
        "package_id": "municipal-linux-v1",
        "package_digest": "sha256:abc123",
        "node_id": "deception-node-1",
        "decision_id": "legacy-runtime-decision-id",
        "activated_at": "2026-08-26T00:00:00+00:00",
    }


def build(**overrides):
    data = {
        "environment_id": "env-1",
        "producer": producer(),
        "runtime_state": active_state(),
        "expected_package_id": "municipal-linux-v1",
        "expected_package_digest": "sha256:abc123",
        "package_version": "1.0.0",
        "observed_at": "2026-08-26T00:00:02Z",
        "active_surface_refs": ("surface:http:8080",),
        "isolation_assertion_refs": ("isolation:net:none",),
        "runtime_verified_active": True,
        "evidence_refs": ("runtime:inspect:1",),
    }
    data.update(overrides)
    return build_presented_terrain_snapshot(**data)


def test_active_snapshot_requires_observed_redirection_not_divert():
    snapshot = build()
    assert snapshot.lifecycle_state == "active"
    assert snapshot.producer_mechanism_kind == "redirection"
    assert "effect_class" not in snapshot.model_dump()
    assert "divert" not in snapshot.model_dump_json().lower()
    assert snapshot.executable is False


def test_producer_cannot_claim_divert_as_mechanism():
    with pytest.raises(ValidationError):
        producer(mechanism_kind="divert")
    with pytest.raises(ValidationError):
        producer(status="unverified")


def test_persisted_active_state_without_independent_readback_becomes_stale():
    snapshot = build(runtime_verified_active=False)
    assert snapshot.lifecycle_state == "stale"
    assert snapshot.active_surface_refs == ()
    assert "runtime_active_not_independently_verified" in snapshot.limitations


def test_package_provenance_mismatch_fails_closed():
    with pytest.raises(ValueError, match="package provenance"):
        build(expected_package_digest="sha256:other")
    with pytest.raises(ValueError, match="package provenance"):
        build(expected_package_id="other")


def test_cross_environment_runtime_state_fails_closed():
    state = active_state()
    state["environment_id"] = "other"
    with pytest.raises(ValueError, match="environment"):
        build(runtime_state=state)


def test_active_snapshot_requires_actual_surface_evidence():
    with pytest.raises(ValidationError, match="active surface"):
        build(active_surface_refs=())


def test_terminal_reset_requires_reset_evidence():
    state = active_state()
    state.update({"state": "reset", "reset_at": "2026-08-26T00:10:00Z"})
    with pytest.raises(ValidationError, match="reset evidence"):
        build(runtime_state=state, runtime_verified_active=False, active_surface_refs=())
    snapshot = build(
        runtime_state=state,
        runtime_verified_active=False,
        active_surface_refs=(),
        reset_ref="reset:proof:1",
    )
    assert snapshot.lifecycle_state == "reset"
    assert snapshot.ended_at == "2026-08-26T00:10:00Z"


def test_secret_or_effectiveness_fields_have_no_schema_surface():
    payload = build().model_dump()
    payload["credential_secret"] = "secret"
    with pytest.raises(ValidationError):
        PresentedTerrainSnapshotV0.model_validate(payload)
    payload = build().model_dump()
    payload["attacker_belief"] = "fooled"
    with pytest.raises(ValidationError):
        PresentedTerrainSnapshotV0.model_validate(payload)
    payload = build().model_dump()
    payload["success"] = True
    with pytest.raises(ValidationError):
        PresentedTerrainSnapshotV0.model_validate(payload)


def test_credential_refs_are_refs_only_and_canonical_json_is_stable():
    snapshot = build(synthetic_credential_refs=("credential:lure:42",))
    one = canonical_snapshot_json(snapshot)
    two = canonical_snapshot_json(PresentedTerrainSnapshotV0.model_validate_json(one))
    assert one == two
    assert "credential:lure:42" in one
