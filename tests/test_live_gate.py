"""Live-flip gate readiness validator (canonical-cutover Step 4 pre-work)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from azazel_deception.runtime.live_gate import (
    LIVE_GATES,
    REQUIRED_LIVE_GATE_IDS,
    LiveGateCertification,
    evaluate_live_gate_readiness,
    gate_category,
)


def _cert(gate_id: str, *, certified=True, evidence="lab-report-1") -> dict:
    return {
        "gate_id": gate_id,
        "certified": certified,
        "evidence_ref": evidence,
        "certifier": "hil-lab",
        "certified_as_of": "2026-08-22T00:00:00+00:00",
    }


def _all_certs() -> list[dict]:
    return [_cert(g) for g in REQUIRED_LIVE_GATE_IDS]


def test_required_gate_set_is_non_empty_and_covers_hil_kill_switch():
    # Guard: the required set must not silently collapse, and must include the
    # kill-switch-under-compromise HIL residual that was buried in the checklist.
    assert len(REQUIRED_LIVE_GATE_IDS) >= 8
    assert "hil_kill_switch_against_live_attacker_modified_container" in REQUIRED_LIVE_GATE_IDS
    # every gate has a known category
    assert all(gate_category(g) in {"hil", "portability", "deployment", "software"}
               for g in REQUIRED_LIVE_GATE_IDS)
    # LIVE_GATES ids are unique
    ids = [g[0] for g in LIVE_GATES]
    assert len(ids) == len(set(ids))


def test_empty_bundle_is_not_ready_and_everything_missing():
    result = evaluate_live_gate_readiness([])
    assert result.ready is False
    assert set(result.missing_gate_ids) == set(REQUIRED_LIVE_GATE_IDS)
    assert result.satisfied_gate_ids == []
    assert result.uncertified_gate_ids == []


def test_all_certified_with_evidence_is_ready():
    result = evaluate_live_gate_readiness(_all_certs())
    assert result.ready is True
    assert set(result.satisfied_gate_ids) == set(REQUIRED_LIVE_GATE_IDS)
    assert result.missing_gate_ids == []
    assert result.uncertified_gate_ids == []


def test_one_missing_gate_blocks_readiness():
    certs = _all_certs()[:-1]  # drop the last required gate
    dropped = REQUIRED_LIVE_GATE_IDS[-1]
    result = evaluate_live_gate_readiness(certs)
    assert result.ready is False
    assert dropped in result.missing_gate_ids


def test_certified_true_but_no_evidence_is_uncertified_fail_closed():
    certs = _all_certs()
    certs[0] = _cert(REQUIRED_LIVE_GATE_IDS[0], certified=True, evidence="   ")
    result = evaluate_live_gate_readiness(certs)
    assert result.ready is False
    assert REQUIRED_LIVE_GATE_IDS[0] in result.uncertified_gate_ids


def test_certified_false_is_uncertified():
    certs = _all_certs()
    certs[0] = _cert(REQUIRED_LIVE_GATE_IDS[0], certified=False)
    result = evaluate_live_gate_readiness(certs)
    assert result.ready is False
    assert REQUIRED_LIVE_GATE_IDS[0] in result.uncertified_gate_ids


def test_unknown_gate_id_never_contributes_to_readiness():
    certs = _all_certs() + [_cert("some_made_up_gate")]
    result = evaluate_live_gate_readiness(certs)
    assert result.ready is True  # the real ones are all satisfied
    assert result.unknown_gate_ids == ["some_made_up_gate"]


def test_unknown_gate_id_alone_is_not_ready():
    result = evaluate_live_gate_readiness([_cert("some_made_up_gate")])
    assert result.ready is False
    assert result.unknown_gate_ids == ["some_made_up_gate"]
    assert set(result.missing_gate_ids) == set(REQUIRED_LIVE_GATE_IDS)


def test_extra_field_in_certification_is_rejected():
    bad = _cert(REQUIRED_LIVE_GATE_IDS[0])
    bad["force_ready"] = True
    with pytest.raises(ValidationError):
        evaluate_live_gate_readiness([bad])


def test_result_is_deterministic():
    certs = _all_certs()
    first = evaluate_live_gate_readiness(certs)
    second = evaluate_live_gate_readiness(certs)
    assert first.model_dump() == second.model_dump()


def test_accepts_model_instances_and_single_use_iterator():
    models = (LiveGateCertification.model_validate(_cert(g)) for g in REQUIRED_LIVE_GATE_IDS)
    result = evaluate_live_gate_readiness(models)  # generator: single-use
    assert result.ready is True


def test_empty_required_set_is_never_vacuously_ready():
    # Fail-closed: an empty required set must not report ready with zero evidence
    # (guards against a caller passing required=[] or a set that collapsed).
    assert evaluate_live_gate_readiness([], required=[]).ready is False
    assert evaluate_live_gate_readiness(_all_certs(), required=[]).ready is False


def test_readiness_authorizes_nothing_it_is_only_a_precondition():
    # A ready result carries no authority token / live flag — it is a plain
    # readiness report. This documents that the flip still needs human sign-off.
    result = evaluate_live_gate_readiness(_all_certs())
    dumped = result.model_dump()
    assert set(dumped) == {
        "ready", "satisfied_gate_ids", "missing_gate_ids",
        "uncertified_gate_ids", "unknown_gate_ids",
    }
