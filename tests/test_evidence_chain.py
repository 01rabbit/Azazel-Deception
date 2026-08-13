"""Tamper-evident evidence hash chain."""

import json
from pathlib import Path

from azazel_deception.runtime.state import RuntimeStateStore


def _store(tmp_path):
    return RuntimeStateStore(tmp_path)


def _event(n):
    return {"event_id": f"e{n}", "event_type": "activated", "metadata": {"n": n}}


def test_empty_chain_verifies(tmp_path):
    store = _store(tmp_path)
    assert store.verify_evidence_chain("env-1") is True


def test_chain_verifies_and_sequences(tmp_path):
    store = _store(tmp_path)
    for n in range(3):
        store.append_evidence("env-1", _event(n))
    assert store.verify_evidence_chain("env-1") is True

    lines = store.evidence_path("env-1").read_text().splitlines()
    records = [json.loads(line) for line in lines]
    assert [r["_evidence_seq"] for r in records] == [0, 1, 2]
    assert records[0]["_evidence_prev"] == ""
    assert records[1]["_evidence_prev"] == records[0]["_evidence_hash"]
    assert records[2]["_evidence_prev"] == records[1]["_evidence_hash"]
    # Original event content is preserved alongside the chain metadata.
    assert records[0]["event_id"] == "e0"


def test_edited_event_breaks_chain(tmp_path):
    store = _store(tmp_path)
    for n in range(3):
        store.append_evidence("env-1", _event(n))
    path = store.evidence_path("env-1")
    records = [json.loads(line) for line in path.read_text().splitlines()]
    # Tamper with a field of the middle record, leaving its stored hash intact.
    records[1]["metadata"] = {"n": "TAMPERED"}
    path.write_text("\n".join(json.dumps(r, sort_keys=True) for r in records) + "\n")
    assert store.verify_evidence_chain("env-1") is False


def test_deleted_record_breaks_chain(tmp_path):
    store = _store(tmp_path)
    for n in range(3):
        store.append_evidence("env-1", _event(n))
    path = store.evidence_path("env-1")
    records = [json.loads(line) for line in path.read_text().splitlines()]
    del records[1]  # drop the middle record
    path.write_text("\n".join(json.dumps(r, sort_keys=True) for r in records) + "\n")
    assert store.verify_evidence_chain("env-1") is False


def test_reordered_records_break_chain(tmp_path):
    store = _store(tmp_path)
    for n in range(3):
        store.append_evidence("env-1", _event(n))
    path = store.evidence_path("env-1")
    records = [json.loads(line) for line in path.read_text().splitlines()]
    records[0], records[1] = records[1], records[0]
    path.write_text("\n".join(json.dumps(r, sort_keys=True) for r in records) + "\n")
    assert store.verify_evidence_chain("env-1") is False


def test_forged_hash_is_detected(tmp_path):
    store = _store(tmp_path)
    store.append_evidence("env-1", _event(0))
    path = store.evidence_path("env-1")
    record = json.loads(path.read_text().splitlines()[0])
    record["metadata"] = {"n": "TAMPERED"}
    # Recompute a *plausible* hash but over the wrong field set is impossible for
    # an attacker who cannot include the reserved hash key; simulate a naive
    # forgery that just overwrites the stored hash with garbage.
    record["_evidence_hash"] = "sha256:" + "0" * 64
    path.write_text(json.dumps(record, sort_keys=True) + "\n")
    assert store.verify_evidence_chain("env-1") is False
