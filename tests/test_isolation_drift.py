"""SO-08 detection half, record format, and the harness's refusal to go green.

The namespace lab itself needs root and Linux, so it is not run here; it is
run by ``make so08-virtual-lab`` in a privileged Linux environment. What runs
here is everything that decides what a run *means*: the declared drift kinds,
the observer writing to the real evidence chain, the record validator, and
the harness's measurement and exit-status logic driven by an in-memory lab.
"""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

from azazel_deception.runtime import so08_record as rec
from azazel_deception.runtime.isolation_drift import (
    DRIFT_KIND_POLICY_TWIN,
    DRIFT_KINDS,
    DRIFT_STAGE,
    IsolationDriftObserver,
    recorded_drift,
)
from azazel_deception.runtime.observation_export import export_observations
from azazel_deception.runtime.state import RuntimeStateStore

ROOT = Path(__file__).resolve().parents[1]
HARNESS_PATH = ROOT / "scripts/dev/so08_drift_lab.py"
DOC = ROOT / "docs/so08-isolation-drift.md"


def _load_harness():
    spec = importlib.util.spec_from_file_location("so08_drift_lab", HARNESS_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _empty() -> dict[str, frozenset[str]]:
    return {kind: frozenset() for kind in DRIFT_KINDS}


def _observer(tmp_path: Path) -> tuple[RuntimeStateStore, IsolationDriftObserver]:
    state = RuntimeStateStore(tmp_path / "state")
    return state, IsolationDriftObserver(
        state, environment_id="env-1", package_id="pkg-1", node_id="node-1"
    )


# --- declared kinds ---------------------------------------------------------


def test_drift_kinds_are_declared_once_and_each_has_a_policy_twin():
    assert DRIFT_KINDS == ("route_to_protected", "published_port", "capability_regranted")
    assert set(DRIFT_KIND_POLICY_TWIN) == set(DRIFT_KINDS)


def test_policy_twins_are_real_static_policy_violations(tmp_path):
    """Each twin name is one runtime/policy.py actually emits, not a new vocabulary."""

    from azazel_deception.runtime.policy import validate_compose_policy

    compose = tmp_path / "compose.yaml"
    compose.write_text(
        "networks:\n  ext: {}\n"
        "services:\n  web:\n    image: x\n    ports: ['80:80']\n    cap_add: [NET_ADMIN]\n"
        "    networks: [ext]\n",
        encoding="utf-8",
    )
    emitted = validate_compose_policy(compose)
    for twin in DRIFT_KIND_POLICY_TWIN.values():
        assert any(twin in violation for violation in emitted), (twin, emitted)


# --- observer ---------------------------------------------------------------


def test_new_finding_is_recorded_in_the_real_evidence_chain(tmp_path):
    state, observer = _observer(tmp_path)
    snap = _empty()
    snap["route_to_protected"] = frozenset({"eth0:10.0.2.0/24:via:10.0.1.1"})

    events = observer.observe(snap)

    assert len(events) == 1
    records = recorded_drift(state, "env-1")
    assert len(records) == 1
    assert records[0]["event_type"] == "failure"
    assert records[0]["metadata"]["stage"] == DRIFT_STAGE
    assert records[0]["metadata"]["drift_kind"] == "route_to_protected"
    assert records[0]["metadata"]["authority"] == "descriptive_only"
    assert state.verify_evidence_chain("env-1") is True


def test_a_persisting_finding_is_recorded_once_and_again_after_it_clears(tmp_path):
    state, observer = _observer(tmp_path)
    snap = _empty()
    snap["published_port"] = frozenset({"tcp:18080"})
    observer.observe(snap)
    observer.observe(snap)
    assert len(recorded_drift(state, "env-1")) == 1

    observer.observe(_empty())  # cleared: nothing recorded (AZ-06 did not withdraw it)
    assert len(recorded_drift(state, "env-1")) == 1

    observer.observe(snap)
    assert len(recorded_drift(state, "env-1")) == 2
    assert state.verify_evidence_chain("env-1") is True


def test_drift_is_not_relayed_as_attacker_interaction(tmp_path):
    """A route appearing is not attacker contact; it must not reach Knowledge as one."""

    state, observer = _observer(tmp_path)
    snap = _empty()
    snap["capability_regranted"] = frozenset({"pid:42:CapEff:000001ffffffffff"})
    observer.observe(snap)
    assert export_observations(state, "env-1") == []


@pytest.mark.parametrize(
    "snapshot",
    [
        {"route_to_protected": frozenset()},  # kinds missing: "not observed" != "no drift"
        {**{k: frozenset() for k in DRIFT_KINDS}, "dns_drift": frozenset()},  # undeclared
        {**{k: frozenset() for k in DRIFT_KINDS}, "published_port": "tcp:80"},  # not a set
        {**{k: frozenset() for k in DRIFT_KINDS}, "published_port": frozenset({" tcp:80"})},
    ],
)
def test_a_malformed_snapshot_is_refused_not_read_as_no_drift(tmp_path, snapshot):
    state, observer = _observer(tmp_path)
    with pytest.raises(ValueError):
        observer.observe(snapshot)
    assert recorded_drift(state, "env-1") == []


# --- harness with an in-memory lab ------------------------------------------


class FakeLab:
    """In-memory stand-in: lets the measurement logic run without namespaces.

    Its backend is not the virtual-lab backend, so a record it produces is
    refused by the validator — it can exercise the harness, never stand in for
    a lab run.
    """

    backend = "test-fake"

    def __init__(self, *, setup_error: Exception | None = None, detect: bool = True):
        self.findings = _empty()
        self.setup_error = setup_error
        self.detect = detect
        self.torn_down = False

    def describe(self) -> dict[str, Any]:
        return {"fake": True}

    def setup(self) -> None:
        if self.setup_error is not None:
            raise self.setup_error

    def teardown(self) -> None:
        self.torn_down = True

    def sample(self) -> dict[str, frozenset[str]]:
        return dict(self.findings) if self.detect else _empty()

    def inject(self, kind: str) -> Any:
        self.findings[kind] = frozenset({f"{kind}-finding"})
        return None

    def revert(self, kind: str, handle: Any) -> None:
        self.findings[kind] = frozenset()

    def probe(self) -> bool:
        return bool(self.findings["route_to_protected"])

    def control_probe(self) -> bool:
        return True


@pytest.fixture
def harness(monkeypatch):
    module = _load_harness()
    monkeypatch.setattr(module, "POLL_INTERVAL_S", 0.005)
    monkeypatch.setattr(module, "SAMPLE_TIMEOUT_S", 0.5)
    monkeypatch.setattr(module, "SETTLE_TIMEOUT_S", 2.0)
    return module


def test_harness_measures_every_kind_and_never_reports_pass(harness, tmp_path):
    record, status = harness.run_lab(FakeLab(), state_root=tmp_path / "s", samples_per_kind=3)

    assert record["executed"] is True
    assert status == harness.EXIT_DETECTION_WITHIN_BOUND
    detection, withdrawal = record["parts"]
    assert [s["drift_kind"] for s in detection["samples"]] == [
        k for k in DRIFT_KINDS for _ in range(3)
    ]
    for sample in detection["samples"]:
        assert sample["end_monotonic_ns"] >= sample["start_monotonic_ns"]
        assert sample["evidence_event_id"].startswith("so08-virtual-lab-isolation-drift-")
    assert detection["verdict"] == "pass"
    # Withdrawal is Edge's enforcement; nothing here performs it.
    assert withdrawal["verdict"] == "not_measurable"
    assert all(s["end_monotonic_ns"] is None for s in withdrawal["samples"])
    assert withdrawal["gaps"][0]["refs"] == [rec.EDGE_WITHDRAWAL_GAP_REF]
    assert record["verdict"] == "not_measurable"
    assert record["class"] == "virtual-lab-regression"
    assert record["gate"] is False
    assert record["product_configuration"]["commissioned_identity"] == rec.VIRTUAL_LAB_NO_IDENTITY


def test_an_undetected_drift_is_an_unfinished_violation(harness, tmp_path):
    record, status = harness.run_lab(
        FakeLab(detect=False), state_root=tmp_path / "s", samples_per_kind=1
    )
    assert status == harness.EXIT_DETECTION_REGRESSION
    detection = record["parts"][0]
    assert detection["verdict"] == "fail"
    assert detection["pass_rule"]["evaluated"]["unfinished_samples"] == len(DRIFT_KINDS)
    assert record["verdict"] == "fail"


def test_lab_unavailable_is_not_executed_never_green(harness, tmp_path):
    lab = FakeLab(setup_error=harness.LabUnavailable("not root"))
    record, status = harness.run_lab(lab, state_root=tmp_path / "s")
    assert status == harness.EXIT_NOT_EXECUTED != 0
    assert record["executed"] is False
    assert record["not_executed_reason"] == "not root"
    assert record["verdict"] == "not_measurable"
    assert all(p["verdict"] == "not_measurable" for p in record["parts"])
    assert lab.torn_down is True


def test_an_unexpected_harness_error_is_also_not_executed(harness, tmp_path):
    record, status = harness.run_lab(
        FakeLab(setup_error=RuntimeError("boom")), state_root=tmp_path / "s"
    )
    assert status == harness.EXIT_NOT_EXECUTED
    assert record["verdict"] == "not_measurable"


def test_main_refuses_green_for_a_record_the_validator_rejects(harness, tmp_path):
    """A test double's run must not exit 0 through the CLI path."""

    out = tmp_path / "record.json"
    status = harness.main(["--output", str(out)], lab=FakeLab())
    assert status == harness.EXIT_NOT_EXECUTED
    written = json.loads(out.read_text())
    assert any("lab_backend" in p for p in written["validation_problems"])


def test_namespace_lab_preflight_refuses_without_privileges(harness, monkeypatch):
    monkeypatch.setattr(harness.sys, "platform", "linux")
    monkeypatch.setattr(harness.os, "geteuid", lambda: 1000)
    with pytest.raises(harness.LabUnavailable, match="not root"):
        harness.NamespaceLab().preflight()


def test_namespace_lab_off_linux_is_not_executed(harness, monkeypatch, tmp_path):
    monkeypatch.setattr(harness.sys, "platform", "darwin")
    record, status = harness.run_lab(harness.NamespaceLab(), state_root=tmp_path / "s")
    assert status == harness.EXIT_NOT_EXECUTED
    assert "not Linux" in record["not_executed_reason"]


# --- record validator --------------------------------------------------------


@pytest.fixture(scope="module")
def _full_fake_record(tmp_path_factory) -> dict[str, Any]:
    """One full-size (20 per kind) run, shared: the validator tests only read it."""

    module = _load_harness()
    module.POLL_INTERVAL_S = 0.005
    module.SAMPLE_TIMEOUT_S = 0.5
    module.SETTLE_TIMEOUT_S = 2.0
    record, _ = module.run_lab(FakeLab(), state_root=tmp_path_factory.mktemp("so08"))
    # Stand in for what only a real lab run provides, so the validator's other
    # rules can be exercised one at a time.
    record["product_configuration"]["lab_backend"] = rec.VIRTUAL_LAB_BACKEND
    record["owner"]["commit"] = "0" * 40
    return record


@pytest.fixture
def virtual_record(_full_fake_record) -> dict[str, Any]:
    return copy.deepcopy(_full_fake_record)


def test_a_full_virtual_lab_record_validates(virtual_record):
    record = virtual_record
    assert rec.validate_record(record) == []


@pytest.mark.parametrize(
    "mutate, needle",
    [
        (lambda r: r.__setitem__("gate", True), "gate: false"),
        (lambda r: r.__setitem__("verdict", "pass"), "can never pass"),
        (lambda r: r.__setitem__("verdict", "skipped"), "no 'skip'"),
        (lambda r: r["parts"][1].__setitem__("gaps", []), "withdrawal"),
        (
            lambda r: r["product_configuration"].__setitem__("commissioned_identity", "eth0"),
            "commissioned_identity",
        ),
        (lambda r: r["parts"][0]["pass_rule"].__setitem__("bound_ms", 3000.0), "fixed"),
        (lambda r: r["parts"][0]["samples"].pop(), "20 required"),
        (lambda r: r["parts"][0]["samples"][0].__setitem__("end_monotonic_ns", None),
         "does not match"),
        (lambda r: r["owner"].__setitem__("commit", "unavailable"), "40-hex"),
    ],
)
def test_validator_refuses_a_record_claiming_more_than_it_shows(
    virtual_record, mutate, needle
):
    record = virtual_record
    mutate(record)
    problems = rec.validate_record(record)
    assert any(needle in p for p in problems), problems


def _hil_record(record: dict[str, Any]) -> dict[str, Any]:
    record["class"] = rec.CLASS_HIL
    record["gate"] = True
    record["product_configuration"]["lab_backend"] = "field-segment"
    record["product_configuration"]["commissioned_identity"] = "site-a/az06-node-07/seg-decoy-2"
    record["field_exercise"] = {
        "performed_at_utc": "2026-11-01T00:00:00Z",
        "operator": "operator-ref",
        "site_ref": "site-a",
        "protected_network_ref": "seg-prod-1",
        "edge": {"repository": "01rabbit/Azazel-Edge", "commit": "1" * 40,
                 "authority_path_ref": "Azazel-Edge#412"},
    }
    return record


def test_a_hil_record_cannot_pass_while_withdrawal_is_unmeasured(virtual_record):
    record = _hil_record(virtual_record)
    assert rec.validate_record(record) == []
    assert record["verdict"] == "not_measurable"
    bad = copy.deepcopy(record)
    bad["verdict"] = "pass"
    assert any("parts give" in p for p in rec.validate_record(bad))


@pytest.mark.parametrize("identity", ["", "eth0", "br0", "enp3s0", rec.VIRTUAL_LAB_NO_IDENTITY])
def test_a_hil_record_needs_a_commissioned_identity(virtual_record, identity):
    record = _hil_record(virtual_record)
    record["product_configuration"]["commissioned_identity"] = identity
    assert any("commissioned" in p for p in rec.validate_record(record))


def test_a_hil_record_cannot_come_from_the_virtual_lab(virtual_record):
    record = _hil_record(virtual_record)
    record["product_configuration"]["lab_backend"] = rec.VIRTUAL_LAB_BACKEND
    assert any("virtual-lab backend" in p for p in rec.validate_record(record))


def test_targets_are_the_section_8_values():
    assert rec.DETECTION_BOUND_MS == 2000.0
    assert rec.WITHDRAWAL_BOUND_MS == 5000.0
    assert rec.SAMPLES_PER_KIND == 20


def test_the_record_format_doc_names_the_kinds_and_the_validator():
    text = DOC.read_text(encoding="utf-8")
    for kind in DRIFT_KINDS:
        assert f"`{kind}`" in text, kind
    assert "azazel_deception.runtime.so08_record.validate_record" in text
    assert rec.FIELD_EXERCISE_DIR in text
    assert "No green CI run satisfies the SO-08 HIL gate" in text
