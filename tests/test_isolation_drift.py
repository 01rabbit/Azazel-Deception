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


def test_reinjection_is_not_lost_to_the_detectors_in_flight_cycle(harness, tmp_path, monkeypatch):
    """The observer appends before it updates its active set.

    A harness that injected the next sample as soon as the previous record was
    readable could land the new drift inside that window, and the observer
    would treat it as already recorded — a missed detection. Widening the
    window makes the race near-certain if the harness does not wait for the
    detector to finish the cycle.
    """

    import time as _time

    original = RuntimeStateStore.append_evidence

    def slow_append(self, environment_id, event):
        path = original(self, environment_id, event)
        _time.sleep(0.03)
        return path

    monkeypatch.setattr(RuntimeStateStore, "append_evidence", slow_append)
    record, status = harness.run_lab(FakeLab(), state_root=tmp_path / "s", samples_per_kind=4)
    assert record["parts"][0]["pass_rule"]["evaluated"]["unfinished_samples"] == 0
    assert status == harness.EXIT_DETECTION_WITHIN_BOUND


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
        (lambda r: r["parts"][0].__setitem__("verdict", "fail"), "detection.verdict is"),
        (lambda r: r["parts"][1].__setitem__("verdict", "pass"), "withdrawal.verdict is"),
        (lambda r: r["parts"][0]["samples"][0].__setitem__("drift_kind", "dns"),
         "undeclared drift_kind"),
        (lambda r: r["parts"][0]["samples"].__setitem__(
            19, copy.deepcopy(r["parts"][0]["samples"][0])), "duplicate sample_id"),
        (lambda r: r["parts"][0]["samples"][0].__setitem__("evidence_event_id", None),
         "evidence_event_id"),
        (lambda r: r["parts"][0]["samples"][0].__setitem__("evidence_seq", True),
         "evidence_event_id"),
        (lambda r: r["parts"][1]["samples"].pop(), "withdrawal has 19"),
        (lambda r: r["parts"][1]["gaps"].append({"id": "x"}), "boolean blocks_verdict"),
    ],
)
def test_validator_refuses_a_record_claiming_more_than_it_shows(
    virtual_record, mutate, needle
):
    record = virtual_record
    mutate(record)
    problems = rec.validate_record(record)
    assert any(needle in p for p in problems), problems


IDENTITY = "az06-commission:site-a/az06-node-07/seg-decoy-2"


def _hil_record(record: dict[str, Any]) -> dict[str, Any]:
    record["class"] = rec.CLASS_HIL
    record["gate"] = True
    record["product_configuration"]["lab_backend"] = "field-segment"
    record["product_configuration"]["commissioned_identity"] = IDENTITY
    record["field_exercise"] = {
        "performed_at_utc": "2026-11-01T00:00:00Z",
        "operator": "operator-ref",
        "site_ref": "site-a",
        "protected_network_ref": "seg-prod-1",
        "edge": {"repository": "01rabbit/Azazel-Edge", "commit": "1" * 40,
                 "authority_path_ref": "01rabbit/Azazel-Edge#412"},
    }
    return record


def _measure_withdrawal(record: dict[str, Any], *, with_refs: bool = True) -> dict[str, Any]:
    """Pretend every withdrawal was measured at 1 s, as a future HIL run would."""

    part = record["parts"][1]
    for sample in part["samples"]:
        sample["end_monotonic_ns"] = sample["start_monotonic_ns"] + 1_000_000_000
        if with_refs:
            sample["edge_enforcement_event_ref"] = f"edge-enforcement:{sample['sample_id']}"
    part["pass_rule"]["evaluated"] = rec.evaluate_samples(
        part["samples"], bound_ms=rec.WITHDRAWAL_BOUND_MS
    )
    return record


def test_a_hil_record_cannot_pass_while_withdrawal_is_unmeasured(virtual_record):
    record = _hil_record(virtual_record)
    assert rec.validate_record(record) == []
    assert record["verdict"] == "not_measurable"
    bad = copy.deepcopy(record)
    bad["verdict"] = "pass"
    assert any("parts give" in p for p in rec.validate_record(bad))


def test_no_hil_record_can_pass_until_edge_declares_the_withdrawal_path(virtual_record):
    """Even fully measured, with the gap dropped and pass claimed, it is refused.

    The doc's "no HIL record can pass until Azazel-Edge#412" is this test.
    """

    assert rec.EDGE_WITHDRAWAL_PATH_DECLARED is False
    pristine = copy.deepcopy(virtual_record)
    record = _measure_withdrawal(_hil_record(virtual_record))
    record["parts"][1]["gaps"] = []
    record["parts"][1]["verdict"] = "pass"
    record["verdict"] = "pass"
    problems = rec.validate_record(record)
    assert any(rec.EDGE_WITHDRAWAL_GAP_ID in p for p in problems), problems

    # With the gap kept, the same measured record is not_measurable, not pass.
    kept = _measure_withdrawal(_hil_record(pristine))
    assert rec.validate_record(kept) == []
    assert kept["verdict"] == "not_measurable"


def test_the_reviewers_forged_hil_pass_is_refused(virtual_record):
    record = _measure_withdrawal(_hil_record(virtual_record))
    part = record["parts"][1]
    part["samples"] = part["samples"][:1]
    part["pass_rule"]["evaluated"] = rec.evaluate_samples(
        part["samples"], bound_ms=rec.WITHDRAWAL_BOUND_MS
    )
    part["gaps"] = []
    part["verdict"] = "pass"
    record["verdict"] = "pass"
    record["product_configuration"]["lab_backend"] = "netns2"
    problems = rec.validate_record(record)
    assert any(rec.EDGE_WITHDRAWAL_GAP_ID in p for p in problems), problems
    assert any("withdrawal has 0 samples" in p or "withdrawal has 1 samples" in p
               for p in problems), problems
    assert any("lab_backend" in p for p in problems), problems
    assert any("same injections" in p for p in problems), problems


def test_once_edge_declares_the_path_a_measured_hil_record_needs_edge_event_refs(
    virtual_record, monkeypatch
):
    """The future path: lifting the flag is a code change, and refs are still required."""

    monkeypatch.setattr(rec, "EDGE_WITHDRAWAL_PATH_DECLARED", True)
    record = _measure_withdrawal(_hil_record(virtual_record))
    record["parts"][1]["gaps"] = []
    record["parts"][1]["verdict"] = "pass"
    record["verdict"] = "pass"
    assert rec.validate_record(record) == []

    no_refs = copy.deepcopy(record)
    for sample in no_refs["parts"][1]["samples"]:
        sample.pop("edge_enforcement_event_ref")
    assert any("edge_enforcement_event_ref" in p for p in rec.validate_record(no_refs))


@pytest.mark.parametrize("value", [False, "false", None])
def test_the_edge_gap_must_block_the_verdict(virtual_record, value):
    virtual_record["parts"][1]["gaps"][0]["blocks_verdict"] = value
    assert any("blocks_verdict" in p for p in rec.validate_record(virtual_record))


def test_the_edge_gap_must_name_edge_412(virtual_record):
    virtual_record["parts"][1]["gaps"][0]["refs"] = ["somewhere-else"]
    assert any(rec.EDGE_WITHDRAWAL_GAP_REF in p for p in rec.validate_record(virtual_record))


@pytest.mark.parametrize(
    "identity",
    [
        "", "eth0", "ETH0", "br0", "enp3s0", "wwan0", "ppp0", "cni0", "dummy0", "vmbr0",
        "tailscale0", "lobby-3", "site-a/az06-node-07/seg-decoy-2",
        "az06-commission:site-a/node", "az06-commission:Site-A/node/seg",
        "az06-commission:site-a/node/seg/extra", "az06-commission:-a/node/seg",
        rec.VIRTUAL_LAB_NO_IDENTITY, 7,
        IDENTITY + "\n", IDENTITY + "\r\n", " " + IDENTITY,
        "az06-commission:sit\u00e9-a/node/seg",  # non-ASCII
    ],
)
def test_a_hil_record_refuses_anything_but_a_commissioned_identity(virtual_record, identity):
    record = _hil_record(virtual_record)
    record["product_configuration"]["commissioned_identity"] = identity
    assert any("commissioned" in p for p in rec.validate_record(record))


@pytest.mark.parametrize(
    "identity",
    [
        IDENTITY,
        "az06-commission:lobby-3/node-1/seg-decoy",
        "az06-commission:enterprise-site-1/eth0-closet/br0",  # names may contain such words
        "az06-commission:a/b/c",
    ],
)
def test_a_hil_record_accepts_a_commissioned_identity(virtual_record, identity):
    record = _hil_record(virtual_record)
    record["product_configuration"]["commissioned_identity"] = identity
    assert rec.validate_record(record) == []


@pytest.mark.parametrize("backend", [rec.VIRTUAL_LAB_BACKEND, "netns2", "", None, "test-fake"])
def test_a_hil_record_backend_is_a_positive_list(virtual_record, backend):
    record = _hil_record(virtual_record)
    record["product_configuration"]["lab_backend"] = backend
    assert any("lab_backend" in p for p in rec.validate_record(record))


@pytest.mark.parametrize(
    "mutate, needle",
    [
        (lambda e: e.__setitem__("commit", "1" * 39), "edge.commit"),
        (lambda e: e.__setitem__("commit", "G" * 40), "edge.commit"),
        (lambda e: e.__setitem__("repository", "someone/Azazel-Edge"), "edge.repository"),
        (lambda e: e.__setitem__("authority_path_ref", "anything"), "authority_path_ref"),
        (lambda e: e.__setitem__("authority_path_ref", "Azazel-Edge#412"), "authority_path_ref"),
        (lambda e: e.__setitem__("authority_path_ref", "01rabbit/Azazel-Edge#412\n"),
         "authority_path_ref"),
        (lambda e: e.__setitem__("authority_path_ref", "01rabbit/Azazel-Edge#\u0664"),
         "authority_path_ref"),
        (lambda e: e.__setitem__("commit", "1" * 40 + "\n"), "edge.commit"),
    ],
)
def test_a_hil_record_edge_fields_are_validated(virtual_record, mutate, needle):
    record = _hil_record(virtual_record)
    mutate(record["field_exercise"]["edge"])
    assert any(needle in p for p in rec.validate_record(record))


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


@pytest.mark.parametrize(
    "ref", ["edge-enforcement:evt-1\n", "edge-enforcement:evt-1\r\n", "edge-enforcement:",
            "edge-enforcement:\u00e9vt"],
)
def test_edge_enforcement_event_ref_must_match_exactly(virtual_record, monkeypatch, ref):
    monkeypatch.setattr(rec, "EDGE_WITHDRAWAL_PATH_DECLARED", True)
    record = _measure_withdrawal(_hil_record(virtual_record))
    record["parts"][1]["samples"][0]["edge_enforcement_event_ref"] = ref
    assert any("edge_enforcement_event_ref" in p for p in rec.validate_record(record))


def test_owner_commit_with_a_trailing_newline_is_refused(virtual_record):
    virtual_record["owner"]["commit"] = virtual_record["owner"]["commit"] + "\n"
    assert any("owner.commit" in p for p in rec.validate_record(virtual_record))


def test_drift_stage_literal_is_pinned():
    assert DRIFT_STAGE == "isolation_drift"


def test_evaluate_samples_refuses_booleans_as_times():
    result = rec.evaluate_samples(
        [{"start_monotonic_ns": True, "end_monotonic_ns": True},
         {"start_monotonic_ns": 0, "end_monotonic_ns": False}],
        bound_ms=rec.DETECTION_BOUND_MS,
    )
    assert result["unfinished_samples"] == 2
    assert result["holds"] is False


# --- observer restart and environment state ------------------------------------


def test_a_restarted_observer_never_reuses_an_event_id(tmp_path):
    state, first = _observer(tmp_path)
    snap = _empty()
    snap["published_port"] = frozenset({"tcp:18080"})
    first.observe(snap)

    second = IsolationDriftObserver(
        state, environment_id="env-1", package_id="pkg-1", node_id="node-1"
    )
    # Persistent drift is re-recorded once by a new observer (documented).
    second.observe(snap)
    ids = [r["event_id"] for r in recorded_drift(state, "env-1")]
    assert len(ids) == 2 and len(set(ids)) == 2, ids
    assert state.verify_evidence_chain("env-1") is True


def test_drift_after_termination_is_recorded_with_the_environment_state(tmp_path):
    """SO-08 is independent of runtime cleanup: drift outliving the decoy matters."""

    state, observer = _observer(tmp_path)
    snap = _empty()
    snap["route_to_protected"] = frozenset({"eth0:10.0.2.0/24:via:10.0.1.1"})
    observer.observe(snap)
    state.write("env-1", {"environment_id": "env-1", "state": "terminated"})
    observer.observe(_empty())
    observer.observe(snap)
    states = [r["metadata"]["environment_state"] for r in recorded_drift(state, "env-1")]
    assert states == ["absent", "terminated"]


# --- harness baseline abort --------------------------------------------------------


def test_a_drifted_baseline_aborts_as_not_executed(harness, tmp_path):
    lab = FakeLab()
    lab.findings["published_port"] = frozenset({"tcp:80"})
    record, status = harness.run_lab(lab, state_root=tmp_path / "s", samples_per_kind=1)
    assert status == harness.EXIT_NOT_EXECUTED
    assert "not isolated at baseline" in record["not_executed_reason"]
    assert record["prerequisites"][0] == {
        "id": "baseline_isolated", "met": False,
        "detail": "baseline already drifted: {'published_port': ['tcp:80']}",
    }
    assert record["parts"][0]["samples"] == []


def test_a_reachable_baseline_aborts_as_not_executed(harness, tmp_path):
    lab = FakeLab()
    lab.probe = lambda: True  # decoy already reaches the protected side
    record, status = harness.run_lab(lab, state_root=tmp_path / "s", samples_per_kind=1)
    assert status == harness.EXIT_NOT_EXECUTED
    assert "not isolated at baseline" in record["not_executed_reason"]
    assert record["prerequisites"][1]["met"] is False


# --- scripts/ci/assert_so08_record.py, as CI runs it -------------------------------

ASSERT_SCRIPT = ROOT / "scripts/ci/assert_so08_record.py"


def _run_assert(tmp_path: Path, record: dict[str, Any]):
    import subprocess
    import sys

    path = tmp_path / "record.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(ASSERT_SCRIPT), str(path)],
        capture_output=True, text=True, timeout=60,
    )


def test_assert_script_accepts_an_executed_virtual_record(tmp_path, virtual_record):
    result = _run_assert(tmp_path, virtual_record)
    assert result.returncode == 0, result.stderr
    assert "not HIL evidence" in result.stdout


def test_assert_script_refuses_a_run_that_did_not_execute(tmp_path, virtual_record):
    record = virtual_record
    record["executed"] = False
    record["not_executed_reason"] = "not root"
    for part in record["parts"]:
        part["verdict"] = "not_measurable"
    record["verdict"] = "not_measurable"
    assert rec.validate_record(record) == []  # well-formed; only "executed" is wrong
    result = _run_assert(tmp_path, record)
    assert result.returncode == 1
    assert "run did not execute: 'not root'" in result.stderr


def test_assert_script_refuses_a_hil_record(tmp_path, virtual_record):
    record = _hil_record(virtual_record)
    assert rec.validate_record(record) == []  # well-formed; only the class is wrong
    result = _run_assert(tmp_path, record)
    assert result.returncode == 1
    assert "expected 'virtual-lab-regression'" in result.stderr
    assert "detection half" not in result.stderr


def test_assert_script_refuses_a_detection_regression(tmp_path, virtual_record):
    record = virtual_record
    detection = record["parts"][0]
    sample = detection["samples"][0]
    sample["start_monotonic_ns"] = sample["end_monotonic_ns"] - 3_000_000_000
    detection["pass_rule"]["evaluated"] = rec.evaluate_samples(
        detection["samples"], bound_ms=rec.DETECTION_BOUND_MS
    )
    detection["verdict"] = "fail"
    record["verdict"] = "fail"
    assert rec.validate_record(record) == []  # well-formed; only detection failed
    result = _run_assert(tmp_path, record)
    assert result.returncode == 1
    assert "detection half did not hold" in result.stderr
    assert "did not execute" not in result.stderr
