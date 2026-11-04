"""Environment-ID boundary: strict validation before any filesystem or compose use.

``environment_id`` is caller-provided. It is used verbatim in state and evidence
file paths and, prefixed with ``az06-``, as a Docker Compose project name. These
tests pin that malformed IDs are rejected (never normalized), that distinct
accepted IDs cannot alias, that project names stay within Compose's limit, that
previously valid IDs keep working, and that state/evidence records are created
owner-only.
"""

from __future__ import annotations

import os
import stat
from datetime import timedelta
from pathlib import Path

import pytest

from azazel_deception.runtime import compose as compose_module
from azazel_deception.runtime.compose import DockerComposeAdapter, RuntimeGateError
from azazel_deception.runtime.state import (
    ENVIRONMENT_ID_MAX_LENGTH,
    EnvironmentIdError,
    RuntimeStateStore,
    validate_environment_id,
)

MALFORMED_IDS = [
    "",
    "..",
    "../escape",
    "../../etc/passwd",
    "a/b",
    "env/1",
    "/abs",
    "env\\1",
    "env\x001",
    "env\n1",
    "env 1",
    "env.1",
    "env.json",
    "-leading-dash",
    "_leading-underscore",
    "ENV-1",  # would alias env-1 on case-insensitive filesystems
    "Env-1",
    "env-ß",
    "env-١",  # non-ASCII digit
    "x" * (ENVIRONMENT_ID_MAX_LENGTH + 1),
]

PRESERVED_IDS = ["env-1", "env-55", "env-golden-1", "env_a-2", "a", "0", "x" * ENVIRONMENT_ID_MAX_LENGTH]


@pytest.mark.parametrize("environment_id", MALFORMED_IDS)
def test_validator_rejects_malformed_ids_without_normalizing(environment_id):
    with pytest.raises(EnvironmentIdError):
        validate_environment_id(environment_id)


@pytest.mark.parametrize("value", [None, 1, b"env-1", ["env-1"]])
def test_validator_rejects_non_string_ids(value):
    with pytest.raises(EnvironmentIdError):
        validate_environment_id(value)


@pytest.mark.parametrize("environment_id", PRESERVED_IDS)
def test_validator_preserves_valid_ids_unchanged(environment_id):
    assert validate_environment_id(environment_id) == environment_id


def test_state_store_rejects_traversal_before_touching_disk(tmp_path):
    root = tmp_path / "state"
    store = RuntimeStateStore(root)
    outside = tmp_path / "outside.json"
    for bad in ("../../outside", "../escape", "a/b"):
        with pytest.raises(EnvironmentIdError):
            store.write(bad, {"state": "active"})
        with pytest.raises(EnvironmentIdError):
            store.read(bad)
        with pytest.raises(EnvironmentIdError):
            store.append_evidence(bad, {"event_id": "x"})
        with pytest.raises(EnvironmentIdError):
            store.evidence_path(bad)
        with pytest.raises(EnvironmentIdError):
            store.clear_runtime_state(bad)
    assert not outside.exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["state"]
    assert list((root / "environments").iterdir()) == []
    assert list((root / "evidence").iterdir()) == []


def test_state_store_rejects_case_variant_that_would_alias(tmp_path):
    store = RuntimeStateStore(tmp_path)
    store.write("env-1", {"state": "active"})
    with pytest.raises(EnvironmentIdError):
        store.read("ENV-1")
    with pytest.raises(EnvironmentIdError):
        store.write("ENV-1", {"state": "terminated"})
    assert store.read("env-1") == {"state": "active"}


def test_valid_existing_ids_keep_working_end_to_end(tmp_path):
    store = RuntimeStateStore(tmp_path)
    for environment_id in ("env-1", "env-55", "env-golden-1"):
        store.write(environment_id, {"environment_id": environment_id, "state": "active"})
        assert store.read(environment_id)["state"] == "active"
        store.append_evidence(environment_id, {"event_id": f"{environment_id}-activated"})
        assert store.verify_evidence_chain(environment_id) is True
        assert store.evidence_path(environment_id) == tmp_path / "evidence" / f"{environment_id}.jsonl"
    assert store.list_environments() == ["env-1", "env-55", "env-golden-1"]


def test_state_and_evidence_records_are_owner_only(tmp_path):
    if os.name != "posix":
        pytest.skip("POSIX file modes only")
    store = RuntimeStateStore(tmp_path)
    store.write("env-1", {"state": "active"})
    store.append_evidence("env-1", {"event_id": "env-1-activated"})
    state_mode = stat.S_IMODE(os.stat(tmp_path / "environments" / "env-1.json").st_mode)
    evidence_mode = stat.S_IMODE(os.stat(tmp_path / "evidence" / "env-1.jsonl").st_mode)
    assert state_mode == 0o600
    assert evidence_mode == 0o600


def _adapter(tmp_path: Path) -> DockerComposeAdapter:
    compose_file = tmp_path / "compose.yml"
    compose_file.write_text("services: {}\n", encoding="utf-8")
    return DockerComposeAdapter(compose_file, tmp_path / "state", live_enabled=False)


def test_compose_project_name_is_injective_and_bounded(tmp_path):
    adapter = _adapter(tmp_path)
    assert adapter._project_name("env-1") == "az06-env-1"
    longest = "x" * ENVIRONMENT_ID_MAX_LENGTH
    project = adapter._project_name(longest)
    assert len(project) <= 63
    names = {adapter._project_name(e) for e in PRESERVED_IDS}
    assert len(names) == len(PRESERVED_IDS)


@pytest.mark.parametrize("environment_id", ["../x", "ENV-1", "x" * (ENVIRONMENT_ID_MAX_LENGTH + 1)])
def test_compose_project_name_rejects_malformed_ids(tmp_path, environment_id):
    adapter = _adapter(tmp_path)
    with pytest.raises(RuntimeGateError):
        adapter._project_name(environment_id)


def test_compose_invocation_never_runs_for_malformed_id(tmp_path, monkeypatch):
    adapter = _adapter(tmp_path)
    calls: list[list[str]] = []

    def spy(command, **kwargs):  # pragma: no cover - must not be reached
        calls.append(list(command))
        raise AssertionError("docker compose must not run for a malformed environment_id")

    monkeypatch.setattr(compose_module.subprocess, "run", spy)
    with pytest.raises(RuntimeGateError):
        adapter._compose("../escape", "up", "-d")
    with pytest.raises(RuntimeGateError):
        adapter.collect_status("../escape")
    with pytest.raises(RuntimeGateError):
        adapter.emergency_stop("ENV-1", operator="op", reason="test")
    with pytest.raises(RuntimeGateError):
        adapter.reset_environment("a/b")
    assert calls == []
    assert not (tmp_path / "state" / "escape.json").exists()


def test_adapter_public_entry_rejects_before_state_mutation(tmp_path):
    adapter = _adapter(tmp_path)
    with pytest.raises(RuntimeGateError):
        adapter.reset_environment("../x")
    with pytest.raises(RuntimeGateError):
        adapter.verify_evidence("../x")
    with pytest.raises(RuntimeGateError):
        adapter.export_evidence("../x")
    assert [p for p in (tmp_path / "state").rglob("*") if p.is_file()] == []


posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX file modes/symlinks only")


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


@posix_only
def test_existing_directories_and_files_keep_their_modes(tmp_path):
    """F4/F5: opening a shared tree never re-modes it; reads do not mutate."""

    root = tmp_path / "state"
    for d in (root, root / "environments", root / "evidence", root / "decisions"):
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o755)
    (root / "evidence" / "keep.txt").write_text("untouched", encoding="utf-8")
    store = RuntimeStateStore(root)
    for d in (root, root / "environments", root / "evidence", root / "decisions"):
        assert _mode(d) == 0o755, d
    store.write("env-1", {"state": "active"})
    store.append_evidence("env-1", {"event_id": "env-1-activated"})
    for f in (store._state_path("env-1"), store.evidence_path("env-1")):
        os.chmod(f, 0o644)
    assert store.read("env-1") == {"state": "active"}
    assert store.read_evidence_snapshot("env-1") is not None
    assert store.verify_evidence_chain("env-1") is True
    store.append_evidence("env-1", {"event_id": "env-1-terminated"})
    for f in (store._state_path("env-1"), store.evidence_path("env-1")):
        assert _mode(f) == 0o644


@posix_only
def test_new_directories_and_records_are_owner_only(tmp_path):
    store = RuntimeStateStore(tmp_path / "fresh" / "state")
    for name in ("", "environments", "evidence", "decisions"):
        assert _mode(store.root / name) & 0o077 == 0
    store.write("env-1", {"state": "active"})
    store.append_evidence("env-1", {"event_id": "x"})
    assert store.consume_decision("dec.1", {"k": 1})
    for f in (store._state_path("env-1"), store.evidence_path("env-1"), store.root / "decisions" / "dec.1.json"):
        assert _mode(f) == 0o600


def test_decision_marker_is_one_shot(tmp_path):
    store = RuntimeStateStore(tmp_path / "state")

    assert store.consume_decision("decision-1", {"attempt": 1}) is True
    assert store.consume_decision("decision-1", {"attempt": 2}) is False
    assert store.decision_consumed("decision-1") is True


@pytest.mark.parametrize(
    ("first", "folded"),
    [("Decision-A", "decision-a"), ("\u212b", "\u00c5")],
    ids=["case-fold", "unicode-normalization"],
)
@pytest.mark.skipif(os.name != "posix", reason="runtime state store is POSIX-only")
def test_decision_id_folding_collision_fails_closed_when_filesystem_folds(
    tmp_path, first, folded
):
    probe_dir = tmp_path / "fold-probe"
    probe_dir.mkdir()
    (probe_dir / first).write_text("probe", encoding="utf-8")
    if not (probe_dir / folded).exists():
        pytest.skip("the temporary filesystem does not fold these names")

    store = RuntimeStateStore(tmp_path / "state")
    assert store.consume_decision(first, {"attempt": 1}) is True
    assert store.consume_decision(folded, {"attempt": 2}) is False
    assert store.decision_consumed(folded) is True


@posix_only
def test_read_does_not_require_service_user_ownership(tmp_path, monkeypatch):
    store = RuntimeStateStore(tmp_path / "state")
    store.write("env-1", {"state": "active"})
    real_getuid = os.getuid
    monkeypatch.setattr(os, "getuid", lambda: real_getuid() + 1)
    assert store.read("env-1") == {"state": "active"}


@posix_only
def test_configured_symlink_root_is_supported_and_target_not_modified(tmp_path):
    real = tmp_path / "volume"
    real.mkdir()
    os.chmod(real, 0o755)
    link = tmp_path / "link"
    os.symlink(real, link)
    store = RuntimeStateStore(link)
    store.write("env-1", {"state": "active"})
    assert store.read("env-1") == {"state": "active"}
    assert _mode(real) == 0o755


@posix_only
def test_unrelated_tmp_file_is_never_deleted_and_write_uses_unique_temp(tmp_path):
    store = RuntimeStateStore(tmp_path / "state")
    legacy_tmp = store._state_path("env-1").with_suffix(".tmp")
    legacy_tmp.write_text("SOMEONE-ELSES", encoding="utf-8")
    store.write("env-1", {"state": "active"})
    store.write("env-1", {"state": "terminated"})
    assert legacy_tmp.read_text(encoding="utf-8") == "SOMEONE-ELSES"
    assert store.read("env-1") == {"state": "terminated"}
    leftovers = [p.name for p in store._state_path("env-1").parent.iterdir()]
    assert sorted(leftovers) == ["env-1.json", "env-1.tmp"]


@posix_only
def test_failed_write_removes_only_its_own_temp(tmp_path, monkeypatch):
    store = RuntimeStateStore(tmp_path / "state")
    bystander = store._state_path("env-1").parent / "bystander.tmp"
    bystander.write_text("keep", encoding="utf-8")

    def boom(src, dst):
        raise OSError("rename failed")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        store.write("env-1", {"state": "active"})
    monkeypatch.undo()
    assert [p.name for p in bystander.parent.iterdir()] == ["bystander.tmp"]


@posix_only
def test_state_write_never_follows_planted_tmp_symlink(tmp_path):
    store = RuntimeStateStore(tmp_path / "state")
    outside = tmp_path / "outside.txt"
    outside.write_text("keep-me", encoding="utf-8")
    tmp = store._state_path("env-1").with_suffix(".tmp")
    os.symlink(outside, tmp)
    store.write("env-1", {"state": "active"})
    assert outside.read_text(encoding="utf-8") == "keep-me"
    assert os.path.islink(tmp)
    assert not os.path.islink(store._state_path("env-1"))


def test_unsupported_platform_fails_closed(tmp_path, monkeypatch):
    from azazel_deception.runtime import state as state_module

    monkeypatch.setattr(state_module, "_O_NOFOLLOW", 0)
    with pytest.raises(OSError, match="POSIX"):
        RuntimeStateStore(tmp_path / "state")


@posix_only
def test_symlinked_state_subdirectory_is_refused_and_target_not_modified(tmp_path):
    target = tmp_path / "elsewhere"
    target.mkdir()
    os.chmod(target, 0o755)
    root = tmp_path / "state"
    root.mkdir()
    os.symlink(target, root / "environments")
    with pytest.raises(OSError):
        RuntimeStateStore(root)
    assert _mode(target) == 0o755


@posix_only
def test_symlinked_evidence_file_is_refused_and_target_untouched(tmp_path):
    store = RuntimeStateStore(tmp_path / "state")
    outside = tmp_path / "outside.jsonl"
    outside.write_text("external", encoding="utf-8")
    os.chmod(outside, 0o644)
    os.symlink(outside, store.evidence_path("env-1"))
    with pytest.raises(OSError):
        store.append_evidence("env-1", {"event_id": "env-1-activated"})
    assert outside.read_text(encoding="utf-8") == "external"
    assert _mode(outside) == 0o644


@posix_only
def test_symlinked_state_file_read_is_refused(tmp_path):
    store = RuntimeStateStore(tmp_path / "state")
    outside = tmp_path / "outside.json"
    outside.write_text('{"state": "active"}', encoding="utf-8")
    os.symlink(outside, store._state_path("env-1"))
    with pytest.raises(OSError):
        store.read("env-1")


# --- F2/F3: legacy (pre-grammar) persisted IDs: decommission only, never activate ---

import json as _json


def _persist(adapter: DockerComposeAdapter, environment_id: str, state: str = "active") -> None:
    """Simulate a pre-upgrade deployment: write the state file the old code wrote."""

    path = adapter.state.root / "environments" / f"{environment_id}.json"
    path.write_text(
        _json.dumps({"environment_id": environment_id, "state": state, "package_id": "p", "node_id": "n"}),
        encoding="utf-8",
    )


def _termination(environment_id: str) -> dict:
    return {"environment_id": environment_id, "decision_id": "dec-term-1"}


class _FakeTermination:
    def __init__(self, environment_id, decision_id="dec-term-1"):
        self.environment_id = environment_id
        self.decision_id = decision_id
        self.expires_at = compose_module._utcnow() + timedelta(hours=1)
        self.reason = "decommission"
        self.evidence_refs = []


@pytest.fixture
def mocked(tmp_path, monkeypatch):
    adapter = _adapter(tmp_path)
    adapter.live_enabled = True
    calls: list[list[str]] = []

    def fake_run(command, **kwargs):
        calls.append(list(command))
        return compose_module.subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(compose_module.subprocess, "run", fake_run)
    monkeypatch.setattr(
        compose_module.EnvironmentTerminationDecision,
        "model_validate",
        staticmethod(lambda data: _FakeTermination(data["environment_id"], data["decision_id"])),
    )
    monkeypatch.setattr(adapter, "_authenticate_decision", lambda data: None)
    return adapter, calls


def _project_of(command):
    return command[command.index("-p") + 1]


def test_legacy_id_status_and_evidence_remain_readable(tmp_path):
    adapter = _adapter(tmp_path)
    _persist(adapter, "Env.1")
    assert adapter.collect_status("Env.1")["state"] == "active"
    adapter.state.append_evidence("Env.1", {"event_id": "e"})
    assert adapter.verify_evidence("Env.1") is True
    assert len(adapter.export_evidence("Env.1")) == 1


def test_legacy_id_terminate_uses_old_project_and_is_edge_authorized(mocked):
    adapter, calls = mocked
    _persist(adapter, "Env.1")
    result = adapter.terminate_environment("Env.1", _termination("Env.1"))
    assert result["status"] == "terminated"
    assert [_project_of(c) for c in calls] == ["az06-env1"]
    assert adapter.state.read("Env.1")["state"] == "terminated"
    # Edge authority is unchanged: the decision is single-use.
    _persist(adapter, "Env.1")
    with pytest.raises(RuntimeGateError):
        adapter.terminate_environment("Env.1", _termination("Env.1"))
    # and must name this environment
    with pytest.raises(RuntimeGateError):
        adapter.terminate_environment("Env.1", {"environment_id": "other", "decision_id": "d2"})


def test_legacy_id_kill_switch_works(mocked):
    adapter, calls = mocked
    _persist(adapter, "Env.1")
    result = adapter.emergency_stop("Env.1", operator="op", reason="decommission")
    assert result["status"] == "terminated"
    assert [_project_of(c) for c in calls] == ["az06-env1"]
    assert adapter.state.read("Env.1")["state"] == "terminated"


@pytest.mark.parametrize("environment_id", ["Env.1", "ENV-1", "env.1"])
def test_legacy_id_can_never_activate_or_shadow_activate(mocked, environment_id):
    adapter, calls = mocked
    _persist(adapter, environment_id)
    for call in (adapter.activate_environment, adapter.shadow_activation):
        with pytest.raises(RuntimeGateError):
            call(environment_id, {}, {}, {})
    assert calls == []
    assert adapter.state.read(environment_id)["state"] == "active"


def test_unpersisted_legacy_shaped_id_is_refused_everywhere(mocked):
    adapter, calls = mocked
    for call in (
        lambda: adapter.collect_status("Env.1"),
        lambda: adapter.verify_evidence("Env.1"),
        lambda: adapter.emergency_stop("Env.1", operator="op", reason="r"),
        lambda: adapter.terminate_environment("Env.1", _termination("Env.1")),
        lambda: adapter.reset_environment("Env.1"),
    ):
        with pytest.raises(RuntimeGateError):
            call()
    assert calls == []
    assert not (adapter.state.root / "environments" / "Env.1.json").exists()


@pytest.mark.parametrize(
    "environment_id",
    ["../escape", "a/b", "..", "Env 1", "Env\n1", "env-\u00df", ".hidden", "a..b", "X" * 129, "Env.\x00"],
)
def test_unsafe_ids_are_refused_even_when_a_file_could_exist(mocked, environment_id):
    adapter, calls = mocked
    for call in (
        lambda: adapter.collect_status(environment_id),
        lambda: adapter.emergency_stop(environment_id, operator="op", reason="r"),
        lambda: adapter.terminate_environment(environment_id, _termination(environment_id)),
        lambda: adapter.verify_evidence(environment_id),
        lambda: adapter.export_evidence(environment_id),
    ):
        with pytest.raises(RuntimeGateError):
            call()
    assert calls == []


def test_ambiguous_legacy_project_aliases_are_refused_for_compose(mocked):
    adapter, calls = mocked
    _persist(adapter, "Env.1")
    _persist(adapter, "ENV1")  # both map to az06-env1
    _persist(adapter, "En.v1")
    for environment_id in ("Env.1", "ENV1", "En.v1"):
        with pytest.raises(RuntimeGateError, match="shares a Compose project"):
            adapter.emergency_stop(environment_id, operator="op", reason="r")
        with pytest.raises(RuntimeGateError, match="shares a Compose project"):
            adapter.terminate_environment(environment_id, _termination(environment_id))
        # read-only status does not touch Compose and stays available
        assert adapter.collect_status(environment_id)["state"] == "active"
    assert calls == []
    health = adapter.health()
    statuses = {e["environment_id"]: e["id_status"] for e in health["environments"]}
    assert statuses == {
        "Env.1": "legacy_ambiguous",
        "ENV1": "legacy_ambiguous",
        "En.v1": "legacy_ambiguous",
    }


def test_truncated_overlong_legacy_project_is_refused(mocked):
    adapter, calls = mocked
    long_id = "A" + "b" * 70
    _persist(adapter, long_id)
    with pytest.raises(RuntimeGateError):
        adapter.emergency_stop(long_id, operator="op", reason="r")
    assert calls == []


def test_new_activation_refused_when_a_legacy_id_holds_its_compose_project(mocked):
    adapter, calls = mocked
    _persist(adapter, "ENV-1")  # old project az06-env-1
    for call in (adapter.activate_environment, adapter.shadow_activation):
        with pytest.raises(RuntimeGateError, match="shares a Compose project"):
            call("env-1", {}, {}, {})
    assert calls == []


def test_health_and_reconcile_expose_legacy_and_unsupported_ids(tmp_path):
    adapter = _adapter(tmp_path)
    _persist(adapter, "env-1")
    _persist(adapter, "Env.2")
    _persist(adapter, "bad id")
    health = adapter.health()
    by_id = {e["environment_id"]: e for e in health["environments"]}
    assert by_id["env-1"]["id_status"] == "supported"
    assert by_id["Env.2"] == {"environment_id": "Env.2", "state": "active", "id_status": "legacy"}
    assert by_id["bad id"]["state"] == "unsupported_id"
    assert by_id["bad id"]["id_status"] == "unsupported"
    assert health["legacy_environment_ids"] == ["Env.2"]
    assert health["unsupported_environment_ids"] == ["bad id"]
    assert "Env.2" in health["active_environments"]

    report = adapter.reconcile_with_edge(["env-1", "Env.2"])
    assert report["local_only_active"] == []
    assert report["legacy_environment_ids"] == ["Env.2"]
    assert report["unsupported_environment_ids"] == ["bad id"]
    assert report["consistent"] is False  # an unreadable-by-design ID may hide a deployment
    assert adapter.reconcile_with_edge(["env-1"])["local_only_active"] == ["Env.2"]


def test_legacy_id_cannot_be_cleared_or_created_through_the_store(tmp_path):
    store = RuntimeStateStore(tmp_path)
    with pytest.raises(EnvironmentIdError):
        store.write("Env.1", {"state": "active"})
    (tmp_path / "environments" / "Env.1.json").write_text("{}", encoding="utf-8")
    with pytest.raises(EnvironmentIdError):
        store.clear_runtime_state("Env.1")
    assert (tmp_path / "environments" / "Env.1.json").exists()


@posix_only
def test_dangling_symlink_root_is_refused(tmp_path):
    link = tmp_path / "link"
    os.symlink(tmp_path / "missing", link)
    with pytest.raises(OSError):
        RuntimeStateStore(link)
    assert not (tmp_path / "missing").exists()


@pytest.mark.parametrize("legacy_id", ["ENV-1", "Env.1"])
def test_strict_id_compose_ops_refused_while_legacy_alias_persisted(mocked, legacy_id):
    adapter, calls = mocked
    strict = "env-1" if legacy_id == "ENV-1" else "env1"
    _persist(adapter, legacy_id)  # old project az06-<strict>
    # Address both records by exact file path. On a case-folding filesystem the
    # strict and legacy names are the same physical file, so writing the strict
    # record would overwrite the legacy record before its snapshot is taken.
    legacy_path = adapter.state.root / "environments" / f"{legacy_id}.json"
    strict_path = adapter.state.root / "environments" / f"{strict}.json"
    same_file = (
        legacy_path.exists()
        and strict_path.exists()
        and os.path.samefile(legacy_path, strict_path)
    )
    if not same_file:
        _persist(adapter, strict)
    legacy_before = legacy_path.read_bytes()
    with pytest.raises(RuntimeGateError, match="shares a Compose project"):
        adapter.terminate_environment(strict, _termination(strict))
    with pytest.raises(RuntimeGateError, match="shares a Compose project"):
        adapter.emergency_stop(strict, operator="op", reason="r")
    assert calls == []
    assert legacy_path.read_bytes() == legacy_before
    assert _json.loads(legacy_before.decode("utf-8"))["state"] == "active"
    assert not adapter.state.decision_consumed("dec-term-1")


def test_ambiguous_legacy_recovery_text_is_accurate(mocked):
    adapter, calls = mocked
    _persist(adapter, "Env.1")
    _persist(adapter, "ENV1")
    with pytest.raises(RuntimeGateError) as exc:
        adapter.emergency_stop("Env.1", operator="op", reason="r")
    assert "Docker directly" in str(exc.value) and "by hand" in str(exc.value)
    _persist(adapter, "env1")
    with pytest.raises(RuntimeGateError) as exc:
        adapter.terminate_environment("env1", _termination("env1"))
    assert "Docker directly" in str(exc.value) and "by hand" in str(exc.value)
    assert calls == []


def test_fifo_record_is_refused_without_blocking(tmp_path):
    import signal

    adapter = _adapter(tmp_path)
    fifo = adapter.state.root / "environments" / "env-fifo.json"
    os.mkfifo(fifo)
    evidence = adapter.state.evidence_path("env-fifo")
    os.mkfifo(evidence)

    def _timeout(signum, frame):
        raise AssertionError("FIFO open blocked")

    old = signal.signal(signal.SIGALRM, _timeout)
    signal.alarm(5)
    try:
        with pytest.raises(OSError):
            adapter.state.read("env-fifo")
        with pytest.raises(OSError):
            adapter.state.read_evidence_snapshot("env-fifo")
        with pytest.raises(OSError):
            adapter.state.append_evidence("env-fifo", {"event_id": "e"})
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


def test_strict_id_refuses_case_folded_legacy_path_alias(tmp_path):
    store = RuntimeStateStore(tmp_path)
    legacy_state = tmp_path / "environments" / "Foo.json"
    legacy_evidence = tmp_path / "evidence" / "Foo.jsonl"
    legacy_state.write_text('{"state": "active", "legacy": true}\n', encoding="utf-8")
    store.append_evidence("Foo", {"event_id": "foo-activated"})
    state_before = legacy_state.read_bytes()
    evidence_before = legacy_evidence.read_bytes()

    # Only the legacy spelling is present. On a folding filesystem, a lookup
    # for strict ID "foo" could resolve to these "Foo" records; the listing
    # guard refuses every operation before any read, append, replace or unlink.
    with pytest.raises(EnvironmentIdError):
        store.read("foo")
    with pytest.raises(EnvironmentIdError):
        store.write("foo", {"state": "terminated"})
    with pytest.raises(EnvironmentIdError):
        store.clear_runtime_state("foo")
    with pytest.raises(EnvironmentIdError):
        store.append_evidence("foo", {"event_id": "foo-forged"})
    with pytest.raises(EnvironmentIdError):
        store.read_evidence_snapshot("foo")
    with pytest.raises(EnvironmentIdError):
        store.evidence_head_hash("foo")
    with pytest.raises(EnvironmentIdError):
        store.verify_evidence_chain("foo")
    with pytest.raises(EnvironmentIdError):
        store.evidence_path("foo")

    assert legacy_state.read_bytes() == state_before
    assert legacy_evidence.read_bytes() == evidence_before
    # No new entry was created for the strict alias (listing-level check, so it
    # holds on case-insensitive hosts too).
    assert sorted(os.listdir(tmp_path / "environments")) == ["Foo.json"]
    assert sorted(os.listdir(tmp_path / "evidence")) == ["Foo.jsonl"]

    # The exact-case legacy record remains accessible.
    assert store.read("Foo") == {"state": "active", "legacy": True}
    assert store.verify_evidence_chain("Foo") is True
    assert legacy_state.read_bytes() == state_before
