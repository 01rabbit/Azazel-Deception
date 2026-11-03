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
def test_preexisting_permissive_directories_become_owner_only(tmp_path):
    root = tmp_path / "state"
    for d in (root, root / "environments", root / "evidence", root / "decisions"):
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o755)
    (root / "evidence" / "keep.txt").write_text("untouched", encoding="utf-8")
    RuntimeStateStore(root)
    for d in (root, root / "environments", root / "evidence", root / "decisions"):
        assert _mode(d) == 0o700, d
    assert (root / "evidence" / "keep.txt").read_text(encoding="utf-8") == "untouched"


@posix_only
def test_preexisting_0644_evidence_file_is_tightened_and_content_preserved(tmp_path):
    store = RuntimeStateStore(tmp_path / "state")
    store.append_evidence("env-1", {"event_id": "env-1-activated"})
    path = store.evidence_path("env-1")
    original = path.read_bytes()
    os.chmod(path, 0o644)
    store.append_evidence("env-1", {"event_id": "env-1-terminated"})
    assert _mode(path) == 0o600
    assert path.read_bytes().startswith(original)
    assert store.verify_evidence_chain("env-1") is True


@posix_only
def test_preexisting_0644_evidence_file_is_tightened_on_read(tmp_path):
    store = RuntimeStateStore(tmp_path / "state")
    store.append_evidence("env-1", {"event_id": "env-1-activated"})
    path = store.evidence_path("env-1")
    original = path.read_bytes()
    os.chmod(path, 0o644)
    snapshot = store.read_evidence_snapshot("env-1")
    assert snapshot is not None and snapshot.encode("utf-8") == original
    assert _mode(path) == 0o600


@posix_only
def test_preexisting_0644_state_file_is_tightened_on_read(tmp_path):
    store = RuntimeStateStore(tmp_path / "state")
    store.write("env-1", {"state": "active"})
    path = store._state_path("env-1")
    original = path.read_bytes()
    os.chmod(path, 0o644)
    assert store.read("env-1") == {"state": "active"}
    assert _mode(path) == 0o600
    assert path.read_bytes() == original


@posix_only
def test_stale_0644_tmp_is_not_reused_and_state_write_succeeds(tmp_path):
    store = RuntimeStateStore(tmp_path / "state")
    tmp = store._state_path("env-1").with_suffix(".tmp")
    tmp.write_text("STALE-CONTENT", encoding="utf-8")
    os.chmod(tmp, 0o644)
    stale_inode = os.stat(tmp).st_ino
    store.write("env-1", {"state": "active"})
    assert store.read("env-1") == {"state": "active"}
    final = store._state_path("env-1")
    assert _mode(final) == 0o600
    assert os.stat(final).st_ino != stale_inode
    assert not tmp.exists()


@posix_only
def test_state_write_never_follows_planted_tmp_symlink(tmp_path):
    store = RuntimeStateStore(tmp_path / "state")
    outside = tmp_path / "outside.txt"
    outside.write_text("keep-me", encoding="utf-8")
    tmp = store._state_path("env-1").with_suffix(".tmp")
    os.symlink(outside, tmp)
    store.write("env-1", {"state": "active"})
    assert outside.read_text(encoding="utf-8") == "keep-me"
    assert store.read("env-1") == {"state": "active"}
    assert not os.path.islink(store._state_path("env-1"))


@posix_only
def test_symlinked_state_root_directory_is_refused_and_target_not_modified(tmp_path):
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
def test_symlinked_root_itself_is_refused(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    os.chmod(real, 0o755)
    link = tmp_path / "link"
    os.symlink(real, link)
    with pytest.raises(OSError):
        RuntimeStateStore(link)
    assert _mode(real) == 0o755


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
