"""Anti-replay ledger durability: consumed markers must be crash-durable.

RuntimeStateStore backs the one-shot anti-replay guarantee for both AZ-06
decision consumers (TransitionExecutor and DockerComposeAdapter). fsync of a
marker file's data alone does NOT make its directory entry durable, so an OS
crash / power loss on a field-deployed edge node could lose a just-consumed
marker and let the same one-shot decision be consumed (and acted on) a second
time on reboot. These tests assert the store fsyncs BOTH the file and its parent
directory on the durability-critical writes, guarding the module's own stated
crash-durability contract.
"""

from __future__ import annotations

import os
import stat
import threading

from azazel_deception.runtime import state as state_module
from azazel_deception.runtime.state import RuntimeStateStore
from azazel_deception.runtime.mio_feedback import _read_records


def _fsync_spy(monkeypatch):
    """Record whether each fsync targets a regular file or a directory."""
    classified: list[str] = []
    real_fsync = os.fsync

    def spy(fd):
        try:
            mode = os.fstat(fd).st_mode
            classified.append("dir" if stat.S_ISDIR(mode) else "file")
        except OSError:  # pragma: no cover - defensive
            pass
        return real_fsync(fd)

    monkeypatch.setattr(os, "fsync", spy)
    return classified


def test_consume_decision_fsyncs_marker_file_and_parent_dir(tmp_path, monkeypatch):
    store = RuntimeStateStore(tmp_path)
    classified = _fsync_spy(monkeypatch)
    assert store.consume_decision("edge-decision-1", {"kind": "transition"}) is True
    # One-shot semantics are preserved: a second consume of the same id fails.
    assert store.consume_decision("edge-decision-1", {"kind": "transition"}) is False
    assert "file" in classified, "marker file data was not fsync'd"
    assert "dir" in classified, "parent directory (marker dirent) was not fsync'd"


def test_write_state_fsyncs_temp_file_and_parent_dir(tmp_path, monkeypatch):
    store = RuntimeStateStore(tmp_path)
    classified = _fsync_spy(monkeypatch)
    store.write("env-1", {"state": "active"})
    assert store.read("env-1") == {"state": "active"}
    assert "file" in classified, "temp state file was not fsync'd before rename"
    assert "dir" in classified, "parent directory was not fsync'd after rename"


def test_mio_evidence_reader_waits_for_in_progress_append(tmp_path, monkeypatch):
    store = RuntimeStateStore(tmp_path)
    partial_written = threading.Event()
    finish_write = threading.Event()
    read_attempted = threading.Event()
    read_done = threading.Event()
    records: list[dict] = []
    errors: list[Exception] = []
    write_errors: list[Exception] = []
    real_write_all = state_module._write_all

    def paused_write(fd, data):
        split = max(1, len(data) // 2)
        real_write_all(fd, data[:split])
        partial_written.set()
        if not finish_write.wait(5):
            raise TimeoutError("test did not release evidence append")
        real_write_all(fd, data[split:])

    monkeypatch.setattr(state_module, "_write_all", paused_write)

    def append():
        try:
            store.append_evidence("env-1", {"event_type": "interaction", "value": "fixture"})
        except Exception as exc:  # noqa: BLE001 - surfaced below
            write_errors.append(exc)

    def read():
        read_attempted.set()
        try:
            records.extend(_read_records(store, "env-1"))
        except Exception as exc:  # noqa: BLE001 - surfaced below
            errors.append(exc)
        finally:
            read_done.set()

    writer = threading.Thread(target=append)
    reader = threading.Thread(target=read)
    writer.start()
    try:
        assert partial_written.wait(5)
        reader.start()
        assert read_attempted.wait(5)
        # The append holds the same lock as snapshot readers while the line is
        # incomplete; a reader must wait rather than misclassify it as corrupt.
        assert not read_done.wait(0.05)
    finally:
        finish_write.set()
        writer.join(5)
        if reader.ident is not None:
            reader.join(5)

    assert not writer.is_alive() and not reader.is_alive()
    assert not write_errors and not errors
    assert len(records) == 1 and records[0]["event_type"] == "interaction"
    assert store.verify_evidence_chain("env-1") is True
