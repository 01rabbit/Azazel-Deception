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

from azazel_deception.runtime.state import RuntimeStateStore


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
