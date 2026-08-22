"""Small deterministic runtime-state, evidence, and anti-replay store.

Authoritative package/decision data remains external. This store records the
local materialization lifecycle and uses atomic replacement / exclusive-create
operations so crashes or concurrent requests do not silently reuse authority.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

# Evidence records carry a tamper-evident hash chain. These reserved keys hold
# the chain metadata and are excluded from an event's own hash computation.
_EVIDENCE_SEQ = "_evidence_seq"
_EVIDENCE_PREV = "_evidence_prev"
_EVIDENCE_HASH = "_evidence_hash"


def _evidence_hash(record: dict[str, Any]) -> str:
    payload = {k: v for k, v in record.items() if k != _EVIDENCE_HASH}
    encoded = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _fsync_dir(directory: Path) -> None:
    """fsync a directory so a newly created/renamed entry in it survives a crash.

    fsync of a file persists only its data blocks; the directory entry that
    links the file name to its inode is separate metadata, durable only when the
    *parent directory* is itself fsync'd. Without this, an OS crash / power loss
    on a field-deployed edge node can lose a just-created decision-consumed
    marker, letting the same one-shot Edge decision be consumed (and acted on) a
    second time on reboot. Best-effort: a platform/filesystem that cannot fsync a
    directory raises OSError, which is swallowed rather than failing the write.
    """

    try:
        dir_fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    finally:
        os.close(dir_fd)


class RuntimeStateStore:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "environments").mkdir(exist_ok=True)
        (self.root / "evidence").mkdir(exist_ok=True)
        (self.root / "decisions").mkdir(exist_ok=True)

    def _state_path(self, environment_id: str) -> Path:
        return self.root / "environments" / f"{environment_id}.json"

    def _decision_path(self, decision_id: str) -> Path:
        safe = "".join(ch for ch in decision_id if ch.isalnum() or ch in "-_.")
        if not safe or safe != decision_id:
            raise ValueError("decision_id contains unsupported filesystem characters")
        return self.root / "decisions" / f"{safe}.json"

    def read(self, environment_id: str) -> dict[str, Any] | None:
        path = self._state_path(environment_id)
        if not path.exists():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("runtime state root must be a mapping")
        return data

    def write(self, environment_id: str, state: dict[str, Any]) -> None:
        path = self._state_path(environment_id)
        tmp = path.with_suffix(".tmp")
        payload = json.dumps(state, sort_keys=True, indent=2) + "\n"
        # Durable atomic replace: fsync the temp file's data before the rename,
        # then fsync the parent directory so the rename itself is durable --
        # otherwise a crash can leave the state reverted/truncated (the classic
        # rename-without-fsync hazard), which could let a tracked environment's
        # state regress and permit a second activation attempt.
        with open(tmp, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        _fsync_dir(path.parent)

    def consume_decision(self, decision_id: str, record: dict[str, Any]) -> bool:
        """Atomically record a one-shot Edge decision.

        Returns ``False`` if the decision ID was already consumed. A decision
        stays consumed even when the following runtime operation fails; a new
        Edge decision is required to retry.
        """

        path = self._decision_path(decision_id)
        payload = json.dumps(record, sort_keys=True, indent=2, default=str) + "\n"
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return False
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            # Persist the new directory entry too: fsync of the file data alone
            # does not make the just-created marker's dirent durable, so a crash
            # could lose it and let this one-shot decision be consumed again.
            _fsync_dir(path.parent)
        except Exception:
            try:
                path.unlink()
            except OSError:
                pass
            raise
        return True

    def decision_consumed(self, decision_id: str) -> bool:
        return self._decision_path(decision_id).exists()

    def append_evidence(self, environment_id: str, event: dict[str, Any]) -> Path:
        """Append an evidence event to a tamper-evident hash chain.

        Each record embeds its sequence number, the previous record's hash, and
        its own hash. Any edit, deletion, or reordering of a prior record breaks
        :meth:`verify_evidence_chain`.
        """

        path = self.root / "evidence" / f"{environment_id}.jsonl"
        prev_hash = ""
        seq = 0
        if path.exists():
            lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
            if lines:
                last = json.loads(lines[-1])
                prev_hash = str(last.get(_EVIDENCE_HASH, ""))
                seq = int(last.get(_EVIDENCE_SEQ, -1)) + 1
        record = dict(event)
        record[_EVIDENCE_SEQ] = seq
        record[_EVIDENCE_PREV] = prev_hash
        record[_EVIDENCE_HASH] = _evidence_hash(record)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True, default=str) + "\n")
        return path

    def evidence_head_hash(self, environment_id: str) -> str | None:
        """Return the hash of the last evidence record, or None if empty.

        Exporting this head hash to an external append-only/remote anchor lets an
        operator detect a *full-file* rewrite, which an unkeyed local chain alone
        cannot (an attacker with write access and the algorithm could recompute a
        consistent chain). The chain still makes any in-place edit, deletion, or
        reordering locally evident.
        """

        path = self.evidence_path(environment_id)
        if not path.exists():
            return None
        lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if not lines:
            return None
        return str(json.loads(lines[-1]).get(_EVIDENCE_HASH)) or None

    def verify_evidence_chain(self, environment_id: str) -> bool:
        """Return True iff the evidence hash chain is intact and unbroken.

        Detects in-place edits, deletions, truncation-in-the-middle, and
        reordering of records. It is an unkeyed chain, so a full-file rewrite by
        someone with write access is not detectable here; anchor
        :meth:`evidence_head_hash` externally to cover that.
        """

        path = self.evidence_path(environment_id)
        if not path.exists():
            return True
        prev_hash = ""
        expected_seq = 0
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                return False
            if not isinstance(record, dict):
                return False
            if int(record.get(_EVIDENCE_SEQ, -1)) != expected_seq:
                return False
            if str(record.get(_EVIDENCE_PREV, "")) != prev_hash:
                return False
            if _evidence_hash(record) != record.get(_EVIDENCE_HASH):
                return False
            prev_hash = str(record[_EVIDENCE_HASH])
            expected_seq += 1
        return True

    def evidence_path(self, environment_id: str) -> Path:
        return self.root / "evidence" / f"{environment_id}.jsonl"

    def clear_runtime_state(self, environment_id: str) -> None:
        path = self._state_path(environment_id)
        if path.exists():
            path.unlink()

    def list_environments(self) -> list[str]:
        """Return known environment IDs in deterministic order."""

        directory = self.root / "environments"
        return sorted(path.stem for path in directory.glob("*.json"))

    def consumed_decision_count(self) -> int:
        return sum(1 for _ in (self.root / "decisions").glob("*.json"))
