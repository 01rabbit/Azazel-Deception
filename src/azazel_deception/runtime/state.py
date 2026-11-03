"""Small deterministic runtime-state, evidence, and anti-replay store.

Authoritative package/decision data remains external. This store records the
local materialization lifecycle and uses atomic replacement / exclusive-create
operations so crashes or concurrent requests do not silently reuse authority.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import threading
from pathlib import Path
from typing import Any

# environment_id is used verbatim in filesystem paths (state JSON, evidence
# JSONL) and, prefixed with ``az06-``, as a Docker Compose project name. The
# accepted grammar is deliberately strict and is never normalized: lowercase
# ASCII letters/digits and single ``-``/``_`` separators, starting with a letter
# or digit, at most 58 characters so ``az06-<id>`` stays within Compose's
# 63-character project-name limit. Rejecting (rather than lowercasing or
# truncating) keeps the mapping from ID to path and project one-to-one: two
# different IDs can never alias to the same state, evidence file, or project.
_ENVIRONMENT_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9_-]{0,57}")
ENVIRONMENT_ID_MAX_LENGTH = 58

# Records are private operator/evidence material; create them owner-only.
_PRIVATE_FILE_MODE = 0o600
_PRIVATE_DIR_MODE = 0o700
# O_NOFOLLOW makes open() refuse a symlink in the final path component instead
# of following it; O_DIRECTORY makes it refuse anything that is not a directory.
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)


def _secure_dir(path: Path) -> None:
    """Force an existing directory to owner-only (0700) without following symlinks.

    Opens the directory with O_NOFOLLOW|O_DIRECTORY, so a symlink planted at the
    location raises OSError rather than re-moding its target, then fchmods the
    descriptor. Directory contents are not changed.
    """

    fd = os.open(path, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.getuid():
            raise OSError(f"refusing directory owned by another user: {path}")
        if stat.S_IMODE(info.st_mode) != _PRIVATE_DIR_MODE:
            os.fchmod(fd, _PRIVATE_DIR_MODE)
    finally:
        os.close(fd)


def _open_private(path: Path, flags: int) -> int:
    """Open a regular file owner-only, refusing symlinks, and tighten its mode.

    A pre-existing file (for example one created 0644 by another process) is
    fchmod'ed to 0600 through the descriptor. Its contents are left untouched.
    """

    fd = os.open(path, flags | _O_NOFOLLOW, _PRIVATE_FILE_MODE)
    try:
        mode = os.fstat(fd).st_mode
        if not stat.S_ISREG(mode):
            raise OSError(f"refusing non-regular record file: {path}")
        if os.fstat(fd).st_uid != os.getuid():
            raise OSError(f"refusing record file owned by another user: {path}")
        if stat.S_IMODE(mode) != _PRIVATE_FILE_MODE:
            os.fchmod(fd, _PRIVATE_FILE_MODE)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _read_private_text(path: Path) -> str:
    fd = _open_private(path, os.O_RDONLY)
    with os.fdopen(fd, "r", encoding="utf-8") as handle:
        return handle.read()


def _refuse_symlink(path: Path) -> None:
    if os.path.islink(path):
        raise OSError(f"refusing to follow symlink: {path}")


class EnvironmentIdError(ValueError):
    """Raised for an environment_id outside the strict grammar."""


def validate_environment_id(environment_id: object) -> str:
    """Return ``environment_id`` unchanged if it matches the strict grammar.

    This is the single gate for every filesystem and Compose use of an
    environment identifier. It never rewrites the value.
    """

    if not isinstance(environment_id, str) or not _ENVIRONMENT_ID_PATTERN.fullmatch(
        environment_id
    ):
        raise EnvironmentIdError(
            "environment_id must be 1-58 characters of lowercase ASCII letters, "
            "digits, '-' or '_', starting with a letter or digit"
        )
    return environment_id


# Evidence records carry a tamper-evident hash chain. These reserved keys hold
# the chain metadata and are excluded from an event's own hash computation.
_EVIDENCE_SEQ = "_evidence_seq"
_EVIDENCE_PREV = "_evidence_prev"
_EVIDENCE_HASH = "_evidence_hash"


def _evidence_hash(record: dict[str, Any]) -> str:
    payload = {k: v for k, v in record.items() if k != _EVIDENCE_HASH}
    encoded = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


_EVIDENCE_LOCKS_GUARD = threading.Lock()
_EVIDENCE_LOCKS: dict[str, threading.Lock] = {}


def _evidence_lock(path: Path) -> threading.Lock:
    """Return the process-wide lock serializing appends to one evidence file.

    Keyed by the resolved real path so every RuntimeStateStore instance in this
    process that targets the same file through a symlinked path shares one
    lock. Hard links, differently-cased path aliases, and separate processes
    are not coordinated.
    """

    key = os.path.realpath(path)
    with _EVIDENCE_LOCKS_GUARD:
        lock = _EVIDENCE_LOCKS.get(key)
        if lock is None:
            lock = _EVIDENCE_LOCKS[key] = threading.Lock()
        return lock


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


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
        _secure_dir(self.root)
        for name in ("environments", "evidence", "decisions"):
            child = self.root / name
            child.mkdir(mode=_PRIVATE_DIR_MODE, exist_ok=True)
            _secure_dir(child)

    def _state_path(self, environment_id: str) -> Path:
        safe = validate_environment_id(environment_id)
        return self.root / "environments" / f"{safe}.json"

    def _decision_path(self, decision_id: str) -> Path:
        safe = "".join(ch for ch in decision_id if ch.isalnum() or ch in "-_.")
        if not safe or safe != decision_id:
            raise ValueError("decision_id contains unsupported filesystem characters")
        return self.root / "decisions" / f"{safe}.json"

    def read(self, environment_id: str) -> dict[str, Any] | None:
        path = self._state_path(environment_id)
        _refuse_symlink(path)
        if not path.exists():
            return None
        data = json.loads(_read_private_text(path))
        if not isinstance(data, dict):
            raise ValueError("runtime state root must be a mapping")
        return data

    def write(self, environment_id: str, state: dict[str, Any]) -> None:
        path = self._state_path(environment_id)
        tmp = path.with_suffix(".tmp")
        # Never reuse a stale or planted temp file: unlink it first (this removes
        # a symlink itself, not its target), then create the temp exclusively,
        # refusing symlinks, with owner-only mode.
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        payload = json.dumps(state, sort_keys=True, indent=2) + "\n"
        # Durable atomic replace: fsync the temp file's data before the rename,
        # then fsync the parent directory so the rename itself is durable --
        # otherwise a crash can leave the state reverted/truncated (the classic
        # rename-without-fsync hazard), which could let a tracked environment's
        # state regress and permit a second activation attempt.
        fd = os.open(
            tmp,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW,
            _PRIVATE_FILE_MODE,
        )
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
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

        Appends to one file are serialized within this process (not across
        processes). A failed write/fsync is rolled back to the prior EOF.
        """

        path = self.evidence_path(environment_id)
        with _evidence_lock(path):
            _refuse_symlink(path)
            prev_hash = ""
            seq = 0
            if path.exists():
                lines = [
                    line
                    for line in _read_private_text(path).splitlines()
                    if line.strip()
                ]
                if lines:
                    # Pre-existing corruption raises here; it is never repaired.
                    last = json.loads(lines[-1])
                    prev_hash = str(last.get(_EVIDENCE_HASH, ""))
                    seq = int(last.get(_EVIDENCE_SEQ, -1)) + 1
            record = dict(event)
            record[_EVIDENCE_SEQ] = seq
            record[_EVIDENCE_PREV] = prev_hash
            record[_EVIDENCE_HASH] = _evidence_hash(record)
            data = (json.dumps(record, sort_keys=True, default=str) + "\n").encode("utf-8")
            resolved_path = Path(os.path.realpath(path))
            created = not resolved_path.exists()
            fd = _open_private(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT)
            try:
                offset = os.lseek(fd, 0, os.SEEK_END)
                try:
                    _write_all(fd, data)
                    os.fsync(fd)
                except BaseException:
                    # Roll back a partial/unsynced append to the prior EOF so no
                    # torn last line is left. If the rollback itself fails the
                    # original error still propagates (fail closed), but the
                    # file may then hold a torn line and nothing durable is
                    # claimed; verify_evidence_chain would report it.
                    try:
                        os.ftruncate(fd, offset)
                        os.fsync(fd)
                    except OSError:
                        pass
                    raise
            finally:
                try:
                    os.close(fd)
                finally:
                    if created:
                        # Sync even if the first append failed and rolled back:
                        # an empty file remains, so later appends must not be
                        # the first attempt to persist its directory entry.
                        # realpath also handles an evidence-file symlink target.
                        _fsync_dir(resolved_path.parent)
        return path

    def read_evidence_snapshot(self, environment_id: str) -> str | None:
        """Read one complete in-process snapshot relative to evidence appends.

        The same lock used by :meth:`append_evidence` prevents a thread from
        observing a partially written JSONL record. This is not a cross-process
        lock; concurrent processes still require external serialization.
        """

        path = self.evidence_path(environment_id)
        with _evidence_lock(path):
            _refuse_symlink(path)
            if not path.exists():
                return None
            return _read_private_text(path)

    def evidence_head_hash(self, environment_id: str) -> str | None:
        """Return the hash of the last evidence record, or None if empty.

        Exporting this head hash to an external append-only/remote anchor lets an
        operator detect a *full-file* rewrite, which an unkeyed local chain alone
        cannot (an attacker with write access and the algorithm could recompute a
        consistent chain). The chain still makes any in-place edit, deletion, or
        reordering locally evident.
        """

        snapshot = self.read_evidence_snapshot(environment_id)
        if snapshot is None:
            return None
        lines = [line for line in snapshot.splitlines() if line.strip()]
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
        try:
            with _evidence_lock(path):
                _refuse_symlink(path)
                if not path.exists():
                    return True
                prev_hash = ""
                expected_seq = 0
                for line in _read_private_text(path).splitlines():
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
        except (OSError, TypeError, ValueError, OverflowError, UnicodeDecodeError):
            # Unreadable files, malformed JSON value types, and invalid UTF-8
            # cannot prove chain integrity, so report a fail-closed result.
            return False

    def evidence_path(self, environment_id: str) -> Path:
        safe = validate_environment_id(environment_id)
        return self.root / "evidence" / f"{safe}.jsonl"

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
