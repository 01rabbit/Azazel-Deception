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
import secrets
import stat
import threading
import unicodedata
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

# New records and directories are created owner-only. Existing directories and
# files are never re-moded: a read must not mutate permissions, and a deployment
# that deliberately shares the state tree (group-readable evidence, a mounted
# volume) keeps working. Tighten an existing tree yourself if you want that.
_PRIVATE_FILE_MODE = 0o600
_PRIVATE_DIR_MODE = 0o700
# O_NOFOLLOW makes open() refuse a symlink in the final path component instead
# of following it. The store is POSIX-only (Linux, macOS): without O_NOFOLLOW
# the symlink guarantees cannot be given, so construction fails closed.
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)

# Environment IDs persisted before the strict grammar existed. They are only
# ever *recognised* so already-running deployments can be read, reported,
# terminated or killed; they can never start a new activation. Path-safe by
# construction: one ASCII component, alphanumeric start, no "..", <= 128 chars.
_LEGACY_ENVIRONMENT_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_PROJECT_PREFIX = "az06-"
_PROJECT_MAX_LENGTH = 63


def _require_posix() -> None:
    if os.name != "posix" or not _O_NOFOLLOW:
        raise OSError(
            "the runtime state store is supported on POSIX hosts (Linux, macOS) "
            "only; Windows is not supported"
        )


def _require_real_dir(path: Path) -> None:
    """Create ``path`` owner-only if absent; refuse a symlink or non-directory.

    An existing directory keeps its mode and owner. ``path`` itself must not be
    a symlink (a planted link under the state root would redirect records).
    """

    try:
        path.mkdir(mode=_PRIVATE_DIR_MODE, exist_ok=True)
    except FileExistsError:
        pass
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode):
        raise OSError(f"refusing symlinked state directory: {path}")
    if not stat.S_ISDIR(info.st_mode):
        raise OSError(f"state path is not a directory: {path}")


def _open_regular(path: Path, flags: int) -> int:
    """Open a regular file, refusing symlinks; never changes mode or owner.

    New files are created ``0600``. Existing files keep their permissions, so a
    shared (group-readable) deployment stays readable and a read has no side
    effects. Access is governed by the file's own permissions.

    The open is nonblocking so a planted FIFO cannot hang the caller before the
    regular-file check; the descriptor is returned to blocking mode afterwards.
    """

    fd = os.open(path, flags | _O_NOFOLLOW | _O_NONBLOCK, _PRIVATE_FILE_MODE)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(f"refusing non-regular record file: {path}")
        os.set_blocking(fd, True)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _read_private_text(path: Path) -> str:
    fd = _open_regular(path, os.O_RDONLY)
    with os.fdopen(fd, "r", encoding="utf-8") as handle:
        return handle.read()


def _refuse_symlink(path: Path) -> None:
    if os.path.islink(path):
        raise OSError(f"refusing to follow symlink: {path}")


def _case_fold_name(name: str) -> str:
    return unicodedata.normalize("NFD", name).casefold()


def _require_exact_entry(directory: Path, name: str) -> None:
    """Refuse ``name`` if the directory holds a different entry that folds to it.

    On a case- or normalization-insensitive filesystem a lookup for ``foo.json``
    can resolve to an existing ``Foo.json`` (a legacy record or evidence file).
    Reads, appends, replaces and unlinks through such a name would then touch
    that other file. When the exact name is absent and a folding alias exists,
    refuse before any filesystem operation. An exact-name entry is never
    refused, so legacy exact-case records keep working.
    """

    try:
        entries = os.listdir(directory)
    except FileNotFoundError:
        return
    if name in entries:
        return
    folded = _case_fold_name(name)
    aliases = sorted(entry for entry in entries if _case_fold_name(entry) == folded)
    if aliases:
        raise EnvironmentIdError(
            f"{name} would resolve to existing {aliases[0]} on a case- or "
            "normalization-insensitive filesystem; refusing to touch it"
        )


class EnvironmentIdError(ValueError):
    """Raised for an environment_id outside the strict grammar."""


def validate_environment_id(environment_id: object) -> str:
    """Return ``environment_id`` unchanged if it matches the strict grammar.

    This is the single gate for every *new* filesystem and Compose use of an
    environment identifier. It never rewrites the value. Previously persisted
    IDs outside this grammar are handled only by the narrow legacy path
    (:meth:`RuntimeStateStore.legacy_project_name`).
    """

    if not isinstance(environment_id, str) or not _ENVIRONMENT_ID_PATTERN.fullmatch(
        environment_id
    ):
        raise EnvironmentIdError(
            "environment_id must be 1-58 characters of lowercase ASCII letters, "
            "digits, '-' or '_', starting with a letter or digit"
        )
    return environment_id


def is_legacy_environment_id(environment_id: object) -> bool:
    """True for a path-safe ID outside the strict grammar (legacy shape only)."""

    return (
        isinstance(environment_id, str)
        and _LEGACY_ENVIRONMENT_ID_PATTERN.fullmatch(environment_id) is not None
        and ".." not in environment_id
        and _ENVIRONMENT_ID_PATTERN.fullmatch(environment_id) is None
    )


def old_project_name(environment_id: str) -> str:
    """The pre-grammar Compose project name (lowercased, filtered, truncated).

    Used only to detect aliasing between persisted IDs and to address an
    already-running legacy project; never for a new activation.
    """

    safe = "".join(ch for ch in environment_id.lower() if ch.isalnum() or ch in "-_")
    return f"{_PROJECT_PREFIX}{safe}"[:_PROJECT_MAX_LENGTH] if safe else ""


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
        _require_posix()
        # The configured root is operator-chosen: it may itself be a symlink
        # (for example /var/lib/x -> a mounted volume) and keeps its mode.
        # Only the directories *inside* it are checked for symlinks.
        self.root = Path(root)
        if self.root.is_symlink():
            # A configured symlink must resolve to an existing directory the
            # service user can fully use; it is never created or re-moded.
            target = self.root.resolve(strict=True)
            if not target.is_dir() or not os.access(target, os.R_OK | os.W_OK | os.X_OK):
                raise OSError(f"state root symlink target is not a usable directory: {self.root}")
        else:
            self.root.mkdir(mode=_PRIVATE_DIR_MODE, parents=True, exist_ok=True)
        if not self.root.is_dir():
            raise OSError(f"state root is not a directory: {self.root}")
        for name in ("environments", "evidence", "decisions"):
            _require_real_dir(self.root / name)

    def _check_environment_id(self, environment_id: str) -> str:
        """Strict IDs always pass; a legacy-shaped ID passes only if already persisted.

        A legacy ID therefore can service an environment whose state file
        exists, but can never create one: ``clear_runtime_state`` and every
        activation entry point use :func:`validate_environment_id` directly.
        """

        if isinstance(environment_id, str) and (
            _ENVIRONMENT_ID_PATTERN.fullmatch(environment_id)
            or (
                is_legacy_environment_id(environment_id)
                and self._persisted_regular(environment_id)
            )
        ):
            return environment_id
        return validate_environment_id(environment_id)  # raises EnvironmentIdError

    def _persisted_regular(self, environment_id: str) -> bool:
        """True only for a regular, non-symlink state file with this *exact* name.

        The directory listing is compared byte-for-byte so a case-insensitive
        filesystem cannot make ``ENV-1`` resolve to ``env-1.json``.
        """

        directory = self.root / "environments"
        name = f"{environment_id}.json"
        try:
            if name not in os.listdir(directory):
                return False
            return stat.S_ISREG(os.lstat(directory / name).st_mode)
        except OSError:
            return False

    def _state_path(self, environment_id: str) -> Path:
        safe = self._check_environment_id(environment_id)
        _require_exact_entry(self.root / "environments", f"{safe}.json")
        return self.root / "environments" / f"{safe}.json"

    def _decision_path(self, decision_id: str) -> Path:
        # Decision IDs are Edge-issued and use a different grammar from
        # environment IDs: ASCII-or-Unicode alphanumerics plus "-", "_" and "."
        # (dots allowed, any case, unbounded length up to the filesystem limit).
        safe = "".join(ch for ch in decision_id if ch.isalnum() or ch in "-_.")
        if not safe or safe != decision_id or safe in {".", ".."}:
            raise ValueError("decision_id contains unsupported filesystem characters")
        return self.root / "decisions" / f"{safe}.json"

    def classify_environment_id(self, environment_id: str) -> str:
        """``supported`` | ``legacy`` | ``legacy_ambiguous`` | ``unsupported``.

        ``legacy`` IDs predate the strict grammar: they are path-safe and can be
        read, terminated and killed but never activated. ``legacy_ambiguous``
        means another persisted ID shares the old Compose project name, so no
        Compose operation is possible for it. ``unsupported`` IDs are not
        path-safe and are never opened.
        """

        if _ENVIRONMENT_ID_PATTERN.fullmatch(environment_id):
            return "supported"
        if not is_legacy_environment_id(environment_id):
            return "unsupported"
        try:
            self.legacy_project_name(environment_id)
        except EnvironmentIdError:
            return "legacy_ambiguous"
        return "legacy"

    def project_aliases(self, project: str, *, excluding: str) -> list[str]:
        """Persisted environment IDs, other than ``excluding``, mapping to ``project``."""

        return [
            other
            for other in self.list_environments()
            if other != excluding and old_project_name(other) == project
        ]

    def legacy_project_name(self, environment_id: str) -> str:
        """Compose project of an already-persisted legacy ID, or refuse.

        Refuses when the ID is not legacy-shaped, has no persisted state, the
        old project name was truncated, or any other persisted ID resolves to
        the same project (two environments would share one Compose project).
        """

        if not is_legacy_environment_id(environment_id) or not self._persisted_regular(
            environment_id
        ):
            raise EnvironmentIdError("not a persisted legacy environment_id")
        project = old_project_name(environment_id)
        if len(project) >= _PROJECT_MAX_LENGTH:
            # The old derivation truncated to 63 characters: the name may
            # collide with a longer ID's, so it is never addressed.
            raise EnvironmentIdError(
                "legacy environment_id project name was truncated; stop the "
                "deployment with Docker directly and remove the legacy state "
                "file by hand"
            )
        aliases = self.project_aliases(project, excluding=environment_id)
        if aliases:
            raise EnvironmentIdError(
                "legacy environment_id shares a Compose project with another "
                f"persisted environment: {sorted(aliases)}; the runtime cannot "
                "tell their deployments apart, so stop the deployment with "
                "Docker directly and remove the legacy state file(s) by hand"
            )
        return project

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
        # A legacy ID passes only while its state file already exists.
        path = self._state_path(environment_id)
        payload = json.dumps(state, sort_keys=True, indent=2) + "\n"
        # A unique, exclusively-created temp name: concurrent writers never
        # share a temp, and a pre-existing file or symlink is never unlinked or
        # reused. Only this call's own temp is cleaned up on failure.
        tmp = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp")
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
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
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
            fd = _open_regular(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT)
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
        safe = self._check_environment_id(environment_id)
        _require_exact_entry(self.root / "evidence", f"{safe}.jsonl")
        return self.root / "evidence" / f"{safe}.jsonl"

    def clear_runtime_state(self, environment_id: str) -> None:
        # Strict IDs only: a legacy ID is decommissioned (terminated) but its
        # record is not deleted by the runtime; the operator removes it.
        validate_environment_id(environment_id)
        path = self._state_path(environment_id)
        if path.exists():
            path.unlink()

    def list_environments(self) -> list[str]:
        """Return known environment IDs in deterministic order."""

        directory = self.root / "environments"
        return sorted(path.stem for path in directory.glob("*.json"))

    def consumed_decision_count(self) -> int:
        return sum(1 for _ in (self.root / "decisions").glob("*.json"))
