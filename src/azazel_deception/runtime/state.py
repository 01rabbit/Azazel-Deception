"""Small deterministic runtime-state, evidence, and anti-replay store.

Authoritative package/decision data remains external. This store records the
local materialization lifecycle and uses atomic replacement / exclusive-create
operations so crashes or concurrent requests do not silently reuse authority.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


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
        tmp.write_text(payload, encoding="utf-8")
        os.replace(tmp, path)

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
        path = self.root / "evidence" / f"{environment_id}.jsonl"
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True, default=str) + "\n")
        return path

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
