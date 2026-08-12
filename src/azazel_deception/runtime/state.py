"""Small deterministic runtime-state and evidence store.

Authoritative package/decision data remains external. This store records the
local materialization lifecycle and uses atomic replacement so a crash does not
leave a partially-written state document.
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

    def _state_path(self, environment_id: str) -> Path:
        return self.root / "environments" / f"{environment_id}.json"

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
