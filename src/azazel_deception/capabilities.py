"""Portable host-capability discovery for AZ-06.

Capability reports are descriptive. They never authorize activation.
"""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
from pathlib import Path
from typing import Any


def _architecture() -> str:
    machine = platform.machine().lower()
    aliases = {
        "aarch64": "arm64",
        "arm64": "arm64",
        "x86_64": "amd64",
        "amd64": "amd64",
    }
    return aliases.get(machine, machine or "unknown")


def _memory_mb() -> int:
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        pass
    return 0


def _node_id() -> str:
    explicit = os.environ.get("AZAZEL_DECEPTION_NODE_ID")
    if explicit:
        return explicit
    try:
        raw = Path("/etc/machine-id").read_text(encoding="utf-8").strip()
    except OSError:
        raw = platform.node() or "unknown"
    return "az06-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]


def detect_host_capabilities(root: str = "/") -> dict[str, Any]:
    usage = shutil.disk_usage(root)
    docker = shutil.which("docker") is not None
    podman = shutil.which("podman") is not None
    return {
        "schema_version": "host-capabilities/bootstrap-v0.1",
        "node_id": _node_id(),
        "architecture": _architecture(),
        "cpu_cores": os.cpu_count() or 1,
        "memory_mb": _memory_mb(),
        "storage_free_mb": usage.free // (1024 * 1024),
        "runtime_adapters": {
            "docker_compose": docker,
            "podman": podman,
        },
        "kvm_available": Path("/dev/kvm").exists(),
        "gpu_available": Path("/dev/dri").exists(),
        "supported_profile_classes": ["static_linux", "low_interaction_services"],
        "authority": "descriptive_only",
    }
