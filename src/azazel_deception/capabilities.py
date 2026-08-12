"""Portable host-capability discovery for AZ-06.

Capability reports are canonical Azazel-Fabric ``HostCapabilities`` objects.
They are descriptive-only and never authorize activation.
"""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Any

from azazel_fabric.deception_contracts import HostCapabilities


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
    """Return host physical memory in MiB on Linux and macOS.

    AZ-06 development is supported on Apple Silicon macOS even though live
    attacker-facing deployment remains a Linux target.  macOS does not expose
    ``/proc/meminfo`` so use the native ``hw.memsize`` sysctl there.
    """

    if platform.system() == "Darwin":
        try:
            result = subprocess.run(
                ["sysctl", "-n", "hw.memsize"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=2,
                check=False,
            )
            if result.returncode == 0:
                return max(int((result.stdout or "").strip()) // (1024 * 1024), 1)
        except (OSError, ValueError, subprocess.SubprocessError):
            pass

    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                return max(int(line.split()[1]) // 1024, 1)
    except (OSError, ValueError, IndexError):
        pass
    return 1


def _node_id() -> str:
    explicit = os.environ.get("AZAZEL_DECEPTION_NODE_ID")
    if explicit:
        return explicit
    try:
        raw = Path("/etc/machine-id").read_text(encoding="utf-8").strip()
    except OSError:
        raw = platform.node() or "unknown"
    return "az06-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]


def _version(command: list[str]) -> str | None:
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    line = (result.stdout or "").strip().splitlines()
    return line[0][:200] if line else None


def detect_host_capabilities(root: str = "/") -> dict[str, Any]:
    architecture = _architecture()
    if architecture not in {"arm64", "amd64"}:
        raise RuntimeError(f"unsupported AZ-06 host architecture: {architecture!r}")

    usage = shutil.disk_usage(root)
    docker = shutil.which("docker") is not None
    podman = shutil.which("podman") is not None
    is_linux = platform.system() == "Linux"
    runtimes = {
        "docker_compose": docker,
        "podman": podman,
        "kvm_libvirt": is_linux and Path("/dev/kvm").exists() and shutil.which("virsh") is not None,
        "k3s": shutil.which("k3s") is not None,
    }
    versions: dict[str, str] = {}
    if docker:
        value = _version(["docker", "--version"])
        if value:
            versions["docker_compose"] = value
    if podman:
        value = _version(["podman", "--version"])
        if value:
            versions["podman"] = value

    model = HostCapabilities(
        node_id=_node_id(),
        architecture=architecture,
        cpu_cores=os.cpu_count() or 1,
        memory_mb=max(_memory_mb(), 1),
        storage_free_mb=usage.free // (1024 * 1024),
        runtime_adapters=runtimes,
        runtime_versions=versions,
        kvm_available=is_linux and Path("/dev/kvm").exists(),
        gpu_available=is_linux and Path("/dev/dri").exists(),
        network_features={
            "network_namespace": is_linux and shutil.which("ip") is not None,
            "nftables": is_linux and shutil.which("nft") is not None,
            "docker_desktop_host": platform.system() == "Darwin" and docker,
        },
        supported_profile_classes=["static_linux", "low_interaction_services"],
    )
    return model.model_dump(mode="json")
