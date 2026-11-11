"""Test-only strict offline canary admission; no product/default registration.

Real optional package/SPDX callbacks supply supply-chain facts. A synthetic
HMAC decision remains lab-only and grants no genuine Edge/production authority.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess

from azazel_deception.runtime.offline_package_verifier import (
    OfflineGitHubAttestationPackageVerifier, _protected_directory, _read_protected,
)
from azazel_deception.runtime.offline_sbom_verifier import (
    OfflineGitHubSbomVerifier, OfflineImageArtifacts, _json,
)

FLAG = "AZ06_CANARY_STRICT_OFFLINE"
MARKER = Path("/etc/az06-canary-disposable-vm")
MAGIC = b"az06-canary-disposable-vm-v1\n"
ENV_FIELDS = ("AZ06_OFFLINE_GH_PATH", "AZ06_OFFLINE_GH_SHA256", "AZ06_OFFLINE_BUNDLE_PATH",
              "AZ06_OFFLINE_ROOT_PATH", "AZ06_OFFLINE_ROOT_SHA256", "AZ06_OFFLINE_TEMP_PARENT",
              "AZ06_OFFLINE_SPDX_MAP")


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def strict_mode_requested(environment=None):
    env = os.environ if environment is None else environment
    value = env.get(FLAG, "0")
    require(value in ("", "0", "1"), "strict canary flag must be explicitly 0 or 1")
    return value == "1"


def _command(*argv):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=5, check=False)
    require(result.returncode == 0 and len(result.stdout) <= 1024 * 1024,
            "strict local host prerequisite/readback unavailable")
    return result.stdout


def lab_guard(workspace):
    require(platform.system() == "Linux" and os.geteuid() == 0, "strict canary requires root disposable Linux VM")
    require(_read_protected(MARKER, 128) == MAGIC, "strict disposable VM marker missing or invalid")
    _protected_directory(Path(workspace))
    require(bool(_command("systemd-detect-virt", "--vm").strip()), "strict canary requires a disposable VM")
    require(not _command("ip", "-4", "route", "show", "default").strip()
            and not _command("ip", "-6", "route", "show", "default").strip(),
            "strict canary VM must be disconnected from external/default routes")


def offline_callbacks(environment=None):
    env = os.environ if environment is None else environment
    require(all(type(env.get(key)) is str and env[key] for key in ENV_FIELDS), "strict offline material configuration incomplete")
    for key in ("AZ06_OFFLINE_GH_SHA256", "AZ06_OFFLINE_ROOT_SHA256"):
        require(re.fullmatch(r"[0-9a-f]{64}", env[key]), "strict independent CLI/root fingerprints required")
    mapping = _json(_read_protected(Path(env["AZ06_OFFLINE_SPDX_MAP"]), 1024 * 1024))
    require(type(mapping) is dict and len(mapping) == 1, "strict protected image artifact map required")
    images = {}
    for image, value in mapping.items():
        require(type(image) is str and type(value) is dict
                and set(value) == {"index_path", "bundle_path", "artifacts"}
                and type(value["artifacts"]) is dict and 4 <= len(value["artifacts"]) <= 8,
                "strict bounded explicit image artifact map required")
        require(all(type(path) is str for path in [value["index_path"], value["bundle_path"], *value["artifacts"].values()]),
                "strict local artifact paths required")
        images[image] = OfflineImageArtifacts(Path(value["index_path"]), Path(value["bundle_path"]),
                                             {digest: Path(path) for digest, path in value["artifacts"].items()})
    common = dict(gh_path=Path(env["AZ06_OFFLINE_GH_PATH"]), gh_sha256=env["AZ06_OFFLINE_GH_SHA256"],
                  trusted_root_path=Path(env["AZ06_OFFLINE_ROOT_PATH"]), trusted_root_sha256=env["AZ06_OFFLINE_ROOT_SHA256"],
                  temporary_parent=Path(env["AZ06_OFFLINE_TEMP_PARENT"]))
    return (OfflineGitHubAttestationPackageVerifier(bundle_path=Path(env["AZ06_OFFLINE_BUNDLE_PATH"]), **common),
            OfflineGitHubSbomVerifier(images=images, **common))


def measured_host(environment=None):
    env = os.environ if environment is None else environment
    require(env.get("DOCKER_HOST", "") in ("", "unix:///var/run/docker.sock")
            and env.get("DOCKER_CONTEXT", "") in ("", "default"), "strict Docker daemon must be local")
    require(_command("docker", "context", "show").strip() == b"default", "strict local default Docker context required")
    endpoint = _json(_command("docker", "context", "inspect", "default", "--format", "{{json .Endpoints.docker.Host}}"))
    require(endpoint == "unix:///var/run/docker.sock", "strict Docker context is not the local VM socket")
    info = _json(_command("docker", "info", "--format", "{{json .}}"))
    require(type(info) is dict, "actual Docker information must be an object")
    aliases = {"aarch64": "arm64", "arm64": "arm64", "x86_64": "amd64", "amd64": "amd64"}
    controller_arch = aliases.get(platform.machine().lower())
    daemon_arch = aliases.get(info.get("Architecture"))
    require(info.get("OSType") == "linux" and controller_arch == daemon_arch and daemon_arch in ("arm64", "amd64")
            and info.get("KernelVersion") == platform.release(), "Docker/controller Linux platform mismatch")
    cpu, memory = info.get("NCPU"), info.get("MemTotal")
    require(type(cpu) is int and cpu > 0 and type(memory) is int and memory >= 1024 * 1024,
            "actual Docker CPU/memory readback invalid")
    root = info.get("DockerRootDir")
    require(type(root) is str and root.startswith("/"), "local Docker storage path unavailable")
    _protected_directory(Path(root))
    free = shutil.disk_usage(root).free // (1024 * 1024)
    require(free > 0 and type(info.get("ID")) is str and info["ID"], "actual local Docker identity/storage invalid")
    host = dict(node_id="az06-strict-" + hashlib.sha256(info["ID"].encode()).hexdigest()[:12],
                architecture=daemon_arch, cpu_cores=cpu, memory_mb=memory // (1024 * 1024),
                storage_free_mb=free, runtime_adapters={"docker_compose": True}, kvm_available=False, gpu_available=False)
    measured = dict(controller_platform=controller_arch, daemon_platform=daemon_arch,
                    controller_kernel=platform.release(), daemon_kernel=info["KernelVersion"],
                    daemon_cpu_cores=cpu, daemon_memory_mb=host["memory_mb"], local_storage_free_mb=free)
    return host, measured


def strict_preflight(package, workspace, environment=None):
    require(strict_mode_requested(environment), "strict offline mode must be explicit")
    lab_guard(workspace)
    package_verifier, sbom_verifier = offline_callbacks(environment)
    # These are real callbacks, never a fixture fallback or saved result JSON.
    # Refusal occurs before Docker planning, token planting or decision consumption.
    require(package_verifier(package) is True, "strict offline package authentication refused")
    require(sbom_verifier(package) is True, "strict offline SPDX/platform authentication refused")
    host, measured = measured_host(environment)
    return package_verifier, sbom_verifier, host, measured
