"""Static safety-policy validation for attacker-facing Compose assets."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


class RuntimePolicyError(ValueError):
    pass


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _is_non_root_user(value: Any) -> bool:
    if value is None:
        return False
    text = str(value).strip().lower()
    if not text or text == "root":
        return False
    uid = text.split(":", 1)[0]
    return uid not in {"0", "root"}


def validate_compose_policy(path: str | Path) -> list[str]:
    """Return deterministic safety violations for a Docker Compose document.

    Phase-1 AZ-06 attacker-facing Compose assets must be isolated by
    construction. Published host ports are forbidden because exposure/routing
    belongs to Edge. Runtime sockets, host namespaces, local image builds,
    root execution, and capability re-addition are forbidden.
    """

    document = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        return ["compose_root_not_mapping"]

    violations: list[str] = []
    networks = document.get("networks") or {}
    if not isinstance(networks, dict) or not networks:
        violations.append("no_declared_internal_network")
    else:
        for name, config in sorted(networks.items()):
            if not isinstance(config, dict) or config.get("internal") is not True:
                violations.append(f"network_not_internal:{name}")

    services = document.get("services") or {}
    if not isinstance(services, dict) or not services:
        violations.append("no_services")
        return sorted(set(violations))

    for service_name, config in sorted(services.items()):
        prefix = f"service:{service_name}:"
        if not isinstance(config, dict):
            violations.append(prefix + "config_not_mapping")
            continue
        if config.get("build") is not None:
            violations.append(prefix + "local_build_forbidden")
        if not config.get("image"):
            violations.append(prefix + "image_missing")
        if not _is_non_root_user(config.get("user")):
            violations.append(prefix + "non_root_user_required")
        if config.get("privileged") is True:
            violations.append(prefix + "privileged")
        if config.get("network_mode") == "host":
            violations.append(prefix + "host_network")
        if config.get("pid") == "host":
            violations.append(prefix + "host_pid_namespace")
        if config.get("ipc") == "host":
            violations.append(prefix + "host_ipc_namespace")
        if config.get("userns_mode") == "host":
            violations.append(prefix + "host_user_namespace")
        if config.get("ports"):
            violations.append(prefix + "published_ports")
        if config.get("read_only") is not True:
            violations.append(prefix + "rootfs_not_read_only")

        cap_drop = {str(item).upper() for item in _as_list(config.get("cap_drop"))}
        if "ALL" not in cap_drop:
            violations.append(prefix + "cap_drop_all_missing")
        if _as_list(config.get("cap_add")):
            violations.append(prefix + "capability_readdition_forbidden")
        security_opt = {str(item).lower() for item in _as_list(config.get("security_opt"))}
        if "no-new-privileges:true" not in security_opt:
            violations.append(prefix + "no_new_privileges_missing")

        if not config.get("pids_limit"):
            violations.append(prefix + "pids_limit_missing")
        if not config.get("mem_limit"):
            violations.append(prefix + "memory_limit_missing")
        if not config.get("cpus"):
            violations.append(prefix + "cpu_limit_missing")

        service_networks = config.get("networks") or []
        if isinstance(service_networks, dict):
            service_network_names = set(service_networks)
        else:
            service_network_names = {str(item) for item in _as_list(service_networks)}
        if not service_network_names:
            violations.append(prefix + "no_network_binding")
        for network_name in sorted(service_network_names):
            network_config = networks.get(network_name) if isinstance(networks, dict) else None
            if not isinstance(network_config, dict) or network_config.get("internal") is not True:
                violations.append(prefix + f"non_internal_network:{network_name}")

        for volume in _as_list(config.get("volumes")):
            text = str(volume).lower()
            if "docker.sock" in text or "podman.sock" in text or "/run/containerd" in text:
                violations.append(prefix + "runtime_socket_mount")
            if text.startswith("/proc:") or text.startswith("/sys:") or text.startswith("/dev:"):
                violations.append(prefix + "sensitive_host_mount")

    return sorted(set(violations))


def require_safe_compose(path: str | Path) -> None:
    violations = validate_compose_policy(path)
    if violations:
        raise RuntimePolicyError("unsafe compose policy: " + ", ".join(violations))
