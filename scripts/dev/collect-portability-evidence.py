from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _run(*command: str) -> str:
    result = subprocess.run(
        list(command),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _json(*command: str) -> Any:
    return json.loads(_run(*command))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", required=True)
    parser.add_argument("--compose-file", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    compose_file = str(Path(args.compose_file).resolve())
    cid = _run(
        "docker",
        "compose",
        "-p",
        args.project,
        "-f",
        compose_file,
        "ps",
        "-q",
        "intranet-web",
    )
    if not cid:
        raise SystemExit("intranet-web container is not running")

    container = _json("docker", "inspect", cid)[0]
    image_ref = container["Config"]["Image"]
    image = _json("docker", "image", "inspect", image_ref)[0]
    network_name = f"{args.project}_decoy_internal"
    network = _json("docker", "network", "inspect", network_name)[0]

    host_config = container["HostConfig"]
    evidence = {
        "schema_version": "az06-portability-evidence/v0.1",
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "runner": {
            "os": platform.system(),
            "machine": platform.machine(),
            "github_runner_arch": os.environ.get("RUNNER_ARCH"),
            "github_runner_os": os.environ.get("RUNNER_OS"),
            "github_run_id": os.environ.get("GITHUB_RUN_ID"),
            "github_sha": os.environ.get("GITHUB_SHA"),
        },
        "runtime": {
            "docker_version": _run("docker", "--version"),
            "compose_version": _run("docker", "compose", "version"),
            "project": args.project,
        },
        "image": {
            "reference": image_ref,
            "architecture": image.get("Architecture"),
            "os": image.get("Os"),
            "image_id": image.get("Id"),
            "repo_digests": image.get("RepoDigests") or [],
        },
        "container": {
            "id": cid,
            "readonly_rootfs": bool(host_config.get("ReadonlyRootfs")),
            "cap_drop": host_config.get("CapDrop") or [],
            "security_opt": host_config.get("SecurityOpt") or [],
            "pids_limit": host_config.get("PidsLimit"),
            "memory_bytes": host_config.get("Memory"),
            "nano_cpus": host_config.get("NanoCpus"),
            "published_ports": container.get("NetworkSettings", {}).get("Ports") or {},
        },
        "network": {
            "name": network_name,
            "internal": bool(network.get("Internal")),
            "driver": network.get("Driver"),
        },
    }

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
