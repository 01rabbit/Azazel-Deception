#!/usr/bin/env python3
"""T2 live-Docker drill — materialize, isolate, tamper, terminate, reset (dev).

Unlike the shadow/replay drills, this starts a REAL container from the
digest-pinned reference image and exercises the gated live lifecycle through
``DockerComposeAdapter(live_enabled=True)``, then proves the doctrine on a
running decoy:

  L1 materialize   activate -> exactly one container is actually running.
  L2 isolation     that container publishes no host port, is on an internal
                   network, runs non-root, read-only rootfs, all caps dropped,
                   no-new-privileges.
  L3 tamper->reset attacker writes a file inside the decoy; terminate destroys
                   the container; a fresh activation materializes from the
                   pinned image with the tamper gone (no persistence).
  L4 reset+evidence reset reports evidence_preserved and the evidence chain
                   verifies; deterministic reset leaves an absent state.

Explicitly opt-in — it starts containers, so it refuses to run without
``--live`` (or AZAZEL_DECEPTION_LIVE=1) and a reachable Docker daemon. Prints a
PASS/FAIL table; exit 0 iff all pass. Cleans up its own containers.

Run (from the Azazel-Deception checkout, Docker Desktop / daemon running):
    AZAZEL_DECEPTION_LIVE=1 python scripts/dev/live_docker_drill.py --live
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SRC = REPO / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

PACKAGE = REPO / "examples/packages/municipal-linux-v1/package.yaml"
COMPOSE = REPO / "runtime/compose/reference-linux.compose.yaml"

results: list[tuple[str, bool, str]] = []


def _record(name: str, ok: bool, detail: str) -> None:
    results.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} — {detail}", flush=True)


def _docker_ok() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(
        ["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        timeout=30, check=False,
    ).returncode == 0


def _host() -> dict:
    return {
        "node_id": "az06-t2", "architecture": "amd64", "cpu_cores": 4,
        "memory_mb": 8192, "storage_free_mb": 65536,
        "runtime_adapters": {"docker_compose": True},
        "kvm_available": False, "gpu_available": False,
    }


def _decision(package: dict, plan: dict, decision_id: str) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "schema_version": "environment-activation-decision/v0.1",
        "decision_id": decision_id, "decision_authority": "azazel-edge",
        "status": "accepted", "package_id": package["package_id"],
        "package_digest": package["package_digest"], "target_node_id": plan["node_id"],
        "selected_tier": plan["selected_tier"],
        "budget": {"cpu_cores": 2, "memory_mb": 1024, "storage_mb": 2048,
                   "max_connections": 100, "max_duration_seconds": 300, "bandwidth_kbps": 5000},
        "safety": {"outbound_allowed": False, "production_access": False,
                   "privileged_containers": False, "host_network": False,
                   "runtime_socket_exposed_to_decoys": False,
                   "edge_control_access_from_decoys": False},
        "effective_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=5)).isoformat(),
        "evidence_refs": [], "reason_codes": ["t2-drill"],
    }


def _termination(environment_id: str, decision_id: str) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "schema_version": "environment-termination-decision/v0.1",
        "decision_id": decision_id, "decision_authority": "azazel-edge",
        "environment_id": environment_id, "reason": "operator_request",
        "issued_at": now.isoformat(), "expires_at": (now + timedelta(minutes=1)).isoformat(),
        "evidence_refs": [],
    }


def _containers(adapter, environment_id: str) -> list[dict]:
    project = adapter._project_name(environment_id)
    out = subprocess.run(
        ["docker", "ps", "-a", "--filter",
         f"label=com.docker.compose.project={project}", "--format", "{{json .}}"],
        stdout=subprocess.PIPE, text=True, timeout=30, check=True,
    ).stdout
    return [json.loads(line) for line in out.splitlines() if line.strip()]


def _inspect(cid: str) -> dict:
    out = subprocess.run(["docker", "inspect", cid], stdout=subprocess.PIPE,
                         text=True, timeout=30, check=True).stdout
    return json.loads(out)[0]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="T2 live-Docker lifecycle drill")
    parser.add_argument("--live", action="store_true",
                        help="required: acknowledge this starts real containers")
    args = parser.parse_args(argv)

    if not (args.live or os.environ.get("AZAZEL_DECEPTION_LIVE") == "1"):
        print("refusing to start containers without --live (or AZAZEL_DECEPTION_LIVE=1)",
              file=sys.stderr)
        return 2
    if not _docker_ok():
        print("Docker daemon not reachable (start Docker Desktop / dockerd)", file=sys.stderr)
        return 2

    from azazel_deception.package import calculate_package_digest, load_package
    from azazel_deception.planner import build_placement_plan
    from azazel_deception.runtime.compose import DockerComposeAdapter

    package = load_package(PACKAGE)
    for c in package["components"]:
        c["image"]["verified"] = c["component_id"] == "intranet-web"
    package["package_digest"] = calculate_package_digest(package)

    state_root = Path(tempfile.mkdtemp(prefix="az06-t2-"))
    adapter = DockerComposeAdapter(COMPOSE, state_root, live_enabled=True,
                                   package_verifier=lambda _pkg: True)
    env_id = f"t2-{uuid.uuid4().hex[:12]}"
    dec = f"edge-t2-{uuid.uuid4().hex[:8]}"
    activated = False
    try:
        # L1 — materialize a real container.
        plan = build_placement_plan(package, _host(), requested_tier="lite",
                                    edge_decision_id=dec)
        act = adapter.activate_environment(env_id, package, plan, _decision(package, plan, dec))
        activated = True
        conts = _containers(adapter, env_id)
        running = [c for c in conts if c.get("State") == "running"]
        _record("L1 materialize (activate -> 1 running container)",
                act.get("status") == "active" and len(running) == 1,
                f"status={act.get('status')} containers={len(conts)} running={len(running)}")

        # L2 — the running decoy is isolated.
        cid = conts[0]["ID"]
        ins = _inspect(cid)
        hostcfg, cfg, netset = ins["HostConfig"], ins["Config"], ins["NetworkSettings"]
        bound = {p: b for p, b in (netset.get("Ports") or {}).items() if b}
        checks = {
            "no_published_port": not bound,
            "non_root_user": cfg.get("User") in ("101:101", "101"),
            "read_only_rootfs": hostcfg.get("ReadonlyRootfs") is True,
            "caps_dropped_all": "ALL" in (hostcfg.get("CapDrop") or []),
            "no_new_privileges": any("no-new-privileges" in s
                                     for s in (hostcfg.get("SecurityOpt") or [])),
        }
        _record("L2 isolation (no host port, non-root, ro-rootfs, caps dropped)",
                all(checks.values()),
                ", ".join(f"{k}={v}" for k, v in checks.items()))

        # L3 — tamper inside the decoy, terminate, re-materialize fresh.
        subprocess.run(["docker", "exec", cid, "sh", "-c",
                        "echo pwned > /tmp/backdoor && cat /tmp/backdoor"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        term = adapter.terminate_environment(env_id, _termination(env_id, f"{dec}-term"))
        reset = adapter.reset_environment(env_id)
        activated = False
        gone = _containers(adapter, env_id)
        # Fresh activation must come from the pinned image, tamper absent.
        env2 = f"t2-{uuid.uuid4().hex[:12]}"
        dec2 = f"edge-t2-{uuid.uuid4().hex[:8]}"
        plan2 = build_placement_plan(package, _host(), requested_tier="lite",
                                     edge_decision_id=dec2)
        adapter.activate_environment(env2, package, plan2, _decision(package, plan2, dec2))
        cid2 = _containers(adapter, env2)[0]["ID"]
        probe = subprocess.run(["docker", "exec", cid2, "sh", "-c",
                                "cat /tmp/backdoor 2>/dev/null || echo CLEAN"],
                               stdout=subprocess.PIPE, text=True, timeout=30).stdout.strip()
        adapter.terminate_environment(env2, _termination(env2, f"{dec2}-term"))
        adapter.reset_environment(env2)
        _record("L3 tamper destroyed by terminate+reset (no persistence)",
                term.get("status") == "terminated" and not gone and probe == "CLEAN",
                f"terminated={term.get('status')} old_containers={len(gone)} fresh_probe={probe}")

        # L4 — reset preserved evidence and the chain verifies.
        chain_ok = adapter.state.verify_evidence_chain(env_id)
        status_absent = adapter.collect_status(env_id).get("state") == "absent"
        _record("L4 deterministic reset + evidence preserved",
                reset.get("status") == "reset" and reset.get("evidence_preserved") is True
                and chain_ok and status_absent,
                f"reset={reset.get('status')} evidence_preserved={reset.get('evidence_preserved')} "
                f"chain_ok={chain_ok} state_absent={status_absent}")
    finally:
        # Best-effort cleanup of anything still up.
        if activated:
            try:
                adapter.terminate_environment(env_id, _termination(env_id, f"{dec}-cleanup"))
                adapter.reset_environment(env_id)
            except Exception:  # noqa: BLE001
                pass
        shutil.rmtree(state_root, ignore_errors=True)

    print("\n==================== T2 LIVE-DOCKER SUMMARY ====================")
    for name, ok, _ in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    passed = sum(1 for _, ok, _ in results if ok)
    print(f"  ----> {passed}/{len(results)} passed")
    print("===============================================================")
    return 0 if passed == len(results) and results else 1


if __name__ == "__main__":
    raise SystemExit(main())
