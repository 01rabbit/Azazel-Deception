"""Real-Docker integration tests for the gated live lifecycle and reset.

These exercise the DockerComposeAdapter against an actual Docker daemon and
the digest-pinned reference image: gated activation, runtime isolation
invariants, attacker-modified state destruction, container-crash recovery via
the operator kill switch, termination-failure fail-closed behavior, and
deterministic reset with evidence preservation.

They are opt-in: set AZAZEL_DECEPTION_DOCKER_TESTS=1 with a reachable Docker
daemon (the reference image is pulled from GHCR on first use). Everything
here still runs with live gates satisfied through an injected trusted test
verifier; the real GitHub attestation path is proven separately in CI
workflows. Physical-network/HIL isolation properties remain out of scope.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import uuid
from pathlib import Path

import pytest

from azazel_deception.package import calculate_package_digest, load_package
from azazel_deception.planner import build_placement_plan
from azazel_deception.runtime.compose import DockerComposeAdapter, RuntimeGateError

from tests.test_runtime import _decision, _host, _termination

PACKAGE = Path("examples/packages/municipal-linux-v1/package.yaml")
COMPOSE = Path("runtime/compose/reference-linux.compose.yaml")


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    probe = subprocess.run(
        ["docker", "info"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )
    return probe.returncode == 0


pytestmark = pytest.mark.skipif(
    os.environ.get("AZAZEL_DECEPTION_DOCKER_TESTS") != "1" or not _docker_available(),
    reason="requires AZAZEL_DECEPTION_DOCKER_TESTS=1 and a reachable Docker daemon",
)


def _lite_only_package() -> dict:
    package = load_package(PACKAGE)
    for component in package["components"]:
        component["image"]["verified"] = component["component_id"] == "intranet-web"
    package["package_digest"] = calculate_package_digest(package)
    return package


def _trusted_test_verifier(package) -> bool:
    return True


def _adapter(state_root: Path, compose_file: Path = COMPOSE) -> DockerComposeAdapter:
    return DockerComposeAdapter(
        compose_file,
        state_root,
        live_enabled=True,
        package_verifier=_trusted_test_verifier,
    )


def _environment_id() -> str:
    return f"it-{uuid.uuid4().hex[:12]}"


def _activate(adapter: DockerComposeAdapter, environment_id: str, decision_id: str):
    package = _lite_only_package()
    host = _host()
    plan = build_placement_plan(
        package, host, requested_tier="lite", edge_decision_id=decision_id
    )
    decision = _decision(package, plan, decision_id=decision_id)
    return adapter.activate_environment(environment_id, package, plan, decision)


def _terminate(adapter: DockerComposeAdapter, environment_id: str, decision_id: str):
    termination = _termination(decision_id)
    termination["environment_id"] = environment_id
    return adapter.terminate_environment(environment_id, termination)


def _project_containers(adapter: DockerComposeAdapter, environment_id: str) -> list[dict]:
    project = adapter._project_name(environment_id)
    listing = subprocess.run(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            f"label=com.docker.compose.project={project}",
            "--format",
            "{{json .}}",
        ],
        stdout=subprocess.PIPE,
        text=True,
        timeout=30,
        check=True,
    )
    return [json.loads(line) for line in listing.stdout.splitlines() if line.strip()]


def _single_container_id(adapter: DockerComposeAdapter, environment_id: str) -> str:
    containers = _project_containers(adapter, environment_id)
    assert len(containers) == 1, containers
    return containers[0]["ID"]


def _inspect(container_id: str) -> dict:
    result = subprocess.run(
        ["docker", "inspect", container_id],
        stdout=subprocess.PIPE,
        text=True,
        timeout=30,
        check=True,
    )
    return json.loads(result.stdout)[0]


def _docker_exec(container_id: str, *command: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "exec", container_id, *command],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=30,
        check=False,
    )


@pytest.fixture
def cleanup_environment():
    """Best-effort compose-project teardown so a failed test leaks nothing."""

    tracked: list[tuple[DockerComposeAdapter, str]] = []
    yield tracked
    for adapter, environment_id in tracked:
        subprocess.run(
            [
                "docker",
                "compose",
                "-f",
                str(COMPOSE),
                "-p",
                adapter._project_name(environment_id),
                "down",
                "--remove-orphans",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=60,
            check=False,
        )


def test_gated_live_lifecycle_enforces_isolation_and_preserves_evidence(
    tmp_path, cleanup_environment
):
    adapter = _adapter(tmp_path)
    environment_id = _environment_id()
    cleanup_environment.append((adapter, environment_id))

    result = _activate(adapter, environment_id, f"edge-activate-{environment_id}")
    assert result == {
        "environment_id": environment_id,
        "status": "active",
        "live_execution": True,
    }

    container_id = _single_container_id(adapter, environment_id)
    inspected = _inspect(container_id)
    host_config = inspected["HostConfig"]
    config = inspected["Config"]

    # The static Compose policy promises must hold on the running container.
    assert inspected["State"]["Running"] is True
    assert host_config["ReadonlyRootfs"] is True
    assert host_config["CapDrop"] == ["ALL"]
    assert not host_config.get("CapAdd")
    assert "no-new-privileges:true" in (host_config.get("SecurityOpt") or [])
    assert host_config["Privileged"] is False
    assert host_config["NetworkMode"] != "host"
    assert not host_config.get("PortBindings")
    assert not inspected["NetworkSettings"].get("Ports") or all(
        binding is None for binding in inspected["NetworkSettings"]["Ports"].values()
    )
    assert host_config["PidsLimit"] == 128
    assert host_config["Memory"] == 256 * 1024 * 1024
    assert host_config["NanoCpus"] == 500_000_000
    assert config["User"] == "101:101"

    networks = inspected["NetworkSettings"]["Networks"]
    assert set(networks) == {f"{adapter._project_name(environment_id)}_decoy_internal"}

    terminated = _terminate(adapter, environment_id, f"edge-terminate-{environment_id}")
    assert terminated["status"] == "terminated"
    assert _project_containers(adapter, environment_id) == []

    reset = adapter.reset_environment(environment_id)
    assert reset["status"] == "reset"
    assert reset["evidence_preserved"] is True
    assert adapter.collect_status(environment_id) == {
        "environment_id": environment_id,
        "state": "absent",
    }

    events = adapter.export_evidence(environment_id)
    event_types = [event["event_type"] for event in events]
    assert event_types == ["activated", "terminated", "reset_completed"]
    assert adapter.verify_evidence(environment_id) is True

    # Tampering with finalized evidence must be detected.
    evidence_path = adapter.state.evidence_path(environment_id)
    lines = evidence_path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[0])
    tampered["event_type"] = "reset_completed"
    lines[0] = json.dumps(tampered)
    evidence_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert adapter.verify_evidence(environment_id) is False


def test_attacker_modified_state_is_destroyed_by_termination(
    tmp_path, cleanup_environment
):
    adapter = _adapter(tmp_path)
    environment_id = _environment_id()
    cleanup_environment.append((adapter, environment_id))

    _activate(adapter, environment_id, f"edge-activate-{environment_id}")
    container_id = _single_container_id(adapter, environment_id)

    # Attacker writes into the writable tmpfs; the read-only rootfs refuses.
    wrote = _docker_exec(
        container_id, "sh", "-c", "echo persistence > /tmp/attacker-implant"
    )
    assert wrote.returncode == 0, wrote.stdout
    rootfs_write = _docker_exec(
        container_id, "sh", "-c", "echo persistence > /usr/share/nginx/html/backdoor"
    )
    assert rootfs_write.returncode != 0

    _terminate(adapter, environment_id, f"edge-terminate-{environment_id}")
    assert _project_containers(adapter, environment_id) == []
    adapter.reset_environment(environment_id)

    # A fresh activation must materialize from the pinned image, not from any
    # attacker-modified filesystem state.
    second_id = _environment_id()
    cleanup_environment.append((adapter, second_id))
    _activate(adapter, second_id, f"edge-activate-{second_id}")
    fresh_container = _single_container_id(adapter, second_id)
    probe = _docker_exec(fresh_container, "sh", "-c", "test -e /tmp/attacker-implant")
    assert probe.returncode != 0
    _terminate(adapter, second_id, f"edge-terminate-{second_id}")
    adapter.reset_environment(second_id)


def test_container_crash_is_recovered_by_kill_switch(tmp_path, cleanup_environment):
    adapter = _adapter(tmp_path)
    environment_id = _environment_id()
    cleanup_environment.append((adapter, environment_id))

    _activate(adapter, environment_id, f"edge-activate-{environment_id}")
    container_id = _single_container_id(adapter, environment_id)

    subprocess.run(
        ["docker", "kill", container_id],
        stdout=subprocess.DEVNULL,
        timeout=30,
        check=True,
    )
    assert _inspect(container_id)["State"]["Running"] is False

    # Local state still says active; the kill switch must clean up regardless.
    stopped = adapter.emergency_stop(
        environment_id, operator="integration-test", reason="container crash drill"
    )
    assert stopped["status"] == "terminated"
    assert _project_containers(adapter, environment_id) == []
    reset = adapter.reset_environment(environment_id)
    assert reset["status"] == "reset"
    assert adapter.verify_evidence(environment_id) is True


def test_termination_failure_fails_closed_and_kill_switch_recovers(
    tmp_path, cleanup_environment
):
    adapter = _adapter(tmp_path)
    environment_id = _environment_id()
    cleanup_environment.append((adapter, environment_id))

    _activate(adapter, environment_id, f"edge-activate-{environment_id}")
    assert len(_project_containers(adapter, environment_id)) == 1

    # Inject a teardown fault: the same runtime state driven through an adapter
    # whose compose asset is missing cannot terminate and must fail closed.
    broken = _adapter(tmp_path, compose_file=tmp_path / "missing-compose.yaml")
    with pytest.raises(RuntimeGateError):
        _terminate(broken, environment_id, f"edge-terminate-{environment_id}")

    failed_state = adapter.collect_status(environment_id)
    assert failed_state["state"] == "failed"
    assert failed_state["failure_stage"] == "termination"
    # The decoy is still running: failure must not be reported as termination.
    assert len(_project_containers(adapter, environment_id)) == 1

    stopped = adapter.emergency_stop(
        environment_id, operator="integration-test", reason="teardown fault drill"
    )
    assert stopped["status"] == "terminated"
    assert _project_containers(adapter, environment_id) == []

    reset = adapter.reset_environment(environment_id)
    assert reset["status"] == "reset"
    events = adapter.export_evidence(environment_id)
    event_types = [event["event_type"] for event in events]
    assert "failure" in event_types
    assert adapter.verify_evidence(environment_id) is True


def test_reconciliation_reports_unauthorized_local_environment(
    tmp_path, cleanup_environment
):
    adapter = _adapter(tmp_path)
    environment_id = _environment_id()
    cleanup_environment.append((adapter, environment_id))

    _activate(adapter, environment_id, f"edge-activate-{environment_id}")

    divergence = adapter.reconcile_with_edge([])
    assert divergence["consistent"] is False
    assert divergence["local_only_active"] == [environment_id]

    stopped = adapter.emergency_stop(
        environment_id, operator="integration-test", reason="revoked by Edge"
    )
    assert stopped["status"] == "terminated"
    assert adapter.reconcile_with_edge([])["consistent"] is True
    adapter.reset_environment(environment_id)
