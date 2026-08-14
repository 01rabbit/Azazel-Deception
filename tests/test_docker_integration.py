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
import signal
import subprocess
import time
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


# --- Docker daemon lifecycle helpers (for the daemon-restart drill) --------
#
# These manipulate the host's dockerd process itself, not a container. Any
# test using them MUST restore a healthy running daemon before returning,
# via try/finally, since other work in this environment depends on it.

_DOCKERD_RESTART_LOG = Path("/tmp/azazel_deception_dockerd_restart_test.log")


def _docker_daemon_up() -> bool:
    probe = subprocess.run(
        ["docker", "info"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
        check=False,
    )
    return probe.returncode == 0


def _dockerd_pid() -> int:
    result = subprocess.run(
        ["pgrep", "-x", "dockerd"],
        stdout=subprocess.PIPE,
        text=True,
        timeout=10,
        check=False,
    )
    pids = [int(pid) for pid in result.stdout.split() if pid.strip()]
    if not pids:
        raise RuntimeError("no running dockerd process found to restart-drill against")
    return pids[0]


def _wait_until(predicate, *, timeout: float, description: str, interval: float = 1.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(interval)
    raise AssertionError(f"timed out after {timeout}s waiting for {description}")


def _process_gone(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        # Still alive but no longer signalable as us; treat as gone for
        # waiting purposes, matching os.kill's own error semantics.
        return True
    return False


def _stop_dockerd(pid: int) -> None:
    """SIGTERM dockerd and wait for the *process* to fully exit.

    `docker info` can start failing (socket torn down) before the dockerd
    process itself has finished its graceful shutdown and released
    /var/run/docker.pid, so waiting on the socket alone is not enough before
    trying to start a replacement daemon. Escalates to SIGKILL if graceful
    shutdown does not finish in time, then clears a leftover pidfile so a
    fresh dockerd is never blocked by "process with PID N is still running".
    """

    os.kill(pid, signal.SIGTERM)
    if not _wait_until_bool(lambda: _process_gone(pid), timeout=30.0):
        os.kill(pid, signal.SIGKILL)
        _wait_until_bool(lambda: _process_gone(pid), timeout=10.0)
    Path("/var/run/docker.pid").unlink(missing_ok=True)


def _wait_until_bool(predicate, *, timeout: float, interval: float = 0.5) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def _restart_dockerd() -> None:
    """Start a fresh dockerd and block until `docker info` succeeds again.

    Retries a few times: a dockerd that starts immediately after the prior
    one exited can still lose a race against a not-yet-released pidfile.
    """

    last_error: AssertionError | None = None
    for attempt in range(3):
        Path("/var/run/docker.pid").unlink(missing_ok=True)
        with open(_DOCKERD_RESTART_LOG, "a", encoding="utf-8") as log_handle:
            subprocess.Popen(
                ["dockerd"],
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
        try:
            _wait_until(
                _docker_daemon_up,
                timeout=25.0,
                description=f"docker daemon to come back up (attempt {attempt + 1}/3)",
            )
            return
        except AssertionError as exc:
            last_error = exc
            time.sleep(1.0)
    assert last_error is not None
    raise last_error


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


def test_daemon_restart_preserves_state_and_recovers(tmp_path, cleanup_environment):
    """Runtime daemon restart mid-lifecycle: while dockerd is down, an
    attempted termination fails closed (RuntimeGateError, local state records
    a "failed"/"termination" failure, evidence chain intact) rather than
    silently losing state or falsely reporting success. Once dockerd is back,
    the local state store and evidence chain are shown to have survived the
    outage untouched, and the operator kill switch still recovers the
    environment to a clean terminated/reset state. Containers are not
    expected to survive the daemon restart (no live-restore is configured
    here) so this asserts on the adapter's fail-closed bookkeeping, not on
    container survival.
    """

    adapter = _adapter(tmp_path)
    environment_id = _environment_id()
    cleanup_environment.append((adapter, environment_id))

    _activate(adapter, environment_id, f"edge-activate-{environment_id}")
    assert len(_project_containers(adapter, environment_id)) == 1

    daemon_pid = _dockerd_pid()
    try:
        _stop_dockerd(daemon_pid)
        assert not _docker_daemon_up()

        # Fail closed while the daemon is unreachable: termination must not
        # succeed silently, and it must not lose the local record either.
        with pytest.raises(RuntimeGateError):
            _terminate(adapter, environment_id, f"edge-terminate-{environment_id}")

        failed_state = adapter.collect_status(environment_id)
        assert failed_state["state"] == "failed"
        assert failed_state["failure_stage"] == "termination"

        # State/evidence live on local disk, independent of the Docker
        # daemon, so nothing about the outage should disturb them.
        assert adapter.state.read(environment_id) is not None
        event_types_during_outage = [
            event["event_type"] for event in adapter.export_evidence(environment_id)
        ]
        assert event_types_during_outage == ["activated", "failure"]
        assert adapter.verify_evidence(environment_id) is True
    finally:
        _restart_dockerd()

    # The daemon is back up; the state store and evidence chain must have
    # come through the outage intact.
    assert _docker_available()
    recovered_state = adapter.collect_status(environment_id)
    assert recovered_state["state"] == "failed"
    assert recovered_state["failure_stage"] == "termination"
    assert adapter.verify_evidence(environment_id) is True

    # "failed" is a _MAYBE_RUNNING_STATES member, so the kill switch retries
    # the stop regardless of whether the container actually survived the
    # daemon restart, and always brings the environment to "terminated".
    stopped = adapter.emergency_stop(
        environment_id, operator="integration-test", reason="daemon restart drill"
    )
    assert stopped["status"] == "terminated"
    assert _project_containers(adapter, environment_id) == []

    reset = adapter.reset_environment(environment_id)
    assert reset["status"] == "reset"
    events = adapter.export_evidence(environment_id)
    event_types = [event["event_type"] for event in events]
    assert event_types == ["activated", "failure", "terminated", "reset_completed"]
    assert adapter.verify_evidence(environment_id) is True


def test_pid_exhaustion_is_contained_by_limits(tmp_path, cleanup_environment):
    """A fork storm inside the running container is capped by the compose
    policy's pids_limit=128: the storm itself fails to acquire the full 200
    processes it asks for, the container's process count stays bounded
    rather than climbing unbounded, and the host-side adapter (status
    collection, clean termination) is completely unaffected by the
    in-container exhaustion.
    """

    adapter = _adapter(tmp_path)
    environment_id = _environment_id()
    cleanup_environment.append((adapter, environment_id))

    _activate(adapter, environment_id, f"edge-activate-{environment_id}")
    container_id = _single_container_id(adapter, environment_id)
    assert _inspect(container_id)["HostConfig"]["PidsLimit"] == 128

    storm = _docker_exec(
        container_id,
        "sh",
        "-c",
        "for i in $(seq 1 200); do sleep 5 & done; sleep 1; echo done",
    )
    # A fully successful 200-fork storm (rc=0) would mean pids_limit did not
    # engage; the container's shell reports it cannot fork further.
    assert storm.returncode != 0
    assert "fork" in storm.stdout.lower()

    # Use `docker top` (host-side, joins the container's PID namespace)
    # rather than a fresh `docker exec`, since the cgroup can still be
    # saturated immediately after the storm and a brand-new exec may itself
    # fail to fork until the storm's own processes exit.
    top = subprocess.run(
        ["docker", "top", container_id, "-o", "pid"],
        stdout=subprocess.PIPE,
        text=True,
        timeout=30,
        check=True,
    )
    process_count = max(len(top.stdout.splitlines()) - 1, 0)  # drop header row
    assert process_count <= 135  # pids_limit=128 plus a small margin

    # Host-side adapter functionality is unaffected by the in-container
    # exhaustion: status collection and termination both still work cleanly.
    status = adapter.collect_status(environment_id)
    assert status["state"] == "active"

    terminated = _terminate(adapter, environment_id, f"edge-terminate-{environment_id}")
    assert terminated["status"] == "terminated"
    assert _project_containers(adapter, environment_id) == []

    reset = adapter.reset_environment(environment_id)
    assert reset["status"] == "reset"
    assert adapter.verify_evidence(environment_id) is True


def test_storage_and_memory_ceilings_contain_exhaustion(tmp_path, cleanup_environment):
    """Demonstrates two real ceilings the compose policy enforces against a
    resource-exhaustion attempt inside the container:

    (a) the noexec 16m tmpfs mounted at /tmp hits ENOSPC on a 300MB write
        attempt, well short of the requested size, proving the storage quota
        is enforced rather than advisory; and
    (b) a process that keeps doubling an in-memory string is OOM-killed by
        the 256m memory cgroup (confirmed via `docker inspect`'s
        State.OOMKilled) rather than being left free to grow unbounded.

    The reference image is Alpine/BusyBox and ships no memory-allocation
    tool (no python3/perl and a shell `read` cannot be sized), so (b) uses
    shell string-doubling as a portable, deterministic way to force
    allocation growth rather than claiming to hit the exact 256MB boundary.
    Both probes are run against the *same* live container to also show the
    container's main process, and the host-side adapter, stay healthy and
    terminable after each ceiling is hit — the exhaustion attempts are
    contained, not merely fatal to the whole environment.
    """

    adapter = _adapter(tmp_path)
    environment_id = _environment_id()
    cleanup_environment.append((adapter, environment_id))

    _activate(adapter, environment_id, f"edge-activate-{environment_id}")
    container_id = _single_container_id(adapter, environment_id)
    inspected = _inspect(container_id)
    assert inspected["HostConfig"]["Memory"] == 256 * 1024 * 1024

    # (a) tmpfs write ceiling.
    tmpfs_write = _docker_exec(
        container_id, "sh", "-c", "dd if=/dev/zero of=/tmp/bigfile bs=1M count=300 2>&1"
    )
    assert tmpfs_write.returncode != 0
    assert "space" in tmpfs_write.stdout.lower()

    df = _docker_exec(container_id, "df", "-k", "/tmp")
    assert df.returncode == 0, df.stdout
    used_kb = int(df.stdout.splitlines()[-1].split()[2])
    assert used_kb <= 17408  # 16MB tmpfs ceiling plus a small margin, not ~300MB

    # Container must still be alive and exec-able after hitting the storage
    # ceiling; ENOSPC on a write is not expected to kill anything.
    assert _docker_exec(container_id, "sh", "-c", "echo alive").returncode == 0

    # (b) memory cgroup ceiling: 40 doublings of a 1-byte string would reach
    # roughly 2**40 bytes (~1TB), far past the 256m limit, so completing all
    # 40 without being killed would mean the memory ceiling did not engage.
    mem_probe = _docker_exec(
        container_id,
        "sh",
        "-c",
        'x=A; i=0; while [ $i -lt 40 ]; do x="$x$x"; i=$((i+1)); done; echo "survived $i ${#x}"',
    )
    assert mem_probe.returncode != 0

    inspected_after = _inspect(container_id)
    assert inspected_after["State"]["OOMKilled"] is True
    # Only the runaway exec'd process was killed; the container's own main
    # process (nginx) is untouched and the container is still running.
    assert inspected_after["State"]["Running"] is True

    # Host-side adapter functionality and the container's primary process
    # both remain healthy after both ceilings were hit.
    assert _docker_exec(container_id, "sh", "-c", "echo alive").returncode == 0
    status = adapter.collect_status(environment_id)
    assert status["state"] == "active"

    terminated = _terminate(adapter, environment_id, f"edge-terminate-{environment_id}")
    assert terminated["status"] == "terminated"
    assert _project_containers(adapter, environment_id) == []

    reset = adapter.reset_environment(environment_id)
    assert reset["status"] == "reset"
    assert adapter.verify_evidence(environment_id) is True
