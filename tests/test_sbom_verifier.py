"""Cryptographic SBOM-attestation verifier and its optional live gate."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from azazel_deception.package import load_package, parse_package
from azazel_deception.planner import build_placement_plan
from azazel_deception.runtime import verifier as verifier_module
from azazel_deception.runtime.compose import DockerComposeAdapter, RuntimeGateError
from azazel_deception.runtime.verifier import (
    GitHubSbomVerifier,
    OciAttachedSbomVerifier,
)

_MULTIARCH_SBOM = (
    '{"linux/amd64":{"SPDX":{"SPDXID":"SPDXRef-DOCUMENT"}},'
    '"linux/arm64":{"SPDX":{"SPDXID":"SPDXRef-DOCUMENT"}}}'
)

PACKAGE = Path("examples/packages/municipal-linux-v1/package.yaml")
COMPOSE = Path("runtime/compose/reference-linux.compose.yaml")


def _package():
    return parse_package(load_package(PACKAGE))


def test_sbom_verifier_fails_closed_without_gh(monkeypatch):
    monkeypatch.setattr(verifier_module.shutil, "which", lambda command: None)
    assert GitHubSbomVerifier()(_package()) is False


def test_sbom_verifier_verifies_each_verified_image_by_digest(monkeypatch):
    monkeypatch.setattr(verifier_module.shutil, "which", lambda command: "/usr/bin/gh")
    seen = []

    def fake_run(command, **kwargs):
        seen.append(command)
        return SimpleNamespace(returncode=0, stdout="verified")

    monkeypatch.setattr(verifier_module.subprocess, "run", fake_run)
    assert GitHubSbomVerifier()(_package()) is True
    # Only the verified component (intranet-web) is checked; the unverified
    # alpine placeholder is skipped.
    assert len(seen) == 1
    cmd = seen[0]
    assert cmd[1:3] == ["attestation", "verify"]
    assert cmd[3].startswith("oci://") and "@sha256:" in cmd[3]
    assert "--predicate-type" in cmd and "https://spdx.dev/Document" in cmd
    assert "--deny-self-hosted-runners" in cmd


def test_sbom_verifier_fails_closed_on_cli_failure(monkeypatch):
    monkeypatch.setattr(verifier_module.shutil, "which", lambda command: "/usr/bin/gh")
    monkeypatch.setattr(
        verifier_module.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=1, stdout="no attestation"),
    )
    assert GitHubSbomVerifier()(_package()) is False


def test_sbom_verifier_fails_closed_on_subprocess_exception(monkeypatch):
    monkeypatch.setattr(verifier_module.shutil, "which", lambda command: "/usr/bin/gh")

    def boom(*a, **k):
        raise OSError("gh crashed")

    monkeypatch.setattr(verifier_module.subprocess, "run", boom)
    assert GitHubSbomVerifier()(_package()) is False


def test_sbom_verifier_rejects_non_digest_pinned_verified_image(monkeypatch):
    monkeypatch.setattr(verifier_module.shutil, "which", lambda command: "/usr/bin/gh")
    called = {"run": False}
    monkeypatch.setattr(
        verifier_module.subprocess,
        "run",
        lambda *a, **k: called.__setitem__("run", True) or SimpleNamespace(returncode=0),
    )
    package = _package()
    mutated = package.model_copy(
        update={
            "components": [
                package.components[0].model_copy(
                    update={
                        "image": package.components[0].image.model_copy(
                            update={"image": "ghcr.io/example/web:latest"}
                        )
                    }
                )
            ]
        }
    )
    assert GitHubSbomVerifier()(mutated) is False
    assert called["run"] is False  # rejected before any external call


def test_oci_sbom_verifier_fails_closed_without_docker(monkeypatch):
    monkeypatch.setattr(verifier_module.shutil, "which", lambda command: None)
    assert OciAttachedSbomVerifier()(_package()) is False


def test_oci_sbom_verifier_validates_per_platform_spdx(monkeypatch):
    monkeypatch.setattr(verifier_module.shutil, "which", lambda command: "/usr/bin/docker")
    seen = []

    def fake_run(command, **kwargs):
        seen.append(command)
        return SimpleNamespace(returncode=0, stdout=_MULTIARCH_SBOM)

    monkeypatch.setattr(verifier_module.subprocess, "run", fake_run)
    assert OciAttachedSbomVerifier()(_package()) is True
    cmd = seen[0]
    assert cmd[1:4] == ["buildx", "imagetools", "inspect"]
    assert "@sha256:" in cmd[4]
    assert cmd[-1] == "{{json .SBOM}}"


def test_oci_sbom_verifier_rejects_missing_platform_spdx(monkeypatch):
    monkeypatch.setattr(verifier_module.shutil, "which", lambda command: "/usr/bin/docker")
    # Only amd64 present; arm64 platform is declared -> reject.
    monkeypatch.setattr(
        verifier_module.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(
            returncode=0, stdout='{"linux/amd64":{"SPDX":{"SPDXID":"SPDXRef-DOCUMENT"}}}'
        ),
    )
    assert OciAttachedSbomVerifier()(_package()) is False


def test_oci_sbom_verifier_rejects_unparsable_output(monkeypatch):
    monkeypatch.setattr(verifier_module.shutil, "which", lambda command: "/usr/bin/docker")
    monkeypatch.setattr(
        verifier_module.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=0, stdout="not json"),
    )
    assert OciAttachedSbomVerifier()(_package()) is False


def test_oci_sbom_verifier_fails_closed_on_inspect_error(monkeypatch):
    monkeypatch.setattr(verifier_module.shutil, "which", lambda command: "/usr/bin/docker")
    monkeypatch.setattr(
        verifier_module.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=1, stdout="no attestation"),
    )
    assert OciAttachedSbomVerifier()(_package()) is False


def _host():
    return {
        "node_id": "az06-test",
        "architecture": "amd64",
        "cpu_cores": 4,
        "memory_mb": 8192,
        "storage_free_mb": 65536,
        "runtime_adapters": {"docker_compose": True},
        "kvm_available": False,
        "gpu_available": False,
    }


def _decision(raw, plan):
    now = datetime.now(timezone.utc)
    return {
        "schema_version": "environment-activation-decision/v0.1",
        "decision_id": "edge-decision-1",
        "decision_authority": "azazel-edge",
        "status": "accepted",
        "package_id": raw["package_id"],
        "package_digest": raw["package_digest"],
        "target_node_id": plan["node_id"],
        "selected_tier": plan["selected_tier"],
        "budget": {
            "cpu_cores": 2,
            "memory_mb": 1024,
            "storage_mb": 2048,
            "max_connections": 100,
            "max_duration_seconds": 300,
            "bandwidth_kbps": 5000,
        },
        "safety": {
            "outbound_allowed": False,
            "production_access": False,
            "privileged_containers": False,
            "host_network": False,
            "runtime_socket_exposed_to_decoys": False,
            "edge_control_access_from_decoys": False,
        },
        "effective_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=5)).isoformat(),
        "evidence_refs": [],
        "reason_codes": ["test"],
    }


def test_injected_sbom_gate_rejects_before_docker(tmp_path):
    raw = load_package(PACKAGE)
    plan = build_placement_plan(raw, _host(), "lite", edge_decision_id="edge-decision-1")
    adapter = DockerComposeAdapter(
        COMPOSE,
        tmp_path,
        live_enabled=True,
        package_verifier=lambda p: True,
        sbom_verifier=lambda p: False,  # SBOM attestation cannot be verified
    )
    with pytest.raises(RuntimeGateError, match="SBOM verifier rejected"):
        adapter.activate_environment("env-1", raw, plan, _decision(raw, plan))
    assert adapter.state.decision_consumed("edge-decision-1") is False


def test_absent_sbom_verifier_preserves_existing_behavior(tmp_path, monkeypatch):
    raw = load_package(PACKAGE)
    plan = build_placement_plan(raw, _host(), "lite", edge_decision_id="edge-decision-1")
    adapter = DockerComposeAdapter(
        COMPOSE, tmp_path, live_enabled=True, package_verifier=lambda p: True
    )  # no sbom_verifier
    monkeypatch.setattr(adapter, "_compose", lambda *a, **k: None)
    result = adapter.activate_environment("env-1", raw, plan, _decision(raw, plan))
    assert result["status"] == "active"
