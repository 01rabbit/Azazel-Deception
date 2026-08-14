"""Strict posture is the enforced default for the reference live deployment.

Covers the AZ-06 live-gate item: every reference-deployment construction site
(``build_reference_adapter``, the ``runtime-status``/``runtime-reconcile`` CLI
commands, and the virtual Phase-1 lab's ``main()``) must default to the strict
posture (SBOM verification + authenticated decisions both required), with a
single explicit dev-only opt-out (``--dev-relaxed-posture`` /
``AZAZEL_DECEPTION_RELAXED_POSTURE=1``). ``DockerComposeAdapter`` itself keeps
its permissive class defaults so explicit test construction is unaffected.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from azazel_deception.cli import main as cli_main
from azazel_deception.package import load_package
from azazel_deception.planner import build_placement_plan
from azazel_deception.runtime.compose import DockerComposeAdapter, RuntimeGateError
from azazel_deception.runtime.posture import (
    DEV_RELAXED_POSTURE_ENV_VAR,
    build_reference_adapter,
    dev_relaxed_posture_requested,
)
from azazel_deception.runtime.transport import HmacDecisionAuthenticator, sign_decision

PACKAGE = Path("examples/packages/municipal-linux-v1/package.yaml")
COMPOSE = Path("runtime/compose/reference-linux.compose.yaml")
LAB_PATH = Path("scripts/dev/virtual_phase1_lab.py")
KEY = "reference-posture-test-key"


def _load_lab():
    spec = importlib.util.spec_from_file_location("virtual_phase1_lab_posture", LAB_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


def _accept_all(_package):
    return True


def _plan(raw):
    return build_placement_plan(raw, _host(), "lite", edge_decision_id="edge-decision-1")


def _activation_decision(raw, plan):
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


def _termination_decision(environment_id="env-1", decision_id="edge-terminate-1"):
    now = datetime.now(timezone.utc)
    return {
        "schema_version": "environment-termination-decision/v0.1",
        "decision_id": decision_id,
        "decision_authority": "azazel-edge",
        "environment_id": environment_id,
        "reason": "test-teardown",
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=1)).isoformat(),
        "evidence_refs": [],
    }


def _fake_compose_run(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub the real ``docker compose`` invocation used by DockerComposeAdapter._compose.

    Patches subprocess.run inside the compose module only, so tests exercising
    full CLI/lab entry points never need a real Docker daemon.
    """

    def _fake_run(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, stdout="ok")

    monkeypatch.setattr("azazel_deception.runtime.compose.subprocess.run", _fake_run)


# -- posture resolution -------------------------------------------------------


def test_relaxed_posture_not_requested_by_default(monkeypatch):
    monkeypatch.delenv(DEV_RELAXED_POSTURE_ENV_VAR, raising=False)
    assert dev_relaxed_posture_requested() is False


def test_env_var_requests_relaxed_posture(monkeypatch):
    monkeypatch.setenv(DEV_RELAXED_POSTURE_ENV_VAR, "1")
    assert dev_relaxed_posture_requested() is True


def test_explicit_argument_overrides_env_var(monkeypatch):
    monkeypatch.setenv(DEV_RELAXED_POSTURE_ENV_VAR, "1")
    assert dev_relaxed_posture_requested(False) is False
    monkeypatch.delenv(DEV_RELAXED_POSTURE_ENV_VAR, raising=False)
    assert dev_relaxed_posture_requested(True) is True


# -- build_reference_adapter ---------------------------------------------------


def test_reference_adapter_is_strict_by_default(tmp_path):
    adapter = build_reference_adapter(COMPOSE, tmp_path)
    assert adapter.require_sbom_verification is True
    assert adapter.require_authenticated_decisions is True


def test_class_default_stays_permissive(tmp_path):
    # The factory must not change DockerComposeAdapter's own defaults: explicit
    # test/library construction stays permissive without going through it.
    adapter = DockerComposeAdapter(COMPOSE, tmp_path)
    assert adapter.require_sbom_verification is False
    assert adapter.require_authenticated_decisions is False


def test_reference_adapter_env_var_opts_out(tmp_path, monkeypatch):
    monkeypatch.setenv(DEV_RELAXED_POSTURE_ENV_VAR, "1")
    adapter = build_reference_adapter(COMPOSE, tmp_path)
    assert adapter.require_sbom_verification is False
    assert adapter.require_authenticated_decisions is False


def test_reference_adapter_explicit_flag_opts_out(tmp_path, monkeypatch):
    monkeypatch.delenv(DEV_RELAXED_POSTURE_ENV_VAR, raising=False)
    adapter = build_reference_adapter(COMPOSE, tmp_path, dev_relaxed_posture=True)
    assert adapter.require_sbom_verification is False
    assert adapter.require_authenticated_decisions is False


def test_reference_adapter_strict_activation_fails_closed_without_gates(tmp_path):
    raw = load_package(PACKAGE)
    plan = _plan(raw)
    adapter = build_reference_adapter(
        COMPOSE,
        tmp_path,
        live_enabled=True,
        package_verifier=_accept_all,
    )
    with pytest.raises(RuntimeGateError, match="authenticated Edge decision required"):
        adapter.activate_environment("env-1", raw, plan, _activation_decision(raw, plan))
    assert adapter.state.decision_consumed("edge-decision-1") is False


def test_reference_adapter_strict_termination_fails_closed_without_gates(tmp_path):
    adapter = build_reference_adapter(
        COMPOSE,
        tmp_path,
        live_enabled=True,
        package_verifier=_accept_all,
    )
    with pytest.raises(RuntimeGateError, match="authenticated Edge decision required"):
        adapter.terminate_environment("env-1", _termination_decision())


def test_reference_adapter_feature_disabled_activation_unaffected_by_strict_posture(tmp_path):
    # Strict posture is still the default even with live_enabled=False, but the
    # feature-disabled short-circuit must be unchanged: no gate should fire.
    raw = load_package(PACKAGE)
    plan = _plan(raw)
    adapter = build_reference_adapter(COMPOSE, tmp_path, live_enabled=False)
    result = adapter.activate_environment("env-1", raw, plan, _activation_decision(raw, plan))
    assert result["status"] == "disabled"
    assert result["live_execution"] is False


def test_reference_adapter_strict_succeeds_when_all_gates_configured(tmp_path, monkeypatch):
    raw = load_package(PACKAGE)
    plan = _plan(raw)
    adapter = build_reference_adapter(
        COMPOSE,
        tmp_path,
        live_enabled=True,
        package_verifier=_accept_all,
        sbom_verifier=lambda p: True,
        decision_authenticator=HmacDecisionAuthenticator(KEY),
    )
    assert adapter.require_sbom_verification is True
    assert adapter.require_authenticated_decisions is True
    monkeypatch.setattr(adapter, "_compose", lambda *a, **k: None)
    signed = sign_decision(_activation_decision(raw, plan), KEY)
    result = adapter.activate_environment("env-1", raw, plan, signed)
    assert result["status"] == "active"


# -- CLI: runtime-status / runtime-reconcile -----------------------------------


def test_cli_runtime_status_is_strict_by_default(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv(DEV_RELAXED_POSTURE_ENV_VAR, raising=False)
    rc = cli_main(
        ["runtime-status", "--state-root", str(tmp_path), "--compose", str(COMPOSE)]
    )
    assert rc == 0
    health = json.loads(capsys.readouterr().out)
    assert health["require_sbom_verification"] is True
    assert health["require_authenticated_decisions"] is True
    assert health["live_enabled"] is False


def test_cli_runtime_status_dev_relaxed_flag_opts_out(tmp_path, capsys):
    rc = cli_main(
        [
            "runtime-status",
            "--state-root",
            str(tmp_path),
            "--compose",
            str(COMPOSE),
            "--dev-relaxed-posture",
        ]
    )
    assert rc == 0
    health = json.loads(capsys.readouterr().out)
    assert health["require_sbom_verification"] is False
    assert health["require_authenticated_decisions"] is False


def test_cli_runtime_status_env_var_opts_out(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv(DEV_RELAXED_POSTURE_ENV_VAR, "1")
    rc = cli_main(
        ["runtime-status", "--state-root", str(tmp_path), "--compose", str(COMPOSE)]
    )
    assert rc == 0
    health = json.loads(capsys.readouterr().out)
    assert health["require_sbom_verification"] is False
    assert health["require_authenticated_decisions"] is False


def test_cli_runtime_reconcile_strict_by_default_still_runs(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv(DEV_RELAXED_POSTURE_ENV_VAR, raising=False)
    rc = cli_main(
        ["runtime-reconcile", "--state-root", str(tmp_path), "--compose", str(COMPOSE)]
    )
    assert rc == 0
    divergence = json.loads(capsys.readouterr().out)
    assert divergence["authority"] == "descriptive_only"
    assert divergence["consistent"] is True


# -- virtual Phase-1 lab --------------------------------------------------------


def test_lab_main_fails_closed_by_default_without_gates(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv(DEV_RELAXED_POSTURE_ENV_VAR, raising=False)
    lab = _load_lab()
    rc = lab.main(
        [
            "--simulated-verification",
            "--state-root",
            str(tmp_path / "state"),
            "--run-id",
            "default-strict",
        ]
    )
    assert rc == 2
    err = capsys.readouterr().err
    assert "fail-closed" in err
    assert "authenticated Edge decision required" in err


def test_lab_main_relaxed_posture_flag_completes_offline(tmp_path, capsys, monkeypatch):
    _fake_compose_run(monkeypatch)
    lab = _load_lab()
    rc = lab.main(
        [
            "--simulated-verification",
            "--dev-relaxed-posture",
            "--state-root",
            str(tmp_path / "state"),
            "--run-id",
            "relaxed",
        ]
    )
    assert rc == 0
    report = json.loads(capsys.readouterr().out)
    assert report["lifecycle"]["activate"]["status"] == "active"
    assert report["lifecycle"]["terminate"]["status"] == "terminated"


def test_lab_main_env_var_relaxes_posture_offline(tmp_path, capsys, monkeypatch):
    _fake_compose_run(monkeypatch)
    monkeypatch.setenv(DEV_RELAXED_POSTURE_ENV_VAR, "1")
    lab = _load_lab()
    rc = lab.main(
        [
            "--simulated-verification",
            "--state-root",
            str(tmp_path / "state"),
            "--run-id",
            "relaxed-env",
        ]
    )
    assert rc == 0
    report = json.loads(capsys.readouterr().out)
    assert report["lifecycle"]["activate"]["status"] == "active"


def test_lab_main_strict_with_authenticate_still_requires_sbom(tmp_path, capsys, monkeypatch):
    # Strict posture requires BOTH gates; configuring only one still fails closed.
    monkeypatch.delenv(DEV_RELAXED_POSTURE_ENV_VAR, raising=False)
    lab = _load_lab()
    rc = lab.main(
        [
            "--simulated-verification",
            "--authenticate",
            "--state-root",
            str(tmp_path / "state"),
            "--run-id",
            "half-strict",
        ]
    )
    assert rc == 2
    err = capsys.readouterr().err
    assert "SBOM verification required" in err
