"""CI-safe unit test for the Virtual Phase-1 Lab driver.

Docker is stubbed (``_compose`` monkeypatched), so this exercises the lab's
lifecycle orchestration, gate ordering, evidence assertions, and deterministic
reset without needing a real container runtime or network. A real-container run
is driven separately by ``make virtual-lab``.
"""

import importlib.util
from pathlib import Path

import pytest

from azazel_deception.package import load_package
from azazel_deception.runtime.compose import DockerComposeAdapter, RuntimeGateError

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "examples/packages/municipal-linux-v1/package.yaml"
COMPOSE = ROOT / "runtime/compose/reference-linux.compose.yaml"
LAB_PATH = ROOT / "scripts/dev/virtual_phase1_lab.py"


def _load_lab():
    spec = importlib.util.spec_from_file_location("virtual_phase1_lab", LAB_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _host():
    return {
        "node_id": "az06-lab-node",
        "architecture": "amd64",
        "cpu_cores": 4,
        "memory_mb": 8192,
        "storage_free_mb": 65536,
        "runtime_adapters": {"docker_compose": True},
        "kvm_available": False,
        "gpu_available": False,
    }


def test_virtual_lab_completes_full_lifecycle(tmp_path, monkeypatch):
    lab = _load_lab()
    adapter = DockerComposeAdapter(
        COMPOSE,
        tmp_path / "state",
        live_enabled=True,
        package_verifier=lab._simulated_verifier,
    )
    # Stub the real Docker invocation; assert it is actually driven.
    calls = []
    monkeypatch.setattr(adapter, "_compose", lambda *a, **k: calls.append(a))

    report = lab.run_virtual_lab(adapter, load_package(PACKAGE), _host())

    assert report["component_ids"] == ["intranet-web"]
    assert report["evidence_event_types"] == ["activated", "terminated", "reset_completed"]
    assert report["lifecycle"]["activate"]["status"] == "active"
    assert report["lifecycle"]["terminate"]["status"] == "terminated"
    assert report["lifecycle"]["reset"]["status"] == "reset"
    assert report["lifecycle"]["reset"]["evidence_preserved"] is True
    # Both synthetic decisions were consumed one-shot.
    assert report["decision_consumed"][lab.ACTIVATION_DECISION_ID] is True
    assert report["decision_consumed"][lab.TERMINATION_DECISION_ID] is True
    # Docker up + down were invoked.
    assert any("up" in a for a in calls)
    assert any("down" in a for a in calls)
    # Runtime state cleared after reset.
    assert adapter.state.read("az06-lab-env") is None


def test_virtual_lab_fails_closed_without_verifier(tmp_path):
    lab = _load_lab()
    # No package_verifier configured -> trusted-verifier gate must reject.
    adapter = DockerComposeAdapter(COMPOSE, tmp_path / "state", live_enabled=True)
    with pytest.raises(RuntimeGateError, match="trusted package verifier is not configured"):
        lab.run_virtual_lab(adapter, load_package(PACKAGE), _host())


def test_virtual_lab_does_not_change_live_default(tmp_path):
    # The lab must not flip any global default: a plain adapter stays disabled.
    default_adapter = DockerComposeAdapter(COMPOSE, tmp_path / "state2")
    assert default_adapter.live_enabled is False


def test_simulated_verifier_is_not_exported_by_the_package():
    # The dev-only accept function must live only in the script, never in the
    # shippable package (guards against test-only behavior leaking to prod).
    import azazel_deception.runtime.verifier as prod_verifier

    assert not hasattr(prod_verifier, "_simulated_verifier")
