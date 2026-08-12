from types import SimpleNamespace

import azazel_deception.capabilities as capabilities


def test_apple_silicon_architecture_maps_to_arm64(monkeypatch):
    monkeypatch.setattr(capabilities.platform, "machine", lambda: "arm64")
    assert capabilities._architecture() == "arm64"


def test_macos_memory_uses_hw_memsize(monkeypatch):
    monkeypatch.setattr(capabilities.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        capabilities.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=str(36 * 1024 * 1024 * 1024),
        ),
    )
    assert capabilities._memory_mb() == 36 * 1024


def test_macos_kvm_is_never_reported(monkeypatch, tmp_path):
    monkeypatch.setattr(capabilities.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(capabilities.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(capabilities.platform, "node", lambda: "az06-mac-test")
    monkeypatch.setattr(capabilities.os, "cpu_count", lambda: 12)
    monkeypatch.setattr(capabilities, "_memory_mb", lambda: 36 * 1024)
    monkeypatch.setattr(capabilities.shutil, "which", lambda command: None)
    monkeypatch.setattr(
        capabilities.shutil,
        "disk_usage",
        lambda root: SimpleNamespace(free=256 * 1024 * 1024 * 1024),
    )

    payload = capabilities.detect_host_capabilities(str(tmp_path))
    assert payload["architecture"] == "arm64"
    assert payload["memory_mb"] == 36 * 1024
    assert payload["kvm_available"] is False
    assert payload["gpu_available"] is False
    assert payload["network_features"]["network_namespace"] is False
    assert payload["network_features"]["nftables"] is False
