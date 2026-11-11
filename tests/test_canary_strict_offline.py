"""Pure strict-lab guards/refusals; no Docker start or crypto-positive claims."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from azazel_deception.package import load_package, parse_package
from azazel_deception.runtime.compose import DockerComposeAdapter, RuntimeGateError
from azazel_deception.runtime.offline_package_verifier import OfflineGitHubAttestationPackageVerifier
from azazel_deception.runtime.offline_sbom_verifier import OfflineGitHubSbomVerifier
from azazel_deception.runtime.transport import HmacDecisionAuthenticator, sign_decision
from tests import _canary_strict_offline as strict
from tests.test_strict_live_posture import COMPOSE, KEY, PACKAGE, _decision, _plan


def material_environment():
    return dict(AZ06_CANARY_STRICT_OFFLINE="1", AZ06_OFFLINE_GH_PATH="/opt/missing/gh",
                AZ06_OFFLINE_GH_SHA256="0" * 64, AZ06_OFFLINE_BUNDLE_PATH="/opt/missing/package.bundle",
                AZ06_OFFLINE_ROOT_PATH="/opt/missing/root", AZ06_OFFLINE_ROOT_SHA256="0" * 64,
                AZ06_OFFLINE_TEMP_PARENT="/opt/missing/workspace", AZ06_OFFLINE_SPDX_MAP="/opt/missing/map")


def image_map():
    image = load_package(PACKAGE)["components"][0]["image"]["image"]
    return {image: dict(index_path="/opt/missing/index", bundle_path="/opt/missing/spdx.bundle",
                       artifacts={"sha256:" + str(i) * 64: "/opt/missing/artifact-" + str(i) for i in range(4)})}


def test_strict_flag_never_silently_falls_back():
    assert strict.strict_mode_requested({}) is False
    assert strict.strict_mode_requested({strict.FLAG: "0"}) is False
    assert strict.strict_mode_requested({strict.FLAG: "1"}) is True
    for value in ("true", "yes", "2", None):
        with pytest.raises(ValueError, match="explicitly"):
            strict.strict_mode_requested({strict.FLAG: value})


def test_missing_configuration_refuses_without_any_cli_or_docker(monkeypatch):
    monkeypatch.setattr(strict, "_command", lambda *args: pytest.fail("no commands on missing configuration"))
    for key in strict.ENV_FIELDS:
        env = material_environment()
        env.pop(key)
        with pytest.raises(ValueError, match="incomplete"):
            strict.offline_callbacks(env)


def test_marker_guard_refuses_before_host_commands(tmp_path, monkeypatch):
    monkeypatch.setattr(strict.platform, "system", lambda: "Linux")
    monkeypatch.setattr(strict.os, "geteuid", lambda: 0)
    monkeypatch.setattr(strict, "_read_protected", lambda *args: b"wrong marker\n")
    monkeypatch.setattr(strict, "_command", lambda *args: pytest.fail("marker must refuse before commands"))
    with pytest.raises(ValueError, match="marker"):
        strict.lab_guard(tmp_path)


def test_protected_artifact_map_is_read_fail_closed(monkeypatch):
    def denied(*args):
        raise OSError("synthetic unsafe map path")
    monkeypatch.setattr(strict, "_read_protected", denied)
    with pytest.raises(OSError): strict.offline_callbacks(material_environment())


def test_real_missing_package_callback_refuses_before_host_planning(monkeypatch, tmp_path):
    monkeypatch.setattr(strict, "lab_guard", lambda *args: None)  # unit-only VM boundary stub
    monkeypatch.setattr(strict, "_read_protected", lambda *args: json.dumps(image_map()).encode())
    monkeypatch.setattr(strict, "measured_host", lambda *args: pytest.fail("no host planning after real callback refusal"))
    package = parse_package(load_package(PACKAGE))
    package_callback, sbom_callback = strict.offline_callbacks(material_environment())
    assert isinstance(package_callback, OfflineGitHubAttestationPackageVerifier)
    assert isinstance(sbom_callback, OfflineGitHubSbomVerifier)
    # Actual callbacks read missing material and return false; no mock crypto success.
    assert package_callback(package) is False and sbom_callback(package) is False
    with pytest.raises(ValueError, match="package authentication refused"):
        strict.strict_preflight(package, tmp_path, material_environment())


def test_spdx_refusal_never_reaches_host_or_fixture_fallback(monkeypatch, tmp_path):
    monkeypatch.setattr(strict, "lab_guard", lambda *args: None)
    # Deliberately stub only control flow; this is not package authentication evidence.
    calls = []
    def package(_): calls.append("package-stub"); return True
    def spdx(_): calls.append("spdx-refused"); return False
    monkeypatch.setattr(strict, "offline_callbacks", lambda *args: (package, spdx))
    monkeypatch.setattr(strict, "measured_host", lambda *args: pytest.fail("SPDX refusal must stop"))
    with pytest.raises(ValueError, match="SPDX/platform authentication refused"):
        strict.strict_preflight(object(), tmp_path, material_environment())
    assert calls == ["package-stub", "spdx-refused"]


def test_missing_real_material_cannot_consume_decision_or_start_compose(tmp_path, monkeypatch):
    monkeypatch.setattr(strict, "_read_protected", lambda *args: json.dumps(image_map()).encode())
    package_callback, sbom_callback = strict.offline_callbacks(material_environment())
    adapter = DockerComposeAdapter(COMPOSE, tmp_path / "state", live_enabled=True,
        package_verifier=package_callback, sbom_verifier=sbom_callback,
        decision_authenticator=HmacDecisionAuthenticator(KEY),
        require_authenticated_decisions=True, require_sbom_verification=True)
    monkeypatch.setattr(adapter, "_compose", lambda *args: pytest.fail("must not bind/start"))
    raw = load_package(PACKAGE)
    plan = _plan(raw)
    signed = sign_decision(_decision(raw, plan), KEY)
    with pytest.raises(RuntimeGateError): adapter.activate_environment("strict-refused", raw, plan, signed)
    assert adapter.state.decision_consumed("edge-decision-1") is False
    assert adapter.state.read("strict-refused") is None


@pytest.mark.parametrize("environment", [{"DOCKER_HOST": "tcp://remote:2375"}, {"DOCKER_CONTEXT": "remote"}])
def test_remote_daemon_refused_before_any_command(monkeypatch, environment):
    monkeypatch.setattr(strict, "_command", lambda *args: pytest.fail("no remote daemon connection"))
    with pytest.raises(ValueError, match="must be local"): strict.measured_host(environment)


@pytest.mark.parametrize("machine,architecture", [("aarch64", "arm64"), ("x86_64", "amd64")])
def test_host_plan_uses_actual_daemon_platform_resources_and_local_disk(monkeypatch, machine, architecture):
    info = dict(OSType="linux", Architecture=machine, KernelVersion="actual-test-kernel", NCPU=3,
                MemTotal=6 * 1024**3, DockerRootDir="/var/lib/docker", ID="actual-test-daemon-id")
    def command(*args):
        if args[:3] == ("docker", "context", "show"): return b"default\n"
        if args[:3] == ("docker", "context", "inspect"): return b'"unix:///var/run/docker.sock"\n'
        return json.dumps(info).encode()
    monkeypatch.setattr(strict, "_command", command)
    monkeypatch.setattr(strict.platform, "machine", lambda: machine)
    monkeypatch.setattr(strict.platform, "release", lambda: "actual-test-kernel")
    monkeypatch.setattr(strict, "_protected_directory", lambda path: path)
    monkeypatch.setattr(strict.shutil, "disk_usage", lambda path: SimpleNamespace(free=8 * 1024**3))
    host, measured = strict.measured_host({})
    assert host["architecture"] == architecture and host["cpu_cores"] == 3
    assert host["memory_mb"] == 6144 and host["storage_free_mb"] == 8192
    assert measured["controller_platform"] == measured["daemon_platform"] == architecture
    assert measured["daemon_cpu_cores"] == 3 and measured["local_storage_free_mb"] == 8192


@pytest.mark.parametrize("key", ["AZ06_OFFLINE_GH_SHA256", "AZ06_OFFLINE_ROOT_SHA256"])
def test_missing_independent_pin_format_refuses_before_map_or_process(monkeypatch, key):
    env = material_environment()
    env[key] = "not-an-independent-sha256"
    monkeypatch.setattr(strict, "_read_protected", lambda *args: pytest.fail("pins must refuse before artifact read"))
    with pytest.raises(ValueError, match="fingerprints"):
        strict.offline_callbacks(env)


def test_strict_collection_never_probes_docker_before_guards(monkeypatch):
    import importlib.util
    import subprocess
    monkeypatch.setenv("AZ06_CANARY_STRICT_OFFLINE", "1")
    monkeypatch.setenv("AZAZEL_DECEPTION_DOCKER_TESTS", "1")
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: pytest.fail("strict collection must not launch commands"))
    spec = importlib.util.spec_from_file_location("strict_canary_collection_unit_only", Path(__file__).with_name("test_canary_docker.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.strict_mode_requested() is True
