"""Opt-in actual nginx canary plumbing; fixture admission is NOT production trust.

Prestage the pinned reference image before setting AZAZEL_DECEPTION_DOCKER_TESTS=1.
No pulls, host ports, external requests, production keys or product changes.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from azazel_fabric.deception_contracts import PlacementPlan
from azazel_fabric.deception_integrity import canonical_package_signing_bytes
from azazel_deception.credentials.canaries import CanaryRegistry, CanaryScope, record_canary_touch, synthetic_openapi
from azazel_deception.package import load_package, parse_package
from azazel_deception.planner import build_placement_plan
from azazel_deception.runtime.compose import DockerComposeAdapter
from azazel_deception.runtime.observation_export import export_observations
from azazel_deception.runtime.transport import HmacDecisionAuthenticator, sign_decision
from tests.test_docker_integration import (
    COMPOSE, PACKAGE, _docker_available, _inspect, _project_containers, _single_container_id,
)
from tests.test_runtime import _decision, _host, _termination

pytestmark = pytest.mark.skipif(
    os.environ.get("AZAZEL_DECEPTION_DOCKER_TESTS") != "1" or not _docker_available(),
    reason="requires explicit Docker opt-in and a reachable daemon",
)
PACKAGE_SHA256 = "baca710857669a1901afaf18f32c44f7b0d18a913c11dad6030a40aa8785de53"
IMAGE = "ghcr.io/01rabbit/azazel-deception-reference-web@sha256:c187c4ce32a244a45848bceee7ce9aa5c0146bd42e5dc0e03844e56083e2a043"


def _require(condition, message):
    # Do not let assertion introspection dump a token-bearing HTTP document.
    if not condition:
        pytest.fail(message, pytrace=False)


def _run(*args, input=None, timeout=15):
    return subprocess.run(["docker", *args], input=input, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=timeout, check=False)


def _fixture_pin(package):
    """Exact checked-in fixture bytes only; NOT GitHub/SBOM authentication."""
    return (package.package_digest == "sha256:" + PACKAGE_SHA256
            and hashlib.sha256(canonical_package_signing_bytes(package)).hexdigest() == PACKAGE_SHA256
            and package.components[0].image.image == IMAGE)


def _http(container, path):
    # Secret path goes over stdin, never into host argv, exception or report.
    result = _run("exec", "-i", "-e", "http_proxy=", "-e", "HTTP_PROXY=",
                  "-e", "https_proxy=", "-e", "HTTPS_PROXY=", "-e", "ALL_PROXY=",
                  "-e", "all_proxy=", container, "sh", "-c",
                  'IFS= read -r path; exec wget -S -O - "http://127.0.0.1:8080$path"',
                  input=(path + "\n").encode())
    statuses = re.findall(rb"HTTP/1\.[01] ([0-9]{3})", result.stderr)
    return int(statuses[-1]) if statuses else None, result.stdout


def _networks(project):
    result = _run("network", "ls", "--filter", f"label=com.docker.compose.project={project}", "-q")
    _require(result.returncode == 0, "network teardown readback unavailable")
    return result.stdout.split()


def test_real_nginx_canary_presentation_expiry_and_reset(tmp_path):
    raw = load_package(PACKAGE)
    package = parse_package(raw)
    _require(_fixture_pin(package), "checked-in lab package fixture changed; review required")
    image = _run("image", "inspect", IMAGE)
    _require(image.returncode == 0, "pinned reference image must be prestaged; this test never pulls")
    environment = "canary-lab-" + uuid.uuid4().hex[:10]
    decision_id = "fixture-" + uuid.uuid4().hex
    key = os.urandom(32)  # per-run synthetic lab signer, no real Edge authority
    plan = build_placement_plan(raw, _host(), "lite", edge_decision_id=decision_id)
    scope = CanaryScope(package.package_id, PACKAGE_SHA256, environment, "fixture-boot",
                        decision_id, "intranet-web-http")
    registry = CanaryRegistry(scope)
    now = lambda: datetime.now(timezone.utc).isoformat()
    issued = registry.issue(issued_at=now(), ttl_seconds=30)
    document = synthetic_openapi(issued).encode()
    marker_body = b'{"synthetic_marker":true}\n'
    # Private host parent; bind only its readable leaf into the nonroot decoy.
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    web = private / "web"
    web.mkdir(mode=0o755)
    (web / "openapi.json").write_bytes(document)
    markers = web / "__azazel_canary__"
    markers.mkdir(mode=0o755)
    marker = markers / issued.token
    try:
        marker.write_bytes(marker_body)
    except OSError:
        pytest.fail("private canary marker creation failed", pytrace=False)
    for path in (web / "openapi.json", marker):
        try:
            path.chmod(0o644)
        except OSError:
            pytest.fail("private canary artifact permissions failed", pytrace=False)
    config = private / "nginx.conf"
    config.write_text(Path("runtime/compose/nginx.conf").read_text().replace("access_log /dev/stdout;", "access_log off;"))
    config.chmod(0o644)
    composed = yaml.safe_load(COMPOSE.read_text())
    service = composed["services"]["intranet-web"]
    service["pull_policy"] = "never"
    service["volumes"] = [
        {"type": "bind", "source": str(web), "target": "/usr/share/nginx/html", "read_only": True},
        {"type": "bind", "source": str(config), "target": "/etc/nginx/nginx.conf", "read_only": True},
    ]
    compose = private / "canary.compose.yaml"
    compose.write_text(yaml.safe_dump(composed))
    adapter = DockerComposeAdapter(
        compose, tmp_path / "state", live_enabled=True,
        package_verifier=_fixture_pin, sbom_verifier=_fixture_pin,
        decision_authenticator=HmacDecisionAuthenticator(key),
        require_authenticated_decisions=True, require_sbom_verification=True,
    )
    project = adapter._project_name(environment)
    try:
        signed = sign_decision(_decision(raw, plan, decision_id=decision_id), key)
        activation = adapter.activate_environment(environment, raw, plan, signed)
        _require(activation["status"] == "active", "lab activation did not complete")
        container = _single_container_id(adapter, environment)
        inspected = _inspect(container)
        host = inspected["HostConfig"]
        _require(inspected["State"]["Running"] is True, "container is not running")
        _require(host["ReadonlyRootfs"] and not host["Privileged"] and host["CapDrop"] == ["ALL"]
                 and not host.get("CapAdd") and "no-new-privileges:true" in host["SecurityOpt"],
                 "actual container hardening readback differs")
        _require(not host.get("PortBindings") and host["NetworkMode"] != "host"
                 and all(value is None for value in inspected["NetworkSettings"]["Ports"].values()),
                 "unexpected published port or host networking")
        _require(host["Memory"] == 256 * 1024 * 1024 and host["NanoCpus"] == 500_000_000
                 and host["PidsLimit"] == 128 and inspected["Config"]["User"] == "101:101",
                 "actual resource/user readback differs")
        networks = inspected["NetworkSettings"]["Networks"]
        _require(set(networks) == {project + "_decoy_internal"}, "unexpected network attachment")
        network = _run("network", "inspect", project + "_decoy_internal")
        _require(network.returncode == 0 and json.loads(network.stdout)[0]["Internal"] is True,
                 "actual network is not internal")
        mounts = {item["Destination"]: item for item in inspected["Mounts"]}
        _require(all(mounts[path]["RW"] is False for path in ("/usr/share/nginx/html", "/etc/nginx/nginx.conf")),
                 "canary/config mount became writable")
        deadline = time.monotonic() + 10
        while True:
            status, body = _http(container, "/openapi.json")
            if status == 200:
                break
            _require(time.monotonic() < deadline, "actual nginx readiness timed out")
            time.sleep(.1)
        _require(body == document, "actual HTTP presentation bytes differ")
        registry.present(issued.lure_id, scope=scope, evidence_ref="presentation:nginx", as_of=now())
        status, body = _http(container, issued.local_path())
        _require(status == 200 and body == marker_body, "actual HTTP marker status/body differs")
        observer = adapter.make_observer(environment, package, PlacementPlan.model_validate(plan))
        result = record_canary_touch(observer, registry, issued.token, scope=scope,
                                    event_id="nginx-touch", evidence_ref="interaction:nginx", as_of=now())
        _require(result["accepted"], "bounded nginx touch was not recorded")
        observations = export_observations(adapter.state, environment)
        _require(len(observations) == 1, "expected one canonical interaction export")
        _require(issued.token not in adapter.state.read_evidence_snapshot(environment), "token leaked into evidence")
        # Real clock expiry AND physical removal: a registry-only rejection is insufficient.
        expiration = datetime.fromisoformat(issued.expires_at)
        while datetime.now(timezone.utc) < expiration:
            time.sleep(.1)
        try:
            marker.unlink()
        except OSError:
            pytest.fail("expired marker removal failed", pytrace=False)
        _require(_http(container, issued.local_path())[0] == 404, "expired marker remains HTTP-readable")
        _require(not registry.touch(issued.token, scope=scope, event_id="expired", evidence_ref="expired:nginx", as_of=now())["accepted"],
                 "expired token was accepted")
        logs = _run("logs", container)
        _require(logs.returncode == 0 and issued.token.encode() not in logs.stdout + logs.stderr,
                 "token leaked into actual container logs")
        term = _termination(decision_id + "-termination")
        term["environment_id"] = environment
        adapter.terminate_environment(environment, sign_decision(term, key))
        _require(_project_containers(adapter, environment) == [] and _networks(project) == [],
                 "terminated container/network remains")
        registry.reset(as_of=now())
        adapter.reset_environment(environment)
        _require(not registry.touch(issued.token, scope=scope, event_id="reset", evidence_ref="reset:nginx", as_of=now())["accepted"],
                 "reset token was accepted")
        _require(not CanaryRegistry(scope).touch(issued.token, scope=scope, event_id="fresh", evidence_ref="fresh:nginx", as_of=now())["accepted"],
                 "replacement registry accepted old token")
        _require(adapter.verify_evidence(environment) and export_observations(adapter.state, environment) == observations,
                 "reset failed to preserve canonical evidence")
        _require(adapter.collect_status(environment)["state"] == "absent", "runtime state remains after reset")
        # Safe, explicit scope report; no token/document/path/log is serialized.
        (tmp_path / "canary-result.json").write_text(json.dumps({
            "production_admission": False, "admission": "exact_fixture_pin_and_synthetic_HMAC",
            "scope": "local_container_static_canary_plumbing_only", "hardware_acceptance": False,
            "presentation_http": 200, "touch_http": 200, "expiry_http": 404,
            "observations": len(observations), "teardown_readback": True,
        }, sort_keys=True))
    finally:
        # Also cover assertion/HTTP/export/termination failures; never trust only local state.
        _run("compose", "-f", str(compose), "-p", project, "down", "--remove-orphans", timeout=60)
        _require(_project_containers(adapter, environment) == [] and _networks(project) == [],
                 "FAILURE CLEANUP INCOMPLETE: lab container/network still present")
        try:
            marker.unlink(missing_ok=True)
        except OSError:
            pytest.fail("private marker cleanup failed", pytrace=False)
        (web / "openapi.json").unlink(missing_ok=True)


def test_canary_evidence_failure_still_removes_actual_container_and_network(tmp_path, monkeypatch):
    class InjectedEvidenceFailure(OSError):
        pass

    def unavailable(*args, **kwargs):
        raise InjectedEvidenceFailure("injected evidence failure; no receipt")

    monkeypatch.setattr(__name__ + ".record_canary_touch", unavailable)
    # Injection occurs only after actual container inspect and both HTTP reads;
    # the lifecycle function's finally independently inspects real teardown.
    with pytest.raises(InjectedEvidenceFailure):
        test_real_nginx_canary_presentation_expiry_and_reset(tmp_path)
    _require(not (tmp_path / "canary-result.json").exists(), "failed run wrote a successful result")
    _require(not (tmp_path / "private/web/openapi.json").exists(), "failed run retained secret document")
    _require(not list((tmp_path / "private/web/__azazel_canary__").iterdir()), "failed run retained marker")
