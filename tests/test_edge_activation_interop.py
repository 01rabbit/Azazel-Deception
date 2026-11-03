"""#55 interop: Edge activation/termination builders -> Deception gates (test-only).

Imports the *actual* Azazel-Edge producer ``py/azazel_edge/deception_activation.py``
from an extracted copy of the pinned Edge commit (``AZAZEL_DECEPTION_EDGE_SRC``),
calls its activation and termination builders with a deterministic TEST-ONLY key,
valid advisory/objective digest refs and Edge-owned evidence/reason, then passes
the signed objects through Deception's existing authenticator and runtime gates
(``build_reference_adapter`` strict posture, ``DockerComposeAdapter``).

Scope and limits
  * Test-only. The key below is a fixed string in this file; it is not a secret
    and no production key path is exercised.
  * Compose is MOCKED: ``subprocess.run`` inside ``azazel_deception.runtime.compose``
    is replaced by a fake that records argv and returns rc=0. No Docker daemon.
  * No production caller and no live authorization is implemented here. Passing
    this test grants no runtime authority; it only proves the wire objects built
    by Edge bind and are accepted by Deception's existing gates.

Gated: runs only when ``AZAZEL_DECEPTION_EDGE_ACTIVATION_INTEROP=1``.
``scripts/dev/edge_activation_interop.sh`` sets this together with the extracted
Edge source. A skip is not a pass (the runner rejects any skip in the report).
"""

from __future__ import annotations

import importlib
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from azazel_deception.package import load_package
from azazel_deception.planner import build_placement_plan
from azazel_deception.runtime import compose as compose_module
from azazel_deception.runtime.mio_feedback import (
    AdmittedObjective,
    accept_mio_objective,
    admit_objective,
    objective_digest,
)
from azazel_deception.runtime.posture import build_reference_adapter
from azazel_deception.runtime.transport import HmacDecisionAuthenticator
from tests._mio_feedback_support import objective_payload

REPO = Path(__file__).resolve().parents[1]
PACKAGE = REPO / "examples/packages/municipal-linux-v1/package.yaml"
COMPOSE = REPO / "runtime/compose/reference-linux.compose.yaml"

ENABLE_ENV = "AZAZEL_DECEPTION_EDGE_ACTIVATION_INTEROP"
EDGE_SRC_ENV = "AZAZEL_DECEPTION_EDGE_SRC"

# TEST-ONLY deterministic key. Not a secret; never used outside this file.
TEST_KEY = "edge55-activation-interop-TEST-ONLY-key"

ENV_ID = "env-edge55-interop"
ACTIVATION_DECISION_ID = "edge-activation-edge55-interop-1"
TERMINATION_DECISION_ID = "edge-termination-edge55-interop-1"
AS_OF = "2026-11-03T12:00:00+00:00"
NOW = datetime(2026, 11, 3, 12, 0, 0, tzinfo=timezone.utc)
TTL_SECONDS = 600

# Edge-owned evidence (non-advisory kinds only) and a short opaque reason code.
EDGE_EVIDENCE = ["edge-evidence:edge55-interop-1"]
ACTIVATION_REASONS = ["edge55-interop"]
TERMINATION_REASON = "edge55-interop-teardown"

BUDGET = {
    "cpu_cores": 2,
    "memory_mb": 1024,
    "storage_mb": 2048,
    "max_connections": 100,
    "max_duration_seconds": 300,
    "bandwidth_kbps": 5000,
}


def _load_edge_builders():
    """Import the real Edge module from the extracted pinned commit, or fail."""

    src = os.environ.get(EDGE_SRC_ENV)
    if not src:
        pytest.fail(f"{EDGE_SRC_ENV} must point at the extracted Edge py/ directory")
    src_path = Path(src).resolve()
    if not (src_path / "azazel_edge" / "deception_activation.py").is_file():
        pytest.fail(f"{EDGE_SRC_ENV} does not contain azazel_edge/deception_activation.py: {src_path}")
    sys.path.insert(0, str(src_path))
    module = importlib.import_module("azazel_edge.deception_activation")
    module_file = Path(module.__file__).resolve()
    assert src_path in module_file.parents, "Edge module must come from the extracted pinned source"
    return module


def _host():
    return {
        "node_id": "edge55-interop-node",
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


def _fake_compose(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """MOCK: replace the docker compose invocation; record argv, return rc=0."""

    calls: list[list[str]] = []

    def _fake_run(command, **kwargs):
        calls.append(list(command))
        return subprocess.CompletedProcess(command, 0, stdout="ok")

    monkeypatch.setattr(compose_module.subprocess, "run", _fake_run)
    return calls


@pytest.mark.skipif(os.environ.get(ENABLE_ENV) != "1", reason=f"set {ENABLE_ENV}=1 (see runner)")
def test_edge_builders_signed_objects_pass_deception_gates(tmp_path, monkeypatch):
    edge = _load_edge_builders()
    raw = load_package(PACKAGE)
    plan = build_placement_plan(raw, _host(), "lite", edge_decision_id=ACTIVATION_DECISION_ID)
    # Deterministic clock for the runtime gates (builders take as_of explicitly).
    monkeypatch.setattr(compose_module, "_utcnow", lambda: NOW)
    calls = _fake_compose(monkeypatch)
    authenticator = HmacDecisionAuthenticator(TEST_KEY)

    # CONTENT binding (not merely shape/ref binding): the refs Edge signs are
    # derived from a real accepted Deception objective and its content digest,
    # exactly as in test_mio_feedback_interop.py. A wrong or substituted digest
    # ref, or an objective whose content differs, must fail admission below.
    objective = accept_mio_objective(objective_payload())
    digest = objective_digest(objective)
    digest_ref = "advisory:mio-objective-digest-" + digest.split(":", 1)[1][:32]
    objective_refs = [*objective.advisory_refs(), digest_ref]

    activation = edge.build_activation_decision(
        package_id=raw["package_id"],
        package_digest=raw["package_digest"],
        target_node_id=plan["node_id"],
        selected_tier=plan["selected_tier"],
        budget=BUDGET,
        as_of=AS_OF,
        ttl_seconds=TTL_SECONDS,
        status="accepted",
        evidence_refs=EDGE_EVIDENCE,
        reason_codes=ACTIVATION_REASONS,
        objective_refs=objective_refs,
        decision_id=ACTIVATION_DECISION_ID,
        key=TEST_KEY,
    )
    termination = edge.build_termination_decision(
        environment_id=ENV_ID,
        reason=TERMINATION_REASON,
        as_of=AS_OF,
        ttl_seconds=TTL_SECONDS,
        evidence_refs=EDGE_EVIDENCE,
        objective_refs=objective_refs,
        decision_id=TERMINATION_DECISION_ID,
        key=TEST_KEY,
    )

    # Binding: Edge's signed records carry the advisory digest/objective refs
    # alongside its own evidence, and the transport signature verifies.
    for ref in objective_refs:
        assert ref in activation["evidence_refs"]
        assert ref in termination["evidence_refs"]
    assert set(EDGE_EVIDENCE) <= set(activation["evidence_refs"])
    assert authenticator(activation) is True
    assert authenticator(termination) is True

    # CONTENT binding through Deception's own admission gate: the Edge-signed
    # activation, with the real objective's refs and digest ref, must admit the
    # exact objective with objective_content_bound True. This is content
    # binding (digest matches the objective), not merely shape or ref binding.
    admitted = admit_objective(objective, activation, authenticator=authenticator, now=NOW)
    assert isinstance(admitted, AdmittedObjective), admitted
    assert admitted.objective == objective
    assert admitted.objective_content_bound is True
    # Fail-closed sanity: a tampered budget no longer verifies.
    tampered = dict(activation, budget=dict(activation["budget"], bandwidth_kbps=5001))
    assert authenticator(tampered) is False

    adapter = build_reference_adapter(
        COMPOSE,
        tmp_path,
        live_enabled=True,
        package_verifier=_accept_all,
        sbom_verifier=lambda _package: True,
        decision_authenticator=authenticator,
    )

    activated = adapter.activate_environment(ENV_ID, raw, plan, activation)
    assert activated["status"] == "active"
    assert adapter.state.decision_consumed(ACTIVATION_DECISION_ID) is True

    terminated = adapter.terminate_environment(ENV_ID, termination)
    assert terminated["status"] == "terminated"
    assert adapter.state.decision_consumed(TERMINATION_DECISION_ID) is True

    # Cleanup: the (mocked) runtime recorded teardown and the state is terminal.
    assert any("down" in argv and "--remove-orphans" in argv for argv in calls), calls
    state = adapter.state.read(ENV_ID)
    assert state["state"] == "terminated"
    assert state["termination_decision_id"] == TERMINATION_DECISION_ID
    assert state["termination_reason"] == TERMINATION_REASON
