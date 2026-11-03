"""#55 real-container lifecycle for the MIO feedback chain (Docker, opt-in).

Same opt-in as tests/test_docker_integration.py: AZAZEL_DECEPTION_DOCKER_TESTS=1
and a reachable daemon. Written but NOT run by the test team: the shared
colima is reserved by the team leader (suite-lock).

Proves with real containers what test_mio_feedback.py proves with `_compose`
replaced: objective -> signed decision -> real activation -> bound observation
-> bundle -> verify -> real terminate -> reset, with the container actually
gone and the chain's reset refusal in force afterwards.
"""

from __future__ import annotations

import os
import subprocess
import uuid
from datetime import timedelta

import pytest

from azazel_deception.package import calculate_package_digest, load_package
from azazel_deception.planner import build_placement_plan
from azazel_deception.runtime.compose import DockerComposeAdapter
from azazel_deception.runtime.effect_projection import accept_defensive_effect_ref
from azazel_deception.runtime.mio_feedback import (
    BindingRefused,
    PresentedTerrainRef,
    accept_mio_objective,
    admit_objective,
    bind_reference_chain,
    bound_observer,
    build_feedback_bundle,
    reset_feedback,
    verify_feedback_bundle,
)
from azazel_deception.runtime.presented_terrain import ProducerRedirectionEvidence
from azazel_deception.runtime.transport import HmacDecisionAuthenticator, sign_decision

from tests._mio_feedback_support import (
    COMPOSE,
    PACKAGE,
    SURFACE,
    TEST_KEY,
    edge_effect_payload,
    objective_payload,
    utcnow,
)
from tests.test_docker_integration import _docker_available, _project_containers
from tests.test_runtime import _decision, _host, _termination

pytestmark = pytest.mark.skipif(
    os.environ.get("AZAZEL_DECEPTION_DOCKER_TESTS") != "1" or not _docker_available(),
    reason="requires AZAZEL_DECEPTION_DOCKER_TESTS=1 and a reachable Docker daemon",
)

EXPECTED = ("interaction_log", "process_events")


def _package() -> dict:
    package = load_package(PACKAGE)
    for component in package["components"]:
        component["image"]["verified"] = component["component_id"] == "intranet-web"
    package["package_digest"] = calculate_package_digest(package)
    return package


def test_real_container_lifecycle_keeps_the_reference_chain(tmp_path):
    adapter = DockerComposeAdapter(
        COMPOSE, tmp_path, live_enabled=True,
        package_verifier=lambda package: True,
        decision_authenticator=HmacDecisionAuthenticator(TEST_KEY),
        require_authenticated_decisions=True,
    )
    environment_id = f"it-{uuid.uuid4().hex[:12]}"
    decision_id = f"edge-activate-{environment_id}"
    package = _package()
    plan = build_placement_plan(package, _host(), "lite", edge_decision_id=decision_id)
    decision = _decision(package, plan, decision_id=decision_id)
    objective = accept_mio_objective(objective_payload())
    decision["evidence_refs"] = [objective.objective_ref, *objective.hypothesis_refs, objective.frame_ref]
    signed = sign_decision(decision, TEST_KEY)
    try:
        now = utcnow()
        admitted = admit_objective(
            objective, signed, authenticator=adapter.decision_authenticator, now=now
        )
        assert adapter.activate_environment(environment_id, package, plan, signed)["status"] == "active"
        assert _project_containers(adapter, environment_id), "no real container is running"

        chain = bind_reference_chain(
            admitted=admitted, signed_activation_decision=signed,
            defensive_effect_ref=accept_defensive_effect_ref(edge_effect_payload(decision_id, now)),
            adapter=adapter, environment_id=environment_id, now=utcnow(),
        )
        bound_observer(adapter, chain, package, plan).record(
            observation_class="interaction", surface="service"
        )
        # SYNTHETIC test input, not production Edge interop or diversion: a
        # hand-built ProducerRedirectionEvidence stands in for the Edge mechanism
        # observation. It proves only that AZ-06 carries and projects it.
        mechanism = ProducerRedirectionEvidence(
            producer_product="azazel-edge", producer_node="edge-1",
            trace_id=chain.trace_id, decision_ref=f"decision:{decision_id}",
            execution_ref="execution-1", mechanism_observation_ref="mechanism-1",
            evidence_refs=["edge-nft-1"],
        )
        bundle = build_feedback_bundle(
            adapter, chain, now=utcnow(), max_age=300.0,
            expected_telemetry=EXPECTED, observed_telemetry=EXPECTED, mechanism=mechanism,
            isolation_assertion_refs=("isolation-net-none",), active_surface_refs=(SURFACE,),
        )
        assert bundle["observed_mechanism"]["status"] == "observed"
        assert bundle["observed_mechanism"]["trace_id"] == chain.trace_id
        assert "redirection_does_not_imply_diversion" in bundle["limitations"]
        assert "virtual_or_local_evidence_not_hil" in bundle["limitations"]
        assert bundle["tactical_assessment"]["status"] == "not_assessed"
        terrain = bundle["runtime_materialization"]["presented_terrain"]
        assert terrain is not None, "synthetic mechanism did not project a PresentedTerrainRef"
        PresentedTerrainRef.model_validate(terrain)
        verify_feedback_bundle(
            bundle, expected_chain=chain, state=adapter.state, now=utcnow(),
            max_age=300.0, mechanism=mechanism,
        )

        termination = _termination(f"edge-terminate-{environment_id}")
        termination["environment_id"] = environment_id
        assert adapter.terminate_environment(
            environment_id, sign_decision(termination, TEST_KEY)
        )["status"] == "terminated"
        assert _project_containers(adapter, environment_id) == []

        # terminated but not yet reset: reset_feedback must refuse (fail closed)
        with pytest.raises(BindingRefused) as early:
            reset_feedback(adapter, chain, now=utcnow())
        assert early.value.code == "session_mismatch"

        assert adapter.reset_environment(environment_id)["status"] == "reset"
        result = reset_feedback(adapter, chain, now=utcnow())
        assert result["effect_observation"]["status"] == "terminated"
        assert result["limitations"]
        assert adapter.verify_evidence(environment_id) is True
        with pytest.raises(BindingRefused) as refused:
            bound_observer(adapter, chain, package, plan).record(
                observation_class="interaction", surface="service"
            )
        assert refused.value.code == "session_reset"
    finally:
        subprocess.run(
            ["docker", "compose", "-f", str(COMPOSE), "-p", adapter._project_name(environment_id),
             "down", "--remove-orphans"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60, check=False,
        )
