"""Tests for the AZ-06 incremental attacker-interaction emitter."""

from pathlib import Path

import pytest

from azazel_deception.package import load_package
from azazel_deception.planner import build_placement_plan
from azazel_deception.runtime.compose import DockerComposeAdapter
from azazel_deception.runtime.observation import (
    InteractionObserver,
    build_runtime_context,
)
from azazel_deception.runtime.state import RuntimeStateStore
from azazel_fabric.deception_contracts import InteractionObservation, PlacementPlan

from tests.test_runtime import _host

PACKAGE = Path("examples/packages/municipal-linux-v1/package.yaml")
COMPOSE = Path("runtime/compose/reference-linux.compose.yaml")


def _package_and_plan():
    raw = load_package(PACKAGE)
    from azazel_deception.package import parse_package

    package = parse_package(raw)
    plan = PlacementPlan.model_validate(
        build_placement_plan(raw, _host(), requested_tier="lite", edge_decision_id="edge-1")
    )
    return package, plan


def test_observer_records_fact_to_evidence_chain(tmp_path):
    package, plan = _package_and_plan()
    state = RuntimeStateStore(tmp_path)
    observer = InteractionObserver(
        state,
        environment_id="env-1",
        package_id=package.package_id,
        node_id=plan.node_id,
        runtime_context=build_runtime_context(package, plan),
    )
    obs = observer.record(
        observation_class="reaction",
        surface="credential_lure",
        reaction_kind="authenticate",
        lure_id="lure-admin",
        first_contact_latency_ms=800,
        attempt_count=2,
    )
    assert isinstance(obs, InteractionObservation)
    assert obs.observation_class == "reaction"
    assert obs.authority == "descriptive_only"

    chain = observer.state.verify_evidence_chain("env-1")
    assert chain is True
    events = [
        e
        for e in _read_evidence(state, "env-1")
        if e.get("schema_version") == "interaction-observation/v0.1"
    ]
    assert len(events) == 1
    assert events[0]["surface"] == "credential_lure"


def _read_evidence(state, environment_id):
    import json

    path = state.evidence_path(environment_id)
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_incremental_ids_and_ordering(tmp_path):
    package, plan = _package_and_plan()
    state = RuntimeStateStore(tmp_path)
    observer = InteractionObserver(
        state,
        environment_id="env-2",
        package_id=package.package_id,
        node_id=plan.node_id,
    )
    first = observer.record(observation_class="interaction", surface="port")
    second = observer.record(
        observation_class="reaction", surface="service", reaction_kind="enumerate"
    )
    assert first.observation_id.endswith("-0001")
    assert second.observation_id.endswith("-0002")
    assert observer.state.verify_evidence_chain("env-2") is True


def test_runtime_context_marks_active_and_omitted_components(tmp_path):
    package, plan = _package_and_plan()
    ctx = build_runtime_context(package, plan)
    assert "intranet-web" in ctx.active_components
    # optional components not in the lite placement are recorded as omitted
    optional = [c.component_id for c in package.components if not c.required]
    for oid in optional:
        assert oid in ctx.omitted_components
    assert ctx.selected_tier == "lite"


def test_observer_refuses_effectiveness_verdict_in_metadata(tmp_path):
    package, plan = _package_and_plan()
    state = RuntimeStateStore(tmp_path)
    observer = InteractionObserver(
        state,
        environment_id="env-3",
        package_id=package.package_id,
        node_id=plan.node_id,
    )
    with pytest.raises(ValueError, match="honesty invariant"):
        observer.record(
            observation_class="reaction",
            surface="credential_lure",
            reaction_kind="authenticate",
            metadata={"deceived": True},
        )
    # nothing was appended for the rejected record
    assert not state.evidence_path("env-3").exists() or _read_evidence(state, "env-3") == []


def test_interaction_class_rejects_reaction_kind(tmp_path):
    package, plan = _package_and_plan()
    state = RuntimeStateStore(tmp_path)
    observer = InteractionObserver(
        state,
        environment_id="env-4",
        package_id=package.package_id,
        node_id=plan.node_id,
    )
    with pytest.raises(ValueError):
        observer.record(
            observation_class="interaction",
            surface="port",
            reaction_kind="authenticate",
        )


def test_confounder_tags_travel_with_the_observation(tmp_path):
    package, plan = _package_and_plan()
    state = RuntimeStateStore(tmp_path)
    observer = InteractionObserver(
        state,
        environment_id="env-5",
        package_id=package.package_id,
        node_id=plan.node_id,
    )
    obs = observer.record(
        observation_class="interaction",
        surface="port",
        confounder_tags=["scanner_noise"],
    )
    assert obs.confounder_tags == ["scanner_noise"]
    with pytest.raises(ValueError):
        observer.record(
            observation_class="interaction",
            surface="port",
            confounder_tags=["not-a-real-confounder"],
        )


def test_adapter_make_observer_binds_evidence_chain(tmp_path):
    package, plan = _package_and_plan()
    adapter = DockerComposeAdapter(COMPOSE, tmp_path, live_enabled=False)
    observer = adapter.make_observer("env-6", package, plan)
    obs = observer.record(observation_class="outcome", surface="file", reaction_kind="exfiltrate")
    assert obs.runtime_context.runtime_adapter == "docker_compose"
    assert adapter.verify_evidence(observer.environment_id) is True
    exported = adapter.export_evidence("env-6")
    assert any(e.get("observation_class") == "outcome" for e in exported)
