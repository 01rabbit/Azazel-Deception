"""Tests for exporting AZ-06's recorded interaction observations.

Covers the read-side projection (`observation_export.export_observations` /
`observations_since`), the `DockerComposeAdapter.export_observations`
delegate, and the dev-only `scripts/dev/push_observations.py` relay helper.
"""

from __future__ import annotations

import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from azazel_deception.package import load_package, parse_package
from azazel_deception.planner import build_placement_plan
from azazel_deception.runtime.compose import DockerComposeAdapter
from azazel_deception.runtime.observation import InteractionObserver
from azazel_deception.runtime.observation_export import (
    export_observations,
    observations_since,
)
from azazel_deception.runtime.state import RuntimeStateStore
from azazel_fabric.deception_contracts import InteractionObservation, PlacementPlan

from tests.test_runtime import _host

PACKAGE = Path("examples/packages/municipal-linux-v1/package.yaml")
COMPOSE = Path("runtime/compose/reference-linux.compose.yaml")

ROOT = Path(__file__).resolve().parents[1]
PUSH_SCRIPT = ROOT / "scripts/dev/push_observations.py"


def _load_push_module():
    spec = importlib.util.spec_from_file_location("push_observations_dev", PUSH_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _package_and_plan():
    raw = load_package(PACKAGE)
    package = parse_package(raw)
    plan = PlacementPlan.model_validate(
        build_placement_plan(raw, _host(), requested_tier="lite", edge_decision_id="edge-1")
    )
    return package, plan


def _observer(state, environment_id):
    package, plan = _package_and_plan()
    return InteractionObserver(
        state,
        environment_id=environment_id,
        package_id=package.package_id,
        node_id=plan.node_id,
    )


def _lifecycle_event(state, environment_id, event_id, event_type):
    state.append_evidence(
        environment_id,
        {
            "schema_version": "environment-event/v0.1",
            "event_id": event_id,
            "environment_id": environment_id,
            "package_id": "pkg",
            "node_id": "node",
            "event_type": event_type,
            "observed_at": "2026-01-01T00:00:00+00:00",
            "evidence_refs": [],
            "metadata": {},
        },
    )


def test_export_observations_filters_lifecycle_and_orders(tmp_path):
    state = RuntimeStateStore(tmp_path)
    env = "env-export-1"
    observer = _observer(state, env)

    _lifecycle_event(state, env, f"{env}-activated", "activated")
    first = observer.record(observation_class="interaction", surface="port")
    _lifecycle_event(state, env, f"{env}-mid", "failure")
    second = observer.record(
        observation_class="reaction", surface="service", reaction_kind="enumerate"
    )
    _lifecycle_event(state, env, f"{env}-terminated", "terminated")

    exported = export_observations(state, env)

    assert len(exported) == 2
    assert [e["observation_id"] for e in exported] == [
        first.observation_id,
        second.observation_id,
    ]
    for record in exported:
        assert record["schema_version"] == "interaction-observation/v0.1"
        # Round trips through Fabric's own model with no local bookkeeping
        # fields leaking through (extra="forbid" would reject any).
        validated = InteractionObservation.model_validate(record)
        assert validated.observation_id in {first.observation_id, second.observation_id}
        assert "_evidence_seq" not in record
        assert "_evidence_prev" not in record
        assert "_evidence_hash" not in record


def test_export_observations_empty_when_no_evidence(tmp_path):
    state = RuntimeStateStore(tmp_path)
    assert export_observations(state, "env-never-seen") == []


def test_observations_since_returns_only_new(tmp_path):
    state = RuntimeStateStore(tmp_path)
    env = "env-export-2"
    observer = _observer(state, env)

    first = observer.record(observation_class="interaction", surface="port")
    second = observer.record(observation_class="interaction", surface="port")
    third = observer.record(observation_class="interaction", surface="port")

    all_obs = observations_since(state, env)
    assert [o["observation_id"] for o in all_obs] == [
        first.observation_id,
        second.observation_id,
        third.observation_id,
    ]

    since_first = observations_since(state, env, after_observation_id=first.observation_id)
    assert [o["observation_id"] for o in since_first] == [
        second.observation_id,
        third.observation_id,
    ]

    since_last = observations_since(state, env, after_observation_id=third.observation_id)
    assert since_last == []


def test_observations_since_unknown_cursor_raises(tmp_path):
    state = RuntimeStateStore(tmp_path)
    env = "env-export-3"
    _observer(state, env).record(observation_class="interaction", surface="port")
    with pytest.raises(ValueError, match="not found"):
        observations_since(state, env, after_observation_id="bogus-id")


def test_adapter_export_observations_delegates(tmp_path):
    package, plan = _package_and_plan()
    adapter = DockerComposeAdapter(COMPOSE, tmp_path, live_enabled=False)
    observer = adapter.make_observer("env-export-4", package, plan)
    observer.record(observation_class="outcome", surface="file", reaction_kind="exfiltrate")

    exported = adapter.export_observations("env-export-4")
    assert len(exported) == 1
    assert exported[0]["surface"] == "file"
    assert exported == export_observations(adapter.state, "env-export-4")


class _CapturingHandler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802 - stdlib API name
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self.server.received_bodies.append(body)
        self.server.received_headers.append(dict(self.headers.items()))
        self.send_response(202)
        self.end_headers()

    def log_message(self, *args):  # silence stdlib request logging
        pass


class _CapturingServer(HTTPServer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.received_bodies: list[bytes] = []
        self.received_headers: list[dict] = []


def _run_capturing_server():
    server = _CapturingServer(("127.0.0.1", 0), _CapturingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def test_push_observations_forwards_exact_canonical_dicts(tmp_path):
    state = RuntimeStateStore(tmp_path)
    env = "env-export-push"
    observer = _observer(state, env)
    observer.record(observation_class="interaction", surface="port")
    observer.record(observation_class="reaction", surface="service", reaction_kind="enumerate")
    observations = export_observations(state, env)

    push_mod = _load_push_module()
    server, thread = _run_capturing_server()
    try:
        host, port = server.server_address
        status = push_mod.push_observations(
            observations, f"http://{host}:{port}/ingest", token="dev-token"
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert status == 202
    assert len(server.received_bodies) == 1
    received = json.loads(server.received_bodies[0].decode("utf-8"))
    assert received == {"observations": observations}
    assert server.received_headers[0]["Authorization"] == "Bearer dev-token"

    # Each forwarded dict is unchanged and still Fabric-validates: the relay
    # neither adds nor interprets anything.
    for record in received["observations"]:
        InteractionObservation.model_validate(record)


def test_push_observations_is_noop_on_empty_list(tmp_path):
    push_mod = _load_push_module()
    server, thread = _run_capturing_server()
    try:
        host, port = server.server_address
        result = push_mod.push_observations([], f"http://{host}:{port}/ingest")
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert result is None
    assert server.received_bodies == []
