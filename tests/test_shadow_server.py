"""Tests for the authenticated Edge shadow/replay service."""

import errno
import hashlib
import json
import threading
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from azazel_deception.capabilities import detect_host_capabilities
from azazel_deception.package import calculate_package_digest, load_package
from azazel_deception.planner import build_placement_plan
from azazel_deception.runtime.shadow_server import (
    ENVELOPE_SIGNATURE_FIELD,
    REQUEST_SCHEMA,
    RESPONSE_SCHEMA,
    AUDIT_ENVIRONMENT_ID,
    ShadowReplayHTTPServer,
    ShadowReplayService,
    _ledger_key,
)
from azazel_deception.runtime.state import RuntimeStateStore
from azazel_deception.runtime.transport import (
    HmacDecisionAuthenticator,
    compute_decision_signature,
)
from azazel_fabric.deception_contracts import HostCapabilities

from tests.test_runtime import _decision, _host, _termination

PACKAGE = Path("examples/packages/municipal-linux-v1/package.yaml")
COMPOSE = Path("runtime/compose/reference-linux.compose.yaml")
KEY = "shadow-test-key"
EDGE_ID = "edge-node-1"
NODE_ID = "az06-node-1"


@pytest.fixture
def lite_package_path(tmp_path):
    package = load_package(PACKAGE)
    for component in package["components"]:
        component["image"]["verified"] = component["component_id"] == "intranet-web"
    package["package_digest"] = calculate_package_digest(package)
    path = tmp_path / "package.json"
    path.write_text(json.dumps(package), encoding="utf-8")
    return path


def _synthetic_capabilities():
    # The canonical HostCapabilities shape the real detector returns (includes
    # authority="descriptive_only"), built from a deterministic docker-capable
    # host so the plan/activate flow is host-independent (CI runners without
    # Docker, e.g. macOS, would otherwise report the adapter unavailable) and
    # the "identical plan" assertion is stable (real free storage drifts).
    return HostCapabilities.model_validate(_host()).model_dump(mode="json")


@pytest.fixture
def service(tmp_path, lite_package_path):
    return ShadowReplayService(
        node_id=NODE_ID,
        transport_key=KEY,
        allowed_edge_ids=[EDGE_ID],
        package_path=lite_package_path,
        state_root=tmp_path / "state",
        compose_file=COMPOSE,
        capability_provider=_synthetic_capabilities,
    )


_counter = 0


def _envelope(action, payload=None, *, key=KEY, edge_id=EDGE_ID, node_id=NODE_ID, **overrides):
    global _counter
    _counter += 1
    envelope = {
        "schema_version": REQUEST_SCHEMA,
        "request_id": f"req-{_counter}",
        "edge_node_id": edge_id,
        "az06_node_id": node_id,
        "action": action,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "payload": payload or {},
    }
    envelope.update(overrides)
    envelope[ENVELOPE_SIGNATURE_FIELD] = compute_decision_signature(
        envelope, key, signature_field=ENVELOPE_SIGNATURE_FIELD
    )
    return envelope


def _assert_signed_response(response):
    assert response["schema_version"] == RESPONSE_SCHEMA
    assert response["authority"] == "descriptive_only"
    assert response["enforcement_applied"] is False
    verifier = HmacDecisionAuthenticator(KEY, signature_field=ENVELOPE_SIGNATURE_FIELD)
    assert verifier(response) is True


def test_capabilities_requires_authentic_envelope(service):
    envelope = _envelope("capabilities")
    envelope[ENVELOPE_SIGNATURE_FIELD] = "0" * 64
    response = service.handle(envelope)
    assert response["status"] == "rejected"
    assert response["reason_codes"] == ["authentication_failed"]
    _assert_signed_response(response)


def test_wrong_key_fails_authentication(service):
    response = service.handle(_envelope("capabilities", key="not-the-shared-key"))
    assert response["reason_codes"] == ["authentication_failed"]


def test_unknown_edge_identity_is_rejected(service):
    response = service.handle(_envelope("capabilities", edge_id="edge-rogue"))
    assert response["reason_codes"] == ["edge_identity_not_allowlisted"]


def test_wrong_node_identity_is_rejected(service):
    response = service.handle(_envelope("capabilities", node_id="az06-other"))
    assert response["reason_codes"] == ["node_identity_mismatch"]


def test_stale_envelope_is_rejected(service):
    stale = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
    response = service.handle(_envelope("capabilities", issued_at=stale))
    assert response["reason_codes"] == ["stale_request"]


def test_replayed_envelope_is_rejected(service):
    envelope = _envelope("capabilities")
    first = service.handle(envelope)
    assert first["status"] == "ok"
    replay = service.handle(envelope)
    assert replay["status"] == "rejected"
    assert replay["reason_codes"] == ["replayed_request"]


def test_unsupported_schema_and_action_fail_closed(service):
    response = service.handle(_envelope("capabilities", schema_version="bogus/v9"))
    assert response["reason_codes"] == ["unsupported_schema"]
    response = service.handle(_envelope("route_traffic"))
    assert response["reason_codes"] == ["unsupported_action"]


def test_malformed_envelope_fails_closed(service):
    response = service.handle("not a mapping")
    assert response["status"] == "rejected"
    assert response["reason_codes"] == ["malformed_envelope"]


def test_capabilities_and_package_and_plan_flow(service, lite_package_path):
    response = service.handle(_envelope("capabilities"))
    assert response["status"] == "ok"
    _assert_signed_response(response)
    capabilities = response["result"]["capabilities"]
    assert capabilities["authority"] == "descriptive_only"

    package_response = service.handle(_envelope("package"))
    assert package_response["status"] == "ok"
    package = package_response["result"]["package"]
    assert package_response["result"]["package_digest"] == package["package_digest"]

    plan_response = service.handle(
        _envelope("plan", {"requested_tier": "lite", "edge_decision_id": "edge-d-1"})
    )
    assert plan_response["status"] == "ok"
    plan = plan_response["result"]["placement_plan"]
    assert plan["authority"] == "descriptive_only"
    assert plan["edge_decision_id"] == "edge-d-1"
    assert plan["selected_tier"] == "lite"
    # Deterministic: an identical plan request yields an identical plan.
    again = service.handle(
        _envelope("plan", {"requested_tier": "lite", "edge_decision_id": "edge-d-1"})
    )
    assert again["result"]["placement_plan"] == plan


def test_shadow_activation_and_termination_rehearsal(service, lite_package_path):
    package = json.loads(lite_package_path.read_text(encoding="utf-8"))
    plan = build_placement_plan(
        package,
        _host(),
        requested_tier="lite",
        edge_decision_id="edge-d-2",
    )
    decision = _decision(package, plan, decision_id="edge-d-2")
    response = service.handle(
        _envelope(
            "activate",
            {
                "environment_id": "env-shadow-1",
                "package": package,
                "placement": plan,
                "decision": decision,
            },
        )
    )
    assert response["status"] == "ok"
    result = response["result"]
    assert result["status"] == "shadow_accepted"
    assert result["live_execution"] is False
    assert result["simulated_state"] == "active"

    termination = _termination("edge-t-2")
    termination["environment_id"] = "env-shadow-1"
    terminate_response = service.handle(
        _envelope("terminate", {"environment_id": "env-shadow-1", "decision": termination})
    )
    assert terminate_response["status"] == "ok"
    assert terminate_response["result"]["simulated_state"] == "terminated"

    # Rehearsal must not consume the one-shot decision ledger or write state.
    assert service.state.decision_consumed("edge-d-2") is False
    assert service.adapter.collect_status("env-shadow-1")["state"] == "absent"


def test_shadow_activation_binding_mismatch_is_deterministic(service, lite_package_path):
    package = json.loads(lite_package_path.read_text(encoding="utf-8"))
    plan = build_placement_plan(
        package,
        _host(),
        requested_tier="lite",
        edge_decision_id="edge-d-3",
    )
    decision = _decision(package, plan, decision_id="edge-d-other")
    response = service.handle(
        _envelope(
            "activate",
            {
                "environment_id": "env-shadow-2",
                "package": package,
                "placement": plan,
                "decision": decision,
            },
        )
    )
    assert response["status"] == "rejected"
    assert "shadow_validation_failed" in response["reason_codes"]


def test_expired_shadow_decision_is_rejected(service, lite_package_path):
    package = json.loads(lite_package_path.read_text(encoding="utf-8"))
    plan = build_placement_plan(
        package,
        _host(),
        requested_tier="lite",
        edge_decision_id="edge-d-4",
    )
    decision = _decision(package, plan, decision_id="edge-d-4")
    decision["expires_at"] = (
        datetime.now(timezone.utc) - timedelta(minutes=1)
    ).isoformat()
    response = service.handle(
        _envelope(
            "activate",
            {
                "environment_id": "env-shadow-3",
                "package": package,
                "placement": plan,
                "decision": decision,
            },
        )
    )
    assert response["status"] == "rejected"
    assert "shadow_validation_failed" in response["reason_codes"]


def test_every_request_is_audited_with_intact_evidence_chain(service, tmp_path):
    service.handle(_envelope("capabilities"))
    service.handle(_envelope("capabilities", edge_id="edge-rogue"))
    store = RuntimeStateStore(tmp_path / "state")
    events = [
        json.loads(line)
        for line in store.evidence_path(AUDIT_ENVIRONMENT_ID)
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    assert [event["status"] for event in events] == ["ok", "rejected"]
    assert store.verify_evidence_chain(AUDIT_ENVIRONMENT_ID) is True


def test_http_round_trip(service):
    with ShadowReplayHTTPServer(service) as server:
        host, port = server.address
        request = urllib.request.Request(
            f"http://{host}:{port}/shadow",
            data=json.dumps(_envelope("capabilities")).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=10) as raw:
            response = json.loads(raw.read().decode("utf-8"))
    assert response["status"] == "ok"
    _assert_signed_response(response)


def _audit_events(tmp_path):
    store = RuntimeStateStore(tmp_path / "state")
    path = store.evidence_path(AUDIT_ENVIRONMENT_ID)
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


@pytest.mark.parametrize("bad_id", [123, ["req"], {"id": "x"}, ""])
def test_malformed_request_id_is_rejected_signed_and_audited(service, tmp_path, bad_id):
    response = service.handle(_envelope("capabilities", request_id=bad_id))
    assert response["status"] == "rejected"
    assert response["reason_codes"] == ["malformed_envelope"]
    _assert_signed_response(response)
    events = _audit_events(tmp_path)
    assert [event["status"] for event in events] == ["rejected"]
    assert events[0]["reason_codes"] == ["malformed_envelope"]


def test_slash_request_id_is_echoed_and_replay_is_still_rejected(service):
    request_id = "tenant/a:../b c"
    envelope = _envelope("capabilities", request_id=request_id)
    first = service.handle(envelope)
    assert first["status"] == "ok"
    assert first["request_id"] == request_id
    _assert_signed_response(first)
    replay = service.handle(envelope)
    assert replay["status"] == "rejected"
    assert replay["reason_codes"] == ["replayed_request"]
    assert replay["request_id"] == request_id


def test_ordinary_request_writes_legacy_compatible_raw_marker(service, tmp_path):
    # Rollback safety: an ordinary safe request_id must be consumed under the
    # raw marker older builds check, not only under the SHA key.
    request_id = "ordinary-req-1"
    envelope = _envelope("capabilities", request_id=request_id)
    response = service.handle(envelope)
    assert response["status"] == "ok"
    store = RuntimeStateStore(tmp_path / "state")
    assert store.decision_consumed(f"shadow-request-{request_id}")
    sha_key = _ledger_key(request_id)
    assert not store.decision_consumed(sha_key)


def test_legacy_raw_marker_consumed_by_old_build_rejects_as_replay(service, tmp_path):
    request_id = "legacy-req-7"
    # Pre-seed the raw marker exactly as the pre-hash implementation wrote it.
    store = RuntimeStateStore(tmp_path / "state")
    assert store.consume_decision(
        f"shadow-request-{request_id}",
        {"decision_id": f"shadow-request-{request_id}", "kind": "shadow_request"},
    )
    envelope = _envelope("capabilities", request_id=request_id)
    response = service.handle(envelope)
    assert response["status"] == "rejected"
    assert response["reason_codes"] == ["replayed_request"]
    assert response["request_id"] == request_id
    _assert_signed_response(response)
    events = _audit_events(tmp_path)
    assert events[-1]["status"] == "rejected"
    assert events[-1]["reason_codes"] == ["replayed_request"]


def test_unexpected_action_exception_is_fail_closed_and_audited(service, tmp_path, monkeypatch):
    def boom(payload, envelope):
        raise RuntimeError("secret-internal-detail")

    monkeypatch.setattr(service, "_action_capabilities", boom)
    response = service.handle(_envelope("capabilities"))
    assert response["status"] == "rejected"
    assert response["reason_codes"] == ["internal_error"]
    assert response["result"] == {}
    assert "secret-internal-detail" not in json.dumps(response)
    _assert_signed_response(response)
    events = _audit_events(tmp_path)
    assert [event["status"] for event in events] == ["rejected"]
    assert events[0]["reason_codes"] == ["internal_error"]


def test_audit_store_failure_returns_signed_audit_write_failed(service, tmp_path, monkeypatch):
    def fail_write(environment_id, event):
        raise OSError("disk full")

    monkeypatch.setattr(service.state, "append_evidence", fail_write)
    response = service.handle(_envelope("capabilities"))
    assert response["status"] == "rejected"
    assert response["reason_codes"] == ["audit_write_failed"]
    _assert_signed_response(response)
    assert _audit_events(tmp_path) == []


def _post_raw(server, body: bytes):
    host, port = server.address
    request = urllib.request.Request(
        f"http://{host}:{port}/shadow",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as raw:
        return json.loads(raw.read().decode("utf-8"))


def test_lone_surrogate_request_id_gets_signed_rejection_and_audit(service, tmp_path):
    envelope = {
        "schema_version": REQUEST_SCHEMA,
        "request_id": "\ud800",
        "edge_node_id": EDGE_ID,
        "az06_node_id": NODE_ID,
        "action": "capabilities",
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "payload": {},
        ENVELOPE_SIGNATURE_FIELD: "0" * 64,
    }
    response = service.handle(envelope)
    assert response["status"] == "rejected"
    assert response["request_id"] == "unparsable"
    _assert_signed_response(response)
    events = _audit_events(tmp_path)
    assert len(events) == 1
    assert events[0]["status"] == "rejected"


def test_deeply_nested_json_body_gets_signed_rejection_and_audit(service, tmp_path):
    body = b"[" * 200000 + b"]" * 200000
    with ShadowReplayHTTPServer(service) as server:
        response = _post_raw(server, body)
    assert response["status"] == "rejected"
    assert response["reason_codes"] == ["malformed_envelope"]
    _assert_signed_response(response)
    events = _audit_events(tmp_path)
    assert [event["status"] for event in events] == ["rejected"]


def test_concurrent_requests_keep_evidence_chain_intact(service, tmp_path):
    # Drives ShadowReplayService.handle() directly (no HTTP) so the audit path
    # is exercised deterministically: a fixed small worker pool, a barrier that
    # releases all workers together for each batch, and 4 batches x 6 workers
    # = 24 unique authenticated requests.
    workers = 6
    batches = 4
    count = workers * batches
    # Envelopes are built in the main thread: _envelope() mutates a module-level
    # counter and is not thread-safe.
    envelopes = [[_envelope("capabilities") for _ in range(workers)] for _ in range(batches)]
    barrier = threading.Barrier(workers)
    results = [[None] * workers for _ in range(batches)]
    errors = []

    def worker(index):
        try:
            for batch in range(batches):
                barrier.wait(timeout=30)
                results[batch][index] = service.handle(envelopes[batch][index])
        except Exception as exc:  # surfaced via the assertion below
            errors.append(exc)
            barrier.abort()

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert not errors
    assert not any(thread.is_alive() for thread in threads)

    responses = [response for batch in results for response in batch]
    assert len(responses) == count
    assert all(response is not None and response["status"] == "ok" for response in responses)

    store = RuntimeStateStore(tmp_path / "state")
    assert store.verify_evidence_chain(AUDIT_ENVIRONMENT_ID) is True
    events = _audit_events(tmp_path)
    assert len(events) == count
    assert [event["_evidence_seq"] for event in events] == list(range(count))


def test_append_evidence_partial_write_failure_rolls_back_to_prior_eof(tmp_path, monkeypatch):
    import azazel_deception.runtime.state as state_module

    store = RuntimeStateStore(tmp_path / "state")
    store.append_evidence("env", {"n": 1})
    path = store.evidence_path("env")
    before = path.read_bytes()

    real_write = state_module.os.write

    def partial_write(fd, data):
        real_write(fd, bytes(data)[: len(data) // 2])
        raise OSError(errno.EIO, "simulated partial write")

    monkeypatch.setattr(state_module, "_write_all", lambda fd, data: partial_write(fd, data))
    with pytest.raises(OSError):
        store.append_evidence("env", {"n": 2})
    monkeypatch.undo()

    assert path.read_bytes() == before
    assert store.verify_evidence_chain("env") is True
    store.append_evidence("env", {"n": 3})
    assert store.verify_evidence_chain("env") is True


def test_append_evidence_does_not_repair_preexisting_corruption(tmp_path):
    store = RuntimeStateStore(tmp_path / "state")
    store.append_evidence("env", {"n": 1})
    path = store.evidence_path("env")
    path.write_bytes(path.read_bytes() + b'{"torn":')
    corrupt = path.read_bytes()
    with pytest.raises(ValueError):
        store.append_evidence("env", {"n": 2})
    assert path.read_bytes() == corrupt


def test_overlong_safe_request_id_falls_back_to_sha_marker(service, tmp_path):
    request_id = "a" * 300
    envelope = _envelope("capabilities", request_id=request_id)
    first = service.handle(envelope)
    assert first["status"] == "ok"
    assert first["request_id"] == request_id
    store = RuntimeStateStore(tmp_path / "state")
    assert store.decision_consumed(_ledger_key(request_id))
    replay = service.handle(envelope)
    assert replay["reason_codes"] == ["replayed_request"]


def test_non_path_length_oserror_is_not_swallowed_into_fallback(service, tmp_path, monkeypatch):
    def deny(decision_id, record):
        raise OSError(errno.EACCES, "denied")

    monkeypatch.setattr(service.state, "consume_decision", deny)
    response = service.handle(_envelope("capabilities"))
    assert response["reason_codes"] == ["internal_error"]
    _assert_signed_response(response)


def test_sha_fallback_key_does_not_collide_with_raw_marker_of_digest_id(service, tmp_path):
    unsafe_id = "tenant/a b"
    digest = hashlib.sha256(unsafe_id.encode("utf-8")).hexdigest()
    assert _ledger_key(unsafe_id) != f"shadow-request-{digest}"
    raw_first = service.handle(_envelope("capabilities", request_id=digest))
    unsafe = service.handle(_envelope("capabilities", request_id=unsafe_id))
    assert raw_first["status"] == "ok"
    assert unsafe["status"] == "ok"
    # And in the other order, on a fresh unsafe/raw pair.
    other_unsafe = "x/y z"
    other_digest = hashlib.sha256(other_unsafe.encode("utf-8")).hexdigest()
    assert service.handle(_envelope("capabilities", request_id=other_unsafe))["status"] == "ok"
    assert service.handle(_envelope("capabilities", request_id=other_digest))["status"] == "ok"
