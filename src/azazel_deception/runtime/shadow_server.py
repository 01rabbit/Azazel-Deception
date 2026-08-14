"""Authenticated shadow/replay service for Edge -> AZ-06 integration.

This is the strictly non-executing network boundary Azazel-Edge talks to
before any live activation exists: Edge can discover this node's identity and
capabilities, read the reference package identity, request a deterministic
descriptive placement plan, and rehearse activation/termination decisions —
all with zero container start and zero network exposure beyond the management
endpoint itself.

Transport security model:

* Every request/response is an HMAC-SHA256-signed envelope over the same
  canonical bytes the decision transport uses (`canonical_decision_bytes`),
  with a shared key supplied by the operator/integration boundary.
* The Edge caller identity must be allowlisted and the target AZ-06 node
  identity must match this node.
* Envelopes carry `issued_at` freshness (`heartbeat_is_fresh`) and a one-shot
  `request_id` anti-replay ledger, so stale or replayed envelopes fail closed.
* All rejections are deterministic reason codes; every request/response pair
  is appended to the tamper-evident evidence log for Edge audit and Knowledge
  ingest.

Authority model: everything returned is `descriptive_only` and records
`enforcement_applied=False`. Edge remains the sole activation authority; this
service cannot start anything (the adapter's live gates are unaffected).
AZ-06 remains optional — Edge baseline operation must not depend on this
endpoint being reachable.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from azazel_deception.capabilities import detect_host_capabilities
from azazel_deception.package import load_package, parse_package
from azazel_deception.planner import PackageValidationError, build_placement_plan
from azazel_deception.runtime.compose import DockerComposeAdapter, RuntimeGateError
from azazel_deception.runtime.state import RuntimeStateStore
from azazel_deception.runtime.transport import (
    HmacDecisionAuthenticator,
    compute_decision_signature,
    heartbeat_is_fresh,
)

REQUEST_SCHEMA = "az06-shadow-request/v0.1"
RESPONSE_SCHEMA = "az06-shadow-response/v0.1"
ENVELOPE_SIGNATURE_FIELD = "signature"
AUDIT_ENVIRONMENT_ID = "shadow-audit"

_ACTIONS = frozenset({"capabilities", "package", "plan", "activate", "terminate"})


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ShadowReplayService:
    """Transport-independent handler for authenticated shadow requests."""

    def __init__(
        self,
        *,
        node_id: str,
        transport_key: str | bytes,
        allowed_edge_ids: list[str] | tuple[str, ...] | set[str],
        package_path: str | Path,
        state_root: str | Path,
        compose_file: str | Path,
        max_request_age_seconds: float = 30.0,
        decision_authenticator=None,
    ) -> None:
        if not node_id:
            raise ValueError("shadow service requires a node_id")
        self.node_id = node_id
        self._envelope_authenticator = HmacDecisionAuthenticator(
            transport_key, signature_field=ENVELOPE_SIGNATURE_FIELD
        )
        self._transport_key = transport_key
        self.allowed_edge_ids = frozenset(allowed_edge_ids)
        if not self.allowed_edge_ids:
            raise ValueError("shadow service requires a non-empty Edge allowlist")
        self.package_path = Path(package_path)
        self.max_request_age_seconds = float(max_request_age_seconds)
        self.state = RuntimeStateStore(state_root)
        # Shadow rehearsal never enables live execution, whatever the
        # environment says: the adapter is pinned to live_enabled=False.
        self.adapter = DockerComposeAdapter(
            compose_file,
            state_root,
            live_enabled=False,
            decision_authenticator=decision_authenticator,
        )

    # -- envelope plumbing ---------------------------------------------------

    def _sign(self, response: dict[str, Any]) -> dict[str, Any]:
        response[ENVELOPE_SIGNATURE_FIELD] = compute_decision_signature(
            response, self._transport_key, signature_field=ENVELOPE_SIGNATURE_FIELD
        )
        return response

    def _response(
        self,
        request_id: str,
        status: str,
        reason_codes: list[str],
        result: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self._sign(
            {
                "schema_version": RESPONSE_SCHEMA,
                "request_id": request_id,
                "az06_node_id": self.node_id,
                "status": status,
                "reason_codes": sorted(set(reason_codes)),
                "authority": "descriptive_only",
                "enforcement_applied": False,
                "responded_at": _utcnow().isoformat(),
                "result": result or {},
            }
        )

    def _audit(self, envelope: Any, response: dict[str, Any]) -> None:
        summary = {
            "schema_version": "az06-shadow-audit/v0.1",
            "observed_at": _utcnow().isoformat(),
            "request_id": str(response.get("request_id")),
            "edge_node_id": (
                str(envelope.get("edge_node_id"))
                if isinstance(envelope, dict)
                else "unparsable"
            ),
            "action": (
                str(envelope.get("action")) if isinstance(envelope, dict) else "unparsable"
            ),
            "status": response.get("status"),
            "reason_codes": response.get("reason_codes"),
        }
        self.state.append_evidence(AUDIT_ENVIRONMENT_ID, summary)

    # -- request handling ----------------------------------------------------

    def handle(self, envelope: Any) -> dict[str, Any]:
        response = self._handle_inner(envelope)
        self._audit(envelope, response)
        return response

    def _handle_inner(self, envelope: Any) -> dict[str, Any]:
        if not isinstance(envelope, dict):
            return self._response("unparsable", "rejected", ["malformed_envelope"])
        request_id = str(envelope.get("request_id") or "missing")
        if envelope.get("schema_version") != REQUEST_SCHEMA:
            return self._response(request_id, "rejected", ["unsupported_schema"])
        if not self._envelope_authenticator(envelope):
            return self._response(request_id, "rejected", ["authentication_failed"])
        if envelope.get("edge_node_id") not in self.allowed_edge_ids:
            return self._response(request_id, "rejected", ["edge_identity_not_allowlisted"])
        if envelope.get("az06_node_id") != self.node_id:
            return self._response(request_id, "rejected", ["node_identity_mismatch"])
        if not heartbeat_is_fresh(
            envelope.get("issued_at") or "", self.max_request_age_seconds
        ):
            return self._response(request_id, "rejected", ["stale_request"])
        action = envelope.get("action")
        if action not in _ACTIONS:
            return self._response(request_id, "rejected", ["unsupported_action"])
        if envelope.get("request_id") in (None, "") or not self.state.consume_decision(
            f"shadow-request-{request_id}",
            {
                "decision_id": f"shadow-request-{request_id}",
                "kind": "shadow_request",
                "edge_node_id": str(envelope.get("edge_node_id")),
                "consumed_at": _utcnow().isoformat(),
            },
        ):
            return self._response(request_id, "rejected", ["replayed_request"])

        payload = envelope.get("payload")
        if payload is None:
            payload = {}
        if not isinstance(payload, dict):
            return self._response(request_id, "rejected", ["malformed_payload"])
        handler = getattr(self, f"_action_{action}")
        try:
            result = handler(payload)
        except (RuntimeGateError, PackageValidationError, ValueError) as exc:
            return self._response(
                request_id,
                "rejected",
                ["shadow_validation_failed", exc.__class__.__name__],
                {"detail": str(exc)[:500]},
            )
        return self._response(request_id, "ok", ["shadow_only_no_enforcement"], result)

    # -- actions -------------------------------------------------------------

    def _action_capabilities(self, payload: dict[str, Any]) -> dict[str, Any]:
        capabilities = detect_host_capabilities()
        return {"capabilities": capabilities}

    def _action_package(self, payload: dict[str, Any]) -> dict[str, Any]:
        raw = load_package(self.package_path)
        package = parse_package(raw)
        return {
            "package": raw,
            "package_id": package.package_id,
            "package_version": package.package_version,
            "package_digest": package.package_digest,
        }

    def _action_plan(self, payload: dict[str, Any]) -> dict[str, Any]:
        edge_decision_id = payload.get("edge_decision_id")
        if not edge_decision_id:
            raise ValueError("plan request requires edge_decision_id")
        raw = load_package(self.package_path)
        plan = build_placement_plan(
            raw,
            detect_host_capabilities(),
            requested_tier=payload.get("requested_tier"),
            edge_decision_id=str(edge_decision_id),
        )
        return {"placement_plan": plan}

    def _action_activate(self, payload: dict[str, Any]) -> dict[str, Any]:
        for field in ("environment_id", "package", "placement", "decision"):
            if field not in payload:
                raise ValueError(f"activate request requires {field}")
        return self.adapter.shadow_activation(
            str(payload["environment_id"]),
            payload["package"],
            payload["placement"],
            payload["decision"],
        )

    def _action_terminate(self, payload: dict[str, Any]) -> dict[str, Any]:
        for field in ("environment_id", "decision"):
            if field not in payload:
                raise ValueError(f"terminate request requires {field}")
        return self.adapter.shadow_termination(
            str(payload["environment_id"]),
            payload["decision"],
        )


class _ShadowRequestHandler(BaseHTTPRequestHandler):
    service: ShadowReplayService  # set by server factory

    # Silence per-request stderr logging; the evidence log is the audit trail.
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass

    def do_POST(self) -> None:  # noqa: N802 (http.server API)
        if self.path != "/shadow":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length > 0 else b""
            envelope = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            envelope = None
        response = self.service.handle(envelope)
        encoded = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


class ShadowReplayHTTPServer:
    """Localhost-oriented HTTP wrapper around :class:`ShadowReplayService`."""

    def __init__(
        self,
        service: ShadowReplayService,
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        handler = type("BoundShadowHandler", (_ShadowRequestHandler,), {"service": service})
        self._server = ThreadingHTTPServer((host, port), handler)
        self._thread: threading.Thread | None = None

    @property
    def address(self) -> tuple[str, int]:
        return self._server.server_address[0], self._server.server_address[1]

    def start(self) -> None:
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=10)
            self._thread = None

    def __enter__(self) -> "ShadowReplayHTTPServer":
        self.start()
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.stop()
