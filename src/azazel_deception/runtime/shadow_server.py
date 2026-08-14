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

The `heartbeat` and `reconcile` actions extend the same boundary to a live
liveness/state-reconciliation loop: Edge can poll this node for a small health
summary and ask what diverges between its own authoritative active set and
local runtime state. Both are reports, not instructions — AZ-06 never acts on
a reported divergence, and Edge remains the only party that can decide to.

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

_ACTIONS = frozenset(
    {
        "capabilities",
        "package",
        "plan",
        "activate",
        "terminate",
        "heartbeat",
        "reconcile",
    }
)


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
        # Server-side heartbeat counter. It is a liveness/ordering aid for the
        # Edge loop (it can see this node restart or miss beats), not an
        # authority token and not an anti-replay control — the one-shot
        # request_id ledger owns anti-replay.
        self._heartbeat_lock = threading.Lock()
        self._heartbeat_sequence = 0
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
            result = handler(payload, envelope)
        except (RuntimeGateError, PackageValidationError, ValueError) as exc:
            return self._response(
                request_id,
                "rejected",
                ["shadow_validation_failed", exc.__class__.__name__],
                {"detail": str(exc)[:500]},
            )
        return self._response(request_id, "ok", ["shadow_only_no_enforcement"], result)

    # -- actions -------------------------------------------------------------
    #
    # Every handler receives the validated payload plus the (already gated)
    # request envelope, so an action can echo request-bound facts such as
    # `issued_at` without re-deriving or re-trusting them.

    def _action_capabilities(
        self, payload: dict[str, Any], envelope: dict[str, Any]
    ) -> dict[str, Any]:
        capabilities = detect_host_capabilities()
        return {"capabilities": capabilities}

    def _action_package(
        self, payload: dict[str, Any], envelope: dict[str, Any]
    ) -> dict[str, Any]:
        raw = load_package(self.package_path)
        package = parse_package(raw)
        return {
            "package": raw,
            "package_id": package.package_id,
            "package_version": package.package_version,
            "package_digest": package.package_digest,
        }

    def _action_plan(
        self, payload: dict[str, Any], envelope: dict[str, Any]
    ) -> dict[str, Any]:
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

    def _action_activate(
        self, payload: dict[str, Any], envelope: dict[str, Any]
    ) -> dict[str, Any]:
        for field in ("environment_id", "package", "placement", "decision"):
            if field not in payload:
                raise ValueError(f"activate request requires {field}")
        return self.adapter.shadow_activation(
            str(payload["environment_id"]),
            payload["package"],
            payload["placement"],
            payload["decision"],
        )

    def _action_terminate(
        self, payload: dict[str, Any], envelope: dict[str, Any]
    ) -> dict[str, Any]:
        for field in ("environment_id", "decision"):
            if field not in payload:
                raise ValueError(f"terminate request requires {field}")
        return self.adapter.shadow_termination(
            str(payload["environment_id"]),
            payload["decision"],
        )

    @staticmethod
    def _environment_id_list(value: Any, field: str) -> list[str]:
        """Coerce an Edge-supplied environment-id list, failing closed.

        Edge owns this set; AZ-06 only reports on it. A malformed set is
        rejected deterministically rather than silently reinterpreted, so a
        divergence report can never be manufactured by a sloppy payload.
        """

        if not isinstance(value, list):
            raise ValueError(f"{field} must be a list of environment ids")
        if not all(isinstance(item, str) and item for item in value):
            raise ValueError(f"{field} must contain only non-empty environment id strings")
        return list(value)

    def _health_summary(self) -> dict[str, Any]:
        """Small descriptive slice of the adapter health surface.

        A heartbeat is polled continuously, so it deliberately carries only
        what the Edge loop needs to reason about liveness and drift, not the
        full operator health payload.
        """

        health = self.adapter.health()
        return {
            "authority": "descriptive_only",
            "adapter_id": health["adapter_id"],
            "live_enabled": health["live_enabled"],
            "active_environments": health["active_environments"],
            "environment_count": len(health["environments"]),
            # Counts every one-shot ledger entry, including the shadow
            # request_id anti-replay records this endpoint writes per request.
            "consumed_decisions": health["consumed_decisions"],
        }

    def _action_heartbeat(
        self, payload: dict[str, Any], envelope: dict[str, Any]
    ) -> dict[str, Any]:
        """Answer an authenticated Edge liveness poll. Descriptive-only.

        Echoes Edge's own sequence/active set back so the Edge loop can detect
        a stale or crossed conversation, and reports this node's identity, a
        small health summary, and a server-side heartbeat sequence. Nothing
        here starts, stops, or authorizes anything.
        """

        edge_sequence = payload.get("edge_sequence")
        if edge_sequence is not None:
            if isinstance(edge_sequence, bool) or not isinstance(edge_sequence, int):
                raise ValueError("heartbeat edge_sequence must be an integer")
        edge_active = payload.get("edge_active_environment_ids")
        if edge_active is not None:
            edge_active = sorted(
                set(self._environment_id_list(edge_active, "edge_active_environment_ids"))
            )

        with self._heartbeat_lock:
            self._heartbeat_sequence += 1
            sequence = self._heartbeat_sequence

        return {
            "authority": "descriptive_only",
            "enforcement_applied": False,
            "node_id": self.node_id,
            "heartbeat_sequence": sequence,
            "edge_sequence": edge_sequence,
            "edge_active_environment_ids": edge_active,
            "health": self._health_summary(),
            "issued_at": envelope.get("issued_at"),
            "responded_at": _utcnow().isoformat(),
        }

    def _action_reconcile(
        self, payload: dict[str, Any], envelope: dict[str, Any]
    ) -> dict[str, Any]:
        """Report divergence against Edge's authoritative active set.

        Returns the adapter's divergence report verbatim plus the local state
        of every divergent environment, so Edge can decide what (if anything)
        to do. AZ-06 reconciles nothing on its own: acting on a divergence
        still requires a fresh Edge decision or the operator kill switch.
        """

        edge_active = self._environment_id_list(
            payload.get("edge_active_environment_ids"),
            "edge_active_environment_ids",
        )
        divergence = self.adapter.reconcile_with_edge(edge_active)
        divergent = sorted(
            set(divergence.get("local_only_active", []))
            | set(divergence.get("edge_only_active", []))
        )
        return {
            "authority": "descriptive_only",
            "enforcement_applied": False,
            "node_id": self.node_id,
            "divergence": divergence,
            "divergent_environment_ids": divergent,
            "divergent_environment_states": {
                environment_id: self.adapter.collect_status(environment_id)
                for environment_id in divergent
            },
            "issued_at": envelope.get("issued_at"),
            "responded_at": _utcnow().isoformat(),
        }


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
