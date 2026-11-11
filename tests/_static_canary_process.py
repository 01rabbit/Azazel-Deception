"""Test-only fixed loopback canary process; never imported by product code.

Compose execution and supply-chain verification are TEST DOUBLES. Real sockets,
registry matching and evidence export are exercised; container materialization,
network isolation and genuine Edge authorization are not established here.
Control is inherited stdin/stdout, never an HTTP management endpoint.
"""
from __future__ import annotations

import json
import sys
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

from azazel_fabric.deception_contracts import PlacementPlan

from azazel_deception.credentials.canaries import CanaryRegistry, CanaryScope, record_canary_touch, synthetic_openapi
from azazel_deception.package import load_package, parse_package
from azazel_deception.runtime.compose import DockerComposeAdapter
from azazel_deception.runtime.observation_export import export_observations
from azazel_deception.runtime.transport import HmacDecisionAuthenticator, sign_decision
from tests.test_strict_live_posture import COMPOSE, KEY, PACKAGE, _decision, _host

ENVIRONMENT = "static-process-test"
TTL = 60


class LoopbackComposeDouble(DockerComposeAdapter):
    """Retain the real admission gates; replace only the execution boundary."""

    def __init__(self, state_root, mode):
        super().__init__(
            COMPOSE, state_root, live_enabled=True,
            package_verifier=None if mode == "no-verifier" else lambda _: True,
            sbom_verifier=lambda _: True,
            decision_authenticator=HmacDecisionAuthenticator(KEY),
            require_authenticated_decisions=True, require_sbom_verification=True,
        )
        self.server = None
        self.thread = None
        self.bind_count = 0
        self.lock = threading.Lock()
        self.now = datetime.now(timezone.utc)
        self.seq = 0

    def _compose(self, environment_id, *args):
        if args[0] == "up":
            # Deliberately not Docker and not a production adapter. This line
            # can only be reached after the existing activation gates pass.
            owner = self

            class Handler(BaseHTTPRequestHandler):
                def log_message(self, *args):
                    pass  # raw request paths contain secrets

                def do_GET(self):
                    with owner.lock:
                        if self.path == "/openapi.json":
                            try:
                                owner.registry.present(owner.issued.lure_id, scope=owner.scope,
                                                       evidence_ref="presentation:loopback", as_of=owner.now.isoformat())
                            except ValueError:
                                self.send_error(410)
                                return
                            data = synthetic_openapi(owner.issued).encode()
                            self.send_response(200)
                            self.send_header("Content-Type", "application/json")
                            self.send_header("Content-Length", str(len(data)))
                            self.end_headers()
                            self.wfile.write(data)
                            return
                        prefix = "/__azazel_canary__/"
                        if self.path.startswith(prefix):
                            owner.seq += 1
                            result = record_canary_touch(
                                owner.observer, owner.registry, self.path[len(prefix):], scope=owner.scope,
                                event_id=f"request-{owner.seq}", evidence_ref=f"loopback:{owner.seq}",
                                as_of=owner.now.isoformat(),
                            )
                            self.send_response(204 if result["accepted"] else 404)
                            self.send_header("Content-Length", "0")
                            self.end_headers()
                            return
                        self.send_error(404)

            class BoundedServer(HTTPServer):
                def get_request(self):
                    connection, address = super().get_request()
                    connection.settimeout(2)
                    return connection, address

            # Bind only an OS-chosen IPv4 loopback port, never configurable.
            self.server = BoundedServer(("127.0.0.1", 0), Handler)
            self.server.timeout = 1
            self.bind_count += 1
            # No requests are served until activate_environment returns and
            # the observer has been constructed by main().
        elif args[0] == "down":
            self.close()
        else:
            raise AssertionError("unexpected test-double execution")

    def start_serving(self):
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        if self.server is not None:
            if self.thread is not None:
                self.server.shutdown()
                self.thread.join(timeout=5)
                if self.thread.is_alive():
                    raise RuntimeError("loopback thread failed to stop")
                self.thread = None
            self.server.server_close()
            self.server = None


def emit(value):
    print(json.dumps(value), flush=True)


def main():
    state_root, mode, decision_id = sys.argv[1:]
    adapter = LoopbackComposeDouble(state_root, mode)
    raw = load_package(PACKAGE)
    plan = adapter.plan_deployment(raw, _host(), "lite", edge_decision_id=decision_id)
    decision = _decision(raw, plan)
    decision["decision_id"] = decision_id
    if mode == "expired":
        decision["effective_at"] = (adapter.now - timedelta(minutes=2)).isoformat()
        decision["expires_at"] = (adapter.now - timedelta(minutes=1)).isoformat()
    if mode == "wrong-package":
        decision["package_digest"] = "sha256:" + "f" * 64
    signed = sign_decision(decision, KEY)
    if mode == "unsigned":
        signed = decision
    if mode == "forged":
        signed = sign_decision(decision, "wrong-test-key")
    try:
        # Scope comes from the parsed fixture package, not a synthetic digest.
        package = parse_package(raw)
        adapter.scope = CanaryScope(package.package_id, package.package_digest.removeprefix("sha256:"),
                                    ENVIRONMENT, "test-boot", decision_id, "intranet-web-http")
        adapter.registry = CanaryRegistry(adapter.scope)
        adapter.issued = adapter.registry.issue(issued_at=adapter.now.isoformat(), ttl_seconds=TTL)
        try:
            adapter.activate_environment(ENVIRONMENT, raw, plan, signed)
        except Exception as exc:
            emit({"status": "refused", "error_type": type(exc).__name__, "reason": str(exc),
                  "bind_count": adapter.bind_count,
                  "consumed": adapter.state.decision_consumed(decision_id)})
            return
        adapter.observer = adapter.make_observer(ENVIRONMENT, package, PlacementPlan.model_validate(plan))
        adapter.start_serving()
        emit({"status": "ready", "host": adapter.server.server_address[0],
              "port": adapter.server.server_address[1], "bind_count": adapter.bind_count,
              "scope": dict(adapter.scope.__dict__)})
        for line in sys.stdin:
            command = json.loads(line)
            with adapter.lock:
                action = command["action"]
                if action == "export":
                    emit({"observations": export_observations(adapter.state, ENVIRONMENT),
                          "chain_verified": adapter.verify_evidence(ENVIRONMENT)})
                elif action == "expire":
                    adapter.now += timedelta(seconds=TTL)
                    emit({"clock_advanced_for_test": True})
                elif action == "reset-active":
                    try:
                        adapter.reset_environment(ENVIRONMENT)
                    except Exception as exc:
                        emit({"error_type": type(exc).__name__})
                elif action == "reset":
                    # Shutdown must not hold the handler's lock while joining.
                    pass
                elif action == "probe":
                    emit(adapter.registry.touch(command["token"], scope=adapter.scope, event_id="control-probe",
                                                evidence_ref="control:probe", as_of=adapter.now.isoformat()))
                else:
                    raise ValueError("unknown test command")
            if action == "reset":
                adapter.emergency_stop(ENVIRONMENT, operator="test-parent", reason="test-reset")
                with adapter.lock:
                    registry_reset = adapter.registry.reset(as_of=adapter.now.isoformat())
                    runtime_reset = adapter.reset_environment(ENVIRONMENT)
                    emit({"registry": registry_reset, "runtime": runtime_reset,
                          "listener_closed": adapter.server is None})
    finally:
        adapter.close()  # EOF, assertion failures and interruptions all stop it


if __name__ == "__main__":
    main()
