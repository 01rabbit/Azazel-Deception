"""Docker Compose lifecycle adapter for AZ-06.

Live execution is disabled by default. Enabling it still does not grant runtime
authority: an accepted, unexpired, one-shot Azazel-Edge decision, matching
package/placement data, package-bounded resource budget, verified OCI
provenance, a trusted package-verification hook, and a statically safe Compose
asset exactly bound to the package manifest are all required.
"""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from azazel_fabric.deception_contracts import (
    DeceptionPackage,
    EnvironmentActivationDecision,
    EnvironmentEvent,
    EnvironmentTerminationDecision,
    PlacementPlan,
)

from azazel_deception.capabilities import detect_host_capabilities
from azazel_deception.package import parse_package
from azazel_deception.planner import build_placement_plan
from azazel_deception.runtime.policy import require_safe_compose
from azazel_deception.runtime.preflight import (
    PackageVerifier,
    SbomVerifier,
    require_compose_package_binding,
    require_sbom_attestation,
    require_supply_chain_backed_images,
    require_trusted_package_verifier,
)
from azazel_deception.runtime.state import RuntimeStateStore
from azazel_deception.runtime.transport import (
    DEFAULT_SIGNATURE_FIELD,
    DecisionAuthenticationError,
    DecisionAuthenticator,
    require_authenticated_decision,
)


class RuntimeGateError(RuntimeError):
    pass


# States in which a container may still be running, so the operator kill switch
# must (re)attempt the stop rather than trust the recorded state. Notably this
# includes the failure states a prior failed stop/termination leaves behind, so
# retrying the kill switch never reports "terminated" while a decoy is still up.
_MAYBE_RUNNING_STATES = frozenset({"active", "kill_switch_failed", "failed"})


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class DockerComposeAdapter:
    """Bounded Docker Compose adapter with explicit authority gates."""

    def __init__(
        self,
        compose_file: str | Path,
        state_root: str | Path,
        live_enabled: bool | None = None,
        package_verifier: PackageVerifier | None = None,
        sbom_verifier: SbomVerifier | None = None,
        decision_authenticator: DecisionAuthenticator | None = None,
        require_sbom_verification: bool = False,
        require_authenticated_decisions: bool = False,
    ) -> None:
        self.compose_file = Path(compose_file)
        self.state = RuntimeStateStore(state_root)
        self.package_verifier = package_verifier
        self.sbom_verifier = sbom_verifier
        self.decision_authenticator = decision_authenticator
        # Strict live posture: when set, the corresponding gate must be
        # configured, not merely honored if present. A trusted package verifier
        # is always mandatory regardless of these flags. Defaults preserve the
        # existing optional-gate behavior.
        self.require_sbom_verification = bool(require_sbom_verification)
        self.require_authenticated_decisions = bool(require_authenticated_decisions)
        if live_enabled is None:
            live_enabled = os.environ.get("AZAZEL_DECEPTION_LIVE", "0") == "1"
        self.live_enabled = bool(live_enabled)

    def _authenticate_decision(self, decision_data: dict[str, Any]) -> None:
        if self.require_authenticated_decisions and self.decision_authenticator is None:
            raise RuntimeGateError(
                "authenticated Edge decision required but no authenticator is configured"
            )
        try:
            require_authenticated_decision(decision_data, self.decision_authenticator)
        except DecisionAuthenticationError as exc:
            raise RuntimeGateError(str(exc)) from exc

    @staticmethod
    def _decision_contract(decision_data: dict[str, Any]) -> dict[str, Any]:
        # The transport signature is an envelope field, not part of the Fabric
        # decision contract (which forbids extra fields); strip it before
        # validating the canonical decision model.
        return {k: v for k, v in decision_data.items() if k != DEFAULT_SIGNATURE_FIELD}

    @property
    def adapter_id(self) -> str:
        return "docker_compose"

    def inspect_capabilities(self) -> dict[str, Any]:
        return detect_host_capabilities()

    def validate_package(self, raw_package: dict[str, Any]) -> DeceptionPackage:
        package = parse_package(raw_package)
        if package.runtime_requirements.runtime_adapter != self.adapter_id:
            raise RuntimeGateError("package requires a different runtime adapter")
        return package

    def validate_runtime_policy(self) -> None:
        try:
            require_safe_compose(self.compose_file)
        except (OSError, ValueError) as exc:
            raise RuntimeGateError(f"runtime isolation policy failed: {exc}") from exc

    def validate_supply_chain(
        self,
        package: DeceptionPackage,
        placement: PlacementPlan,
    ) -> None:
        if self.require_sbom_verification and self.sbom_verifier is None:
            raise RuntimeGateError(
                "SBOM verification required but no SBOM verifier is configured"
            )
        try:
            require_supply_chain_backed_images(package, placement)
            require_sbom_attestation(package, self.sbom_verifier)
        except (OSError, ValueError) as exc:
            raise RuntimeGateError(f"supply-chain policy failed: {exc}") from exc

    def validate_live_preflight(
        self,
        package: DeceptionPackage,
        placement: PlacementPlan,
    ) -> None:
        try:
            require_trusted_package_verifier(package, self.package_verifier)
            require_compose_package_binding(self.compose_file, package, placement)
        except (OSError, ValueError) as exc:
            raise RuntimeGateError(f"live preflight failed: {exc}") from exc

    def plan_deployment(
        self,
        raw_package: dict[str, Any],
        host_capabilities: dict[str, Any],
        requested_tier: str | None = None,
        edge_decision_id: str | None = None,
    ) -> dict[str, Any]:
        return build_placement_plan(
            raw_package,
            host_capabilities,
            requested_tier=requested_tier,
            edge_decision_id=edge_decision_id,
        )

    def _project_name(self, environment_id: str) -> str:
        safe = "".join(ch for ch in environment_id.lower() if ch.isalnum() or ch in "-_")
        if not safe:
            raise RuntimeGateError("environment_id cannot produce an empty compose project name")
        return f"az06-{safe}"[:63]

    def _compose(self, environment_id: str, *args: str) -> subprocess.CompletedProcess[str]:
        if not self.compose_file.exists():
            raise RuntimeGateError(f"compose file not found: {self.compose_file}")
        command = [
            "docker",
            "compose",
            "-f",
            str(self.compose_file),
            "-p",
            self._project_name(environment_id),
            *args,
        ]
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=60,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeGateError(f"docker compose invocation failed: {exc}") from exc
        if result.returncode != 0:
            raise RuntimeGateError(
                f"docker compose failed with rc={result.returncode}: {(result.stdout or '').strip()[:1000]}"
            )
        return result

    @staticmethod
    def _assert_verified_images(
        package: DeceptionPackage,
        placement: PlacementPlan,
    ) -> None:
        """Require verified OCI state for every component selected to run.

        Optional package components that are not part of the selected deployment
        tier do not participate in the live materialization and therefore do not
        block that placement. Required/selected components always fail closed.
        """

        selected = set(placement.component_ids)
        manifests = {component.component_id: component for component in package.components}
        missing = sorted(selected - set(manifests))
        if missing:
            raise RuntimeGateError(
                "placement references components absent from package: " + ", ".join(missing)
            )
        unverified = sorted(
            component_id
            for component_id in selected
            if not manifests[component_id].image.verified
        )
        if unverified:
            raise RuntimeGateError(
                "live activation requires verified OCI provenance for every selected component: "
                + ", ".join(unverified)
            )

    @staticmethod
    def _assert_activation_binding(
        package: DeceptionPackage,
        placement: PlacementPlan,
        decision: EnvironmentActivationDecision,
    ) -> None:
        if decision.status not in {"accepted", "modified"}:
            raise RuntimeGateError(f"activation decision is not executable: {decision.status}")
        if decision.expires_at <= _utcnow():
            raise RuntimeGateError("activation decision is expired")
        if decision.package_id != package.package_id or decision.package_digest != package.package_digest:
            raise RuntimeGateError("activation decision package binding mismatch")
        if decision.target_node_id != placement.node_id:
            raise RuntimeGateError("activation decision node binding mismatch")
        if decision.selected_tier != placement.selected_tier:
            raise RuntimeGateError("activation decision tier binding mismatch")
        if placement.edge_decision_id != decision.decision_id:
            raise RuntimeGateError("placement is not bound to the activation decision")
        if not decision.budget.is_within(
            package.maximum_budget,
            require_bounded_bandwidth=True,
        ):
            raise RuntimeGateError("Edge decision budget exceeds package maximum budget")

        tiers = {tier.tier_id: tier for tier in package.deployment_tiers}
        tier = tiers.get(placement.selected_tier)
        if tier is None:
            raise RuntimeGateError("placement references an unknown package tier")
        if not tier.minimum.is_within(decision.budget):
            raise RuntimeGateError("Edge decision budget is below selected tier minimum")

    def _consume_decision(self, decision_id: str, kind: str, environment_id: str) -> None:
        consumed = self.state.consume_decision(
            decision_id,
            {
                "decision_id": decision_id,
                "kind": kind,
                "environment_id": environment_id,
                "consumed_at": _utcnow().isoformat(),
            },
        )
        if not consumed:
            raise RuntimeGateError(f"Edge decision already consumed: {decision_id}")

    def _record_failure(
        self,
        *,
        environment_id: str,
        package_id: str,
        node_id: str,
        decision_id: str,
        stage: str,
        error: Exception,
    ) -> None:
        observed_at = _utcnow()
        state = {
            "environment_id": environment_id,
            "state": "failed",
            "package_id": package_id,
            "node_id": node_id,
            "decision_id": decision_id,
            "failure_stage": stage,
            "failure_type": error.__class__.__name__,
            "failed_at": observed_at.isoformat(),
        }
        self.state.write(environment_id, state)
        event = EnvironmentEvent(
            event_id=f"{environment_id}-{stage}-failure",
            environment_id=environment_id,
            package_id=package_id,
            node_id=node_id,
            event_type="failure",
            observed_at=observed_at,
            evidence_refs=[],
            metadata={
                "decision_id": decision_id,
                "stage": stage,
                "error_type": error.__class__.__name__,
            },
        )
        self.state.append_evidence(environment_id, event.model_dump(mode="json"))

    def activate_environment(
        self,
        environment_id: str,
        raw_package: dict[str, Any],
        placement_data: dict[str, Any],
        decision_data: dict[str, Any],
    ) -> dict[str, Any]:
        package = self.validate_package(raw_package)
        placement = PlacementPlan.model_validate(placement_data)
        decision = EnvironmentActivationDecision.model_validate(
            self._decision_contract(decision_data)
        )

        if not self.live_enabled:
            return {
                "environment_id": environment_id,
                "status": "disabled",
                "live_execution": False,
                "reason": "AZAZEL_DECEPTION_LIVE is not enabled",
            }

        self._authenticate_decision(decision_data)
        self._assert_activation_binding(package, placement, decision)
        self._assert_verified_images(package, placement)
        self.validate_supply_chain(package, placement)
        self.validate_runtime_policy()
        self.validate_live_preflight(package, placement)

        existing = self.state.read(environment_id)
        if existing and existing.get("state") not in {"reset", "terminated", "failed"}:
            raise RuntimeGateError("environment already has non-terminal runtime state")

        self._consume_decision(decision.decision_id, "activation", environment_id)
        try:
            self._compose(environment_id, "up", "-d", "--remove-orphans")
        except RuntimeGateError as exc:
            self._record_failure(
                environment_id=environment_id,
                package_id=package.package_id,
                node_id=placement.node_id,
                decision_id=decision.decision_id,
                stage="activation",
                error=exc,
            )
            raise

        event = EnvironmentEvent(
            event_id=f"{environment_id}-activated",
            environment_id=environment_id,
            package_id=package.package_id,
            node_id=placement.node_id,
            event_type="activated",
            observed_at=_utcnow(),
            evidence_refs=[],
            metadata={
                "decision_id": decision.decision_id,
                "selected_tier": placement.selected_tier,
                "runtime_adapter": self.adapter_id,
            },
        )
        state = {
            "environment_id": environment_id,
            "state": "active",
            "package_id": package.package_id,
            "package_digest": package.package_digest,
            "node_id": placement.node_id,
            "decision_id": decision.decision_id,
            "selected_tier": placement.selected_tier,
            "activated_at": event.observed_at.isoformat(),
        }
        self.state.write(environment_id, state)
        self.state.append_evidence(environment_id, event.model_dump(mode="json"))
        return {"environment_id": environment_id, "status": "active", "live_execution": True}

    def collect_status(self, environment_id: str) -> dict[str, Any]:
        state = self.state.read(environment_id)
        return state or {"environment_id": environment_id, "state": "absent"}

    def terminate_environment(
        self,
        environment_id: str,
        decision_data: dict[str, Any],
    ) -> dict[str, Any]:
        decision = EnvironmentTerminationDecision.model_validate(
            self._decision_contract(decision_data)
        )
        self._authenticate_decision(decision_data)
        if decision.environment_id != environment_id:
            raise RuntimeGateError("termination decision environment binding mismatch")
        if decision.expires_at <= _utcnow():
            raise RuntimeGateError("termination decision is expired")

        self._consume_decision(decision.decision_id, "termination", environment_id)
        current = self.state.read(environment_id)
        if current is None:
            return {"environment_id": environment_id, "status": "absent"}

        if self.live_enabled and current.get("state") == "active":
            try:
                self._compose(environment_id, "down", "--remove-orphans")
            except RuntimeGateError as exc:
                self._record_failure(
                    environment_id=environment_id,
                    package_id=str(current.get("package_id") or "unknown"),
                    node_id=str(current.get("node_id") or "unknown"),
                    decision_id=decision.decision_id,
                    stage="termination",
                    error=exc,
                )
                raise

        current["state"] = "terminated"
        current["terminated_at"] = _utcnow().isoformat()
        current["termination_decision_id"] = decision.decision_id
        current["termination_reason"] = decision.reason
        self.state.write(environment_id, current)
        event = EnvironmentEvent(
            event_id=f"{environment_id}-terminated",
            environment_id=environment_id,
            package_id=str(current.get("package_id") or "unknown"),
            node_id=str(current.get("node_id") or "unknown"),
            event_type="terminated",
            observed_at=_utcnow(),
            evidence_refs=list(decision.evidence_refs),
            metadata={"decision_id": decision.decision_id, "reason": decision.reason},
        )
        self.state.append_evidence(environment_id, event.model_dump(mode="json"))
        return {"environment_id": environment_id, "status": "terminated"}

    def emergency_stop(
        self,
        environment_id: str,
        *,
        operator: str,
        reason: str,
    ) -> dict[str, Any]:
        """Operator kill switch: halt an environment without an Edge decision.

        This is a deliberate operator override, not an Edge-authorized path, so
        it requires no activation/termination decision and consumes none. It is
        fail-safe: the intent is always recorded as evidence, the container is
        best-effort stopped, and a failure to stop is surfaced (state
        ``kill_switch_failed``) rather than silently swallowed so the operator
        knows the workload may still be running.
        """

        if not operator or not reason:
            raise RuntimeGateError("operator kill switch requires operator and reason")

        observed_at = _utcnow()
        current = self.state.read(environment_id) or {}
        package_id = str(current.get("package_id") or "unknown")
        node_id = str(current.get("node_id") or "unknown")

        def _emit(event_kind: str, event_type: str, **extra: Any) -> None:
            # Kill-switch semantics live in metadata; the wire-contract
            # event_type vocabulary (owned by Fabric) is not extended.
            self.state.append_evidence(
                environment_id,
                EnvironmentEvent(
                    event_id=f"{environment_id}-{event_kind}",
                    environment_id=environment_id,
                    package_id=package_id,
                    node_id=node_id,
                    event_type=event_type,
                    observed_at=observed_at,
                    evidence_refs=[],
                    metadata={
                        "kind": "operator_kill_switch",
                        "operator": operator,
                        "reason": reason,
                        **extra,
                    },
                ).model_dump(mode="json"),
            )

        if self.live_enabled and current.get("state") in _MAYBE_RUNNING_STATES:
            try:
                self._compose(environment_id, "down", "--remove-orphans")
            except RuntimeGateError as exc:
                _emit("kill-switch-failed", "failure", error_type=exc.__class__.__name__)
                failed = {
                    **current,
                    "state": "kill_switch_failed",
                    "kill_switch_operator": operator,
                    "kill_switch_reason": reason,
                    "kill_switch_error": exc.__class__.__name__,
                    "kill_switch_at": observed_at.isoformat(),
                }
                self.state.write(environment_id, failed)
                raise

        _emit("operator-kill-switch", "terminated")
        stopped = {
            **current,
            "environment_id": environment_id,
            "state": "terminated",
            "termination_kind": "operator_kill_switch",
            "kill_switch_operator": operator,
            "kill_switch_reason": reason,
            "terminated_at": observed_at.isoformat(),
        }
        self.state.write(environment_id, stopped)
        return {
            "environment_id": environment_id,
            "status": "terminated",
            "termination_kind": "operator_kill_switch",
        }

    def health(self) -> dict[str, Any]:
        """Operator-facing status/health surface. Descriptive-only.

        Reports adapter configuration and local runtime state. It authorizes
        nothing and never starts or stops a workload.
        """

        try:
            capabilities = detect_host_capabilities()
            architecture = capabilities.get("architecture")
            docker_available = bool(
                capabilities.get("runtime_adapters", {}).get("docker_compose")
            )
        except Exception:
            architecture = None
            docker_available = False

        environments = [
            {"environment_id": env_id, "state": self._environment_state(env_id)}
            for env_id in self.state.list_environments()
        ]
        return {
            "authority": "descriptive_only",
            "adapter_id": self.adapter_id,
            "live_enabled": self.live_enabled,
            "package_verifier_configured": self.package_verifier is not None,
            "sbom_verifier_configured": self.sbom_verifier is not None,
            "decision_authenticator_configured": self.decision_authenticator is not None,
            "require_sbom_verification": self.require_sbom_verification,
            "require_authenticated_decisions": self.require_authenticated_decisions,
            "compose_file": str(self.compose_file),
            "compose_present": self.compose_file.exists(),
            "architecture": architecture,
            "docker_available": docker_available,
            "environments": environments,
            "active_environments": [
                item["environment_id"] for item in environments if item["state"] == "active"
            ],
            "consumed_decisions": self.state.consumed_decision_count(),
        }

    def reset_environment(self, environment_id: str) -> dict[str, Any]:
        current = self.state.read(environment_id)
        if current and current.get("state") == "active":
            raise RuntimeGateError("active environment must be terminated before reset")

        evidence = str(self.state.evidence_path(environment_id))
        reset_event = {
            "schema_version": "environment-event/v0.1",
            "event_id": f"{environment_id}-reset-completed",
            "environment_id": environment_id,
            "package_id": str((current or {}).get("package_id") or "unknown"),
            "node_id": str((current or {}).get("node_id") or "unknown"),
            "event_type": "reset_completed",
            "observed_at": _utcnow().isoformat(),
            "evidence_refs": [evidence],
            "metadata": {},
        }
        self.state.append_evidence(environment_id, reset_event)
        self.state.clear_runtime_state(environment_id)
        return {
            "environment_id": environment_id,
            "status": "reset",
            "evidence_preserved": True,
            "evidence_path": evidence,
        }

    def verify_evidence(self, environment_id: str) -> bool:
        """Return True iff the environment's evidence hash chain is intact."""

        return self.state.verify_evidence_chain(environment_id)

    def _environment_state(self, environment_id: str) -> str | None:
        """Read an environment's state, tolerating a corrupt state file.

        A single malformed/partially-written state file must not abort the
        descriptive status/reconciliation surfaces operators rely on during an
        incident; it is reported as ``"unreadable"`` instead of crashing.
        """

        try:
            return (self.state.read(environment_id) or {}).get("state")
        except (OSError, ValueError, json.JSONDecodeError):
            return "unreadable"

    def reconcile_with_edge(
        self,
        edge_active_environment_ids: Iterable[str],
    ) -> dict[str, Any]:
        """Report divergence between local runtime state and Edge's authority.

        Descriptive-only: Edge owns the authoritative set of environments that
        should be running. This compares it to local state and reports
        divergence — it authorizes nothing and terminates nothing. Acting on a
        divergence still requires an Edge decision or the operator kill switch.

        * ``local_only_active`` — running locally but not in Edge's active set
          (unauthorized/revoked; candidates for the kill switch).
        * ``edge_only_active`` — Edge expects active but not active locally
          (missing/failed materialization).
        """

        edge_active = {str(env_id) for env_id in edge_active_environment_ids}
        local_states = {
            env_id: self._environment_state(env_id)
            for env_id in self.state.list_environments()
        }
        local_active = {env for env, state in local_states.items() if state == "active"}

        local_only_active = sorted(local_active - edge_active)
        edge_only_active = sorted(edge_active - local_active)
        return {
            "authority": "descriptive_only",
            "consistent": not local_only_active and not edge_only_active,
            "local_active": sorted(local_active),
            "edge_active": sorted(edge_active),
            "local_only_active": local_only_active,
            "edge_only_active": edge_only_active,
        }

    def export_evidence(self, environment_id: str) -> list[dict[str, Any]]:
        path = self.state.evidence_path(environment_id)
        if not path.exists():
            return []
        events: list[dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                events.append(json.loads(line))
        return events
