"""Docker Compose lifecycle adapter for AZ-06.

Live execution is disabled by default.  Enabling it still does not grant
runtime authority: an accepted, unexpired Azazel-Edge activation decision,
matching package/placement data, and verified OCI provenance are all required.
"""

from __future__ import annotations

import json
import os
import subprocess
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

from azazel_deception.package import PackageValidationError, parse_package
from azazel_deception.planner import build_placement_plan
from azazel_deception.runtime.state import RuntimeStateStore


class RuntimeGateError(RuntimeError):
    pass


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class DockerComposeAdapter:
    """Bounded Docker Compose adapter with explicit authority gates."""

    def __init__(
        self,
        compose_file: str | Path,
        state_root: str | Path,
        live_enabled: bool | None = None,
    ) -> None:
        self.compose_file = Path(compose_file)
        self.state = RuntimeStateStore(state_root)
        if live_enabled is None:
            live_enabled = os.environ.get("AZAZEL_DECEPTION_LIVE", "0") == "1"
        self.live_enabled = bool(live_enabled)

    @property
    def adapter_id(self) -> str:
        return "docker_compose"

    def validate_package(self, raw_package: dict[str, Any]) -> DeceptionPackage:
        package = parse_package(raw_package)
        if package.runtime_requirements.runtime_adapter != self.adapter_id:
            raise RuntimeGateError("package requires a different runtime adapter")
        return package

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
    def _assert_verified_images(package: DeceptionPackage) -> None:
        unverified = [
            component.component_id
            for component in package.components
            if not component.image.verified
        ]
        if unverified:
            raise RuntimeGateError(
                "live activation requires verified OCI provenance for every component: "
                + ", ".join(sorted(unverified))
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

    def activate_environment(
        self,
        environment_id: str,
        raw_package: dict[str, Any],
        placement_data: dict[str, Any],
        decision_data: dict[str, Any],
    ) -> dict[str, Any]:
        package = self.validate_package(raw_package)
        placement = PlacementPlan.model_validate(placement_data)
        decision = EnvironmentActivationDecision.model_validate(decision_data)

        if not self.live_enabled:
            return {
                "environment_id": environment_id,
                "status": "disabled",
                "live_execution": False,
                "reason": "AZAZEL_DECEPTION_LIVE is not enabled",
            }

        self._assert_activation_binding(package, placement, decision)
        self._assert_verified_images(package)

        existing = self.state.read(environment_id)
        if existing and existing.get("state") not in {"reset", "terminated", "failed"}:
            raise RuntimeGateError("environment already has non-terminal runtime state")

        self._compose(environment_id, "up", "-d", "--remove-orphans")
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
        decision = EnvironmentTerminationDecision.model_validate(decision_data)
        if decision.environment_id != environment_id:
            raise RuntimeGateError("termination decision environment binding mismatch")

        current = self.state.read(environment_id)
        if current is None:
            return {"environment_id": environment_id, "status": "absent"}

        if self.live_enabled and current.get("state") == "active":
            self._compose(environment_id, "down", "--remove-orphans")

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

    def export_evidence(self, environment_id: str) -> list[dict[str, Any]]:
        path = self.state.evidence_path(environment_id)
        if not path.exists():
            return []
        events: list[dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                events.append(json.loads(line))
        return events
