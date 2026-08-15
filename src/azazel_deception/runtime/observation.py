"""Incremental attacker-interaction emitter for AZ-06.

While an engagement is live, AZ-06 records *facts* about attacker interaction —
what was touched, how the attacker reacted, how much resource was spent — to the
tamper-evident evidence chain, so Azazel-Knowledge can analyze deception
effectiveness. The wire shape is owned by Fabric
(`azazel_fabric.deception_contracts.InteractionObservation`); this module only
builds and appends those facts.

AZ-06 does not score its own effectiveness. The observer refuses any
belief/deception-verdict field (`assert_no_effectiveness_verdict`) — the
layer-4 effectiveness judgement is Knowledge's advisory output, not an observed
fact. Confounder tagging (scanner noise, internal health checks, host-capacity
effects) is carried on each observation so a consumer can subtract it before
claiming effectiveness.

This module authorizes nothing and starts nothing; it appends evidence.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from azazel_fabric.deception_contracts import (
    DeceptionPackage,
    InteractionObservation,
    PlacementPlan,
    RuntimeContext,
    assert_no_effectiveness_verdict,
)

from azazel_deception.runtime.state import RuntimeStateStore


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def build_runtime_context(
    package: DeceptionPackage,
    placement: PlacementPlan,
    *,
    resource_saturation: dict[str, float] | None = None,
    capability_drift: list[str] | None = None,
) -> RuntimeContext:
    """Derive the descriptive runtime context that travels with observations.

    Records which components are active vs omitted so a consumer can separate
    narrative effectiveness from host-capacity/runtime effects.
    """

    active = list(placement.component_ids)
    omitted = [c.component_id for c in package.components if c.component_id not in set(active)]
    return RuntimeContext(
        selected_tier=placement.selected_tier,
        architecture=placement.architecture,
        runtime_adapter=placement.runtime_adapter,
        active_components=active,
        omitted_components=omitted,
        resource_saturation=resource_saturation,
        capability_drift=capability_drift or [],
    )


class InteractionObserver:
    """Builds and records fact-only interaction observations for one environment."""

    def __init__(
        self,
        state: RuntimeStateStore,
        *,
        environment_id: str,
        package_id: str,
        node_id: str,
        runtime_context: RuntimeContext | None = None,
    ) -> None:
        if not environment_id or not package_id or not node_id:
            raise ValueError("observer requires environment_id, package_id, node_id")
        self.state = state
        self.environment_id = environment_id
        self.package_id = package_id
        self.node_id = node_id
        self.runtime_context = runtime_context
        self._seq = 0

    def _next_observation_id(self) -> str:
        self._seq += 1
        return f"{self.environment_id}-obs-{self._seq:04d}"

    def record(
        self,
        *,
        observation_class: str,
        surface: str,
        reaction_kind: str | None = None,
        lure_id: str | None = None,
        first_contact_latency_ms: int | None = None,
        dwell_ms: int | None = None,
        attempt_count: int | None = None,
        confounder_tags: list[str] | None = None,
        evidence_refs: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        observed_at: datetime | None = None,
    ) -> InteractionObservation:
        """Record one fact-only observation and append it to the evidence chain.

        Fails closed if the caller tries to smuggle a belief/effectiveness
        verdict through ``metadata`` — AZ-06 emits facts, not verdicts.
        """

        metadata = dict(metadata or {})
        # AZ-06 never asserts belief/deception success. Reject verdict fields
        # anywhere in the caller-supplied payload before building the fact.
        assert_no_effectiveness_verdict(
            {"metadata": metadata, "surface": surface, "reaction_kind": reaction_kind}
        )

        observation = InteractionObservation(
            observation_id=self._next_observation_id(),
            environment_id=self.environment_id,
            package_id=self.package_id,
            node_id=self.node_id,
            observed_at=observed_at or _utcnow(),
            observation_class=observation_class,
            surface=surface,
            reaction_kind=reaction_kind,
            lure_id=lure_id,
            first_contact_latency_ms=first_contact_latency_ms,
            dwell_ms=dwell_ms,
            attempt_count=attempt_count,
            confounder_tags=confounder_tags or [],
            runtime_context=self.runtime_context,
            evidence_refs=evidence_refs or [],
            metadata=metadata,
        )
        self.state.append_evidence(self.environment_id, observation.model_dump(mode="json"))
        return observation
