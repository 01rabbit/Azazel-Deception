"""Isolation-drift observation for AZ-06 (SO-08, detection half).

SO-08 reads: *Deception isolation drift — detect within 2 seconds and withdraw
attacker-route exposure within 5 seconds, independent of runtime cleanup.* The
two halves have different owners, and this module is only the first one:

* **Detection is observation, and it is AZ-06's.** A drift is a fact about the
  environment AZ-06 materialized; recording it into AZ-06's tamper-evident
  evidence chain is the same kind of act as recording an activation.
* **Withdrawal is enforcement, and it is not AZ-06's.** Taking an attacker
  route away is an enforcement action that goes through Azazel-Edge's
  authority path. Nothing here withdraws, blocks, tears down, or asks anything
  to. A recorded drift is a fact for Edge to act on, not a directive.

The drift kinds are declared once, in :data:`DRIFT_KINDS`. Each one is the
*runtime* counterpart of an isolation invariant the static Compose policy
(`runtime/policy.py`) already refuses at plan time, so the vocabulary is the
policy's rather than a new one:

==========================  =================================================
drift kind                  static policy violation it is the runtime twin of
==========================  =================================================
``route_to_protected``      ``network_not_internal`` / ``non_internal_network``
``published_port``          ``published_ports``
``capability_regranted``    ``capability_readdition_forbidden``
==========================  =================================================

The invariant is absolute, not a diff against a baseline: the policy tolerates
zero published ports, zero re-added capabilities and no non-internal network,
so *any* finding of a declared kind is drift. A sampler reports findings; this
module turns the ones it has not already recorded into evidence.

Fabric has no dedicated isolation-drift record. The drift is therefore written
as Fabric's ``EnvironmentEvent`` with ``event_type="failure"`` — an isolation
invariant failing is a runtime failure — and ``metadata.stage`` set to
:data:`DRIFT_STAGE`. It deliberately does **not** reuse
``InteractionObservation``: that record means "the attacker touched
something", and ``observation_export`` relays it to Knowledge as effectiveness
input. A route that appeared is not attacker interaction.

This module authorizes nothing, starts nothing and changes no runtime state
file; it appends evidence.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from azazel_fabric.deception_contracts import EnvironmentEvent

from azazel_deception.runtime.state import RuntimeStateStore

#: The declared SO-08 drift kinds, in the order a run reports them. This tuple
#: is the single statement of the list: the harness, the record validator and
#: the documentation all read it from here.
DRIFT_KINDS: tuple[str, ...] = (
    "route_to_protected",
    "published_port",
    "capability_regranted",
)

#: Each drift kind's static-policy twin (see the module docstring).
DRIFT_KIND_POLICY_TWIN: Mapping[str, str] = {
    "route_to_protected": "network_not_internal",
    "published_port": "published_ports",
    "capability_regranted": "capability_readdition_forbidden",
}

#: ``metadata.stage`` of an isolation-drift evidence record.
DRIFT_STAGE = "isolation_drift"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _require_snapshot(snapshot: Mapping[str, Any]) -> dict[str, frozenset[str]]:
    """Validate a sampler snapshot, fail-closed.

    Every declared kind must be present. A sampler that says nothing about a
    kind has not observed it, and "not observed" must never read as "no
    drift" — so a missing kind is a refusal, not an empty set.
    """

    if not isinstance(snapshot, Mapping):
        raise ValueError("isolation snapshot must be a mapping of drift kind to findings")
    unknown = sorted(set(snapshot) - set(DRIFT_KINDS))
    if unknown:
        raise ValueError(f"isolation snapshot names undeclared drift kinds: {unknown}")
    missing = [kind for kind in DRIFT_KINDS if kind not in snapshot]
    if missing:
        raise ValueError(f"isolation snapshot does not cover drift kinds: {missing}")
    result: dict[str, frozenset[str]] = {}
    for kind in DRIFT_KINDS:
        findings = snapshot[kind]
        if isinstance(findings, (str, bytes)):
            raise ValueError(f"{kind}: findings must be a collection of strings")
        items = frozenset(findings)
        for item in items:
            if not isinstance(item, str) or not item.strip() or item != item.strip():
                raise ValueError(f"{kind}: each finding must be a non-empty trimmed string")
        result[kind] = items
    return result


class IsolationDriftObserver:
    """Records newly observed isolation drift into the evidence chain.

    A finding is recorded once when it appears. When a sampler stops reporting
    it, it leaves the active set silently, so the same drift re-appearing
    later is recorded again. Its disappearance is *not* recorded: AZ-06 did
    not cause it, and a record of it would read as a withdrawal AZ-06 has no
    authority to perform.
    """

    def __init__(
        self,
        state: RuntimeStateStore,
        *,
        environment_id: str,
        package_id: str,
        node_id: str,
    ) -> None:
        if not environment_id or not package_id or not node_id:
            raise ValueError("observer requires environment_id, package_id, node_id")
        self.state = state
        self.environment_id = environment_id
        self.package_id = package_id
        self.node_id = node_id
        self._active: dict[str, frozenset[str]] = {kind: frozenset() for kind in DRIFT_KINDS}
        self._seq = 0

    def active_findings(self) -> dict[str, frozenset[str]]:
        """The findings currently considered present, per kind (a copy)."""

        return dict(self._active)

    def observe(
        self,
        snapshot: Mapping[str, Any],
        *,
        observed_at: datetime | None = None,
    ) -> list[EnvironmentEvent]:
        """Record every finding in ``snapshot`` not already active.

        Returns the events appended, in :data:`DRIFT_KINDS` order and then
        finding order. Each is appended before the next is built, so a crash
        part-way leaves a valid chain naming what was recorded.
        """

        findings = _require_snapshot(snapshot)
        recorded: list[EnvironmentEvent] = []
        for kind in DRIFT_KINDS:
            current = findings[kind]
            for finding in sorted(current - self._active[kind]):
                self._seq += 1
                event = EnvironmentEvent(
                    event_id=f"{self.environment_id}-isolation-drift-{self._seq:04d}",
                    environment_id=self.environment_id,
                    package_id=self.package_id,
                    node_id=self.node_id,
                    event_type="failure",
                    observed_at=observed_at or _utcnow(),
                    evidence_refs=[],
                    metadata={
                        "stage": DRIFT_STAGE,
                        "drift_kind": kind,
                        "policy_twin": DRIFT_KIND_POLICY_TWIN[kind],
                        "finding": finding,
                        "authority": "descriptive_only",
                    },
                )
                self.state.append_evidence(self.environment_id, event.model_dump(mode="json"))
                recorded.append(event)
            self._active[kind] = current
        return recorded


def recorded_drift(state: RuntimeStateStore, environment_id: str) -> list[dict[str, Any]]:
    """Return the isolation-drift records in an environment's evidence chain.

    Read side only, in append order, each with its ``_evidence_seq``. A line
    that does not parse is skipped rather than raised on, because a reader may
    race the writer's final line; chain integrity is a separate question that
    :meth:`RuntimeStateStore.verify_evidence_chain` answers.
    """

    path = state.evidence_path(environment_id)
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict):
            continue
        metadata = record.get("metadata")
        if (
            record.get("schema_version") == "environment-event/v0.1"
            and record.get("event_type") == "failure"
            and isinstance(metadata, dict)
            and metadata.get("stage") == DRIFT_STAGE
        ):
            out.append(record)
    return out
