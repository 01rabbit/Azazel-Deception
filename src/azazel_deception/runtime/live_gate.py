"""Machine-readable live-activation gate readiness (cutover Step 4 pre-work).

The live flip (materialization enforcement, ``AZAZEL_DECEPTION_LIVE`` + strict
posture actually driving real ``docker compose up``) is the final cutover step.
Per ``docs/canonical-cutover-dryrun-plan.md`` it is gated on the mandatory items
in ``docs/live-gate-checklist.md`` being certified, "recorded as machine-readable
evidence", plus explicit human authorization.

This module turns that checklist into a machine-checkable, **fail-closed**
readiness function. It is deliberately NOT an authorization mechanism and is NOT
wired into any live path:

* It only *answers* "has every mandatory live-flip gate been certified with
  recorded evidence?" — it never enables materialization.
* Wiring this check into ``activate_environment`` as an additional precondition,
  and the human sign-off, are the actual (gated) Step-4 work; this file is the
  non-executing scaffolding that makes that step auditable when it is authorized.

Deterministic: no wall-clock reads, no randomness — readiness is a pure function
of the supplied certification records.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from pydantic import BaseModel, ConfigDict

# The mandatory gates that block the live flip, distilled from the still-open
# items in docs/live-gate-checklist.md. Each is (id, category, summary). HIL
# gates require hardware/lab certification and cannot be closed from a cloud
# session; the software gate is closed by the merged canonical-cutover work but
# is still recorded here so a flip must positively assert it.
LIVE_GATES: tuple[tuple[str, str, str], ...] = (
    ("hil_no_route_decoy_to_production", "hil",
     "No route from a decoy workload to the protected production network."),
    ("hil_egress_denied_under_failure", "hil",
     "Decoy egress is denied under runtime/route failure cases."),
    ("hil_attacker_cannot_reach_mgmt_or_socket", "hil",
     "Attacker traffic cannot reach Edge/AZ-06 management APIs or the runtime socket."),
    ("hil_host_restart_and_route_drift_injection", "hil",
     "Host restart and route-drift failure injection pass in a Linux lab."),
    ("hil_kill_switch_against_live_attacker_modified_container", "hil",
     "End-to-end operator kill-switch control proven against a live, "
     "attacker-modified container."),
    ("hil_combined_networked_e2e_lifecycle", "hil",
     "Combined networked Edge->AZ-06 activation->evidence->termination->reset "
     "demonstrated in a lab."),
    ("portability_package_fully_signed_verified_true_justified", "portability",
     "The package is fully signed/verified and ImageManifest.verified=true is "
     "justified by provenance + SBOM policy."),
    ("portability_equivalent_e2e_on_arm64_and_amd64", "portability",
     "Equivalent end-to-end activation/evidence/termination/reset semantics on "
     "both ARM64 and AMD64."),
    ("deployment_continuous_transport_key_distribution_rotation", "deployment",
     "Continuous key distribution/rotation for the mutually-authenticated "
     "Edge<->AZ-06 transport."),
    ("software_transition_executor_strict_for_live_code_enforced", "software",
     "TransitionExecutor strict-for-live is code-enforced (not .strict() "
     "convention) — delivered by the canonical-cutover Steps 1-3."),
)

REQUIRED_LIVE_GATE_IDS: tuple[str, ...] = tuple(g[0] for g in LIVE_GATES)
_LIVE_GATE_CATEGORY: dict[str, str] = {g[0]: g[1] for g in LIVE_GATES}


class LiveGateCertification(BaseModel):
    """One certification record for a single live gate.

    ``certified`` alone is not enough: a certification counts only when it also
    carries a non-empty ``evidence_ref`` (a link/id to the lab report, workflow
    run, or attestation that backs the claim). Extra fields are rejected so a
    directive/authority-bearing field can never be smuggled into an evidence
    bundle.
    """

    model_config = ConfigDict(extra="forbid")

    gate_id: str
    certified: bool = False
    evidence_ref: str = ""
    certifier: str = ""
    certified_as_of: str = ""

    def is_satisfied(self) -> bool:
        return bool(self.certified) and bool(self.evidence_ref.strip())


class LiveGateReadiness(BaseModel):
    """Result of evaluating a certification bundle against the required gates."""

    model_config = ConfigDict(extra="forbid")

    ready: bool
    satisfied_gate_ids: list[str]
    missing_gate_ids: list[str]
    uncertified_gate_ids: list[str]
    unknown_gate_ids: list[str]

    def blocking_summary(self) -> str:
        if self.ready:
            return "all mandatory live-flip gates are certified"
        parts = []
        if self.missing_gate_ids:
            parts.append(f"missing: {', '.join(self.missing_gate_ids)}")
        if self.uncertified_gate_ids:
            parts.append(f"uncertified/no-evidence: {', '.join(self.uncertified_gate_ids)}")
        return "; ".join(parts) or "not ready"


def gate_category(gate_id: str) -> str | None:
    """Return the category ('hil'/'portability'/'deployment'/'software') of a gate."""
    return _LIVE_GATE_CATEGORY.get(gate_id)


def evaluate_live_gate_readiness(
    certifications: Iterable[Mapping[str, Any] | LiveGateCertification],
    *,
    required: Iterable[str] = REQUIRED_LIVE_GATE_IDS,
) -> LiveGateReadiness:
    """Fail-closed readiness check for the live flip.

    ``ready`` is True only when EVERY required gate has a certification that is
    both ``certified=True`` and carries a non-empty ``evidence_ref``. A required
    gate with no record is *missing*; one present but not satisfied is
    *uncertified*; a record for an id outside the required set is *unknown* (it
    never contributes to readiness). Duplicate records for a gate are satisfied
    only if at least one satisfies it.

    This function authorizes nothing. A True result is a *necessary* precondition
    for the live flip, never sufficient: the flip additionally requires explicit
    human sign-off (see docs/live-flip-runbook.md).
    """

    required_ids = list(dict.fromkeys(required))  # dedupe, preserve order
    required_set = set(required_ids)

    # Materialize once — the input may be a single-use iterator, and validation
    # of each record (extra="forbid") happens here, fail-closed.
    certs = [
        c if isinstance(c, LiveGateCertification) else LiveGateCertification.model_validate(c)
        for c in certifications
    ]

    seen_ids = {c.gate_id for c in certs}
    satisfied = {c.gate_id for c in certs if c.gate_id in required_set and c.is_satisfied()}

    satisfied_ids = [g for g in required_ids if g in satisfied]
    missing_ids = [g for g in required_ids if g not in seen_ids]
    uncertified_ids = [g for g in required_ids if g in seen_ids and g not in satisfied]
    unknown_ids: list[str] = []
    for c in certs:
        if c.gate_id not in required_set and c.gate_id not in unknown_ids:
            unknown_ids.append(c.gate_id)

    return LiveGateReadiness(
        ready=satisfied == required_set,
        satisfied_gate_ids=satisfied_ids,
        missing_gate_ids=missing_ids,
        uncertified_gate_ids=uncertified_ids,
        unknown_gate_ids=unknown_ids,
    )
