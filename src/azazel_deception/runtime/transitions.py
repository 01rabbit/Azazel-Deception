"""Finite-state transition executor for AZ-06 (Azazel-Deception#6).

Doctrine: a live decoy is never hand-mutated mid-engagement. Any change to a
running environment's state is the *selection* of one pre-authored, frozen,
signed :class:`~azazel_fabric.deception_contracts.transitions.
FiniteStateTransition` from a :class:`~azazel_fabric.deception_contracts.
transitions.TransitionCatalog` — and that selection is only ever exercised
because Azazel-Edge, not AZ-06, decided it should be. :class:`TransitionExecutor`
is the local component that enforces that: it consumes the frozen catalog and
one Edge-approved transition decision and fails closed on any mismatch between
what the catalog allows, what Edge approved, and what the caller reports.

Like :class:`~azazel_deception.runtime.compose.DockerComposeAdapter`, this is
non-executing by default: ``live_enabled`` is a live gate (default ``False``,
mirroring ``AZAZEL_DECEPTION_LIVE``'s effect there), and even when set this
module performs **no container action** — actually materializing a transition
is out of scope here and remains the responsibility of a runtime adapter. The
point of this module is the validation gate, not container I/O.

Deterministic: no wall-clock reads, no randomness. ``as_of`` is supplied by
the caller (the decision-time context) and only ever echoed back, never
interpreted here — expiry/effective-time semantics belong to the Edge decision
contract, not to this executor.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from azazel_fabric.deception_contracts import EnvironmentTransitionDecision
from azazel_fabric.deception_contracts.transitions import (
    FiniteStateTransition,
    TransitionCatalog,
    TransitionNotInCatalog,
    select_transition,
)
from azazel_fabric.deception_integrity import catalog_content_digest
from pydantic import ValidationError

from azazel_deception.runtime.compose import RuntimeGateError
from azazel_deception.runtime.state import RuntimeStateStore
from azazel_deception.runtime.transport import (
    DEFAULT_SIGNATURE_FIELD,
    DecisionAuthenticationError,
    DecisionAuthenticator,
    require_authenticated_decision,
)

# Interim (pre-canonical) decision shape, retained for backward compatibility
# with callers that have not migrated to the Fabric contract. A live posture
# should set ``require_canonical_decision=True`` to reject it.
_APPROVED_STATUS = "approved"

# The canonical Fabric transition-decision contract this executor prefers.
_TRANSITION_SCHEMA_VERSION = "environment-transition-decision/v0.1"
# Any decision in the transition-decision family is routed to canonical
# validation, so an unknown *version* (e.g. .../v9.9) is rejected by the model's
# exact-version Literal rather than silently falling back to the interim path.
_TRANSITION_SCHEMA_PREFIX = "environment-transition-decision/"
# Only an accepted/modified Edge decision is executable; a rejected (or any
# other) status is refused fail-closed.
_EXECUTABLE_STATUSES = frozenset({"accepted", "modified"})


def _parse_iso_aware(value: Any, *, field: str) -> datetime:
    """Parse an ISO-8601 timestamp to a tz-aware UTC datetime (naive -> UTC).

    Fail-closed: an absent/non-string/unparseable value raises
    :class:`RuntimeGateError`. Pure string->datetime conversion; never reads the
    wall clock, so callers stay deterministic.
    """

    if not isinstance(value, str) or not value.strip():
        raise RuntimeGateError(f"{field} must be a non-empty ISO-8601 timestamp string")
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise RuntimeGateError(f"{field} is not a valid ISO-8601 timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


class TransitionExecutor:
    """Executes only Edge-authorized transitions frozen into a catalog.

    The catalog's normalized content digest is sealed at construction time
    (``self._sealed_digest``) and re-verified on every :meth:`execute` call
    against a fresh recomputation over the (possibly mutated) catalog object,
    so a catalog tampered with after construction — including a rewritten
    ``catalog_digest`` field itself — is rejected rather than trusted.
    """

    def __init__(
        self,
        catalog: TransitionCatalog,
        *,
        live_enabled: bool = False,
        decision_authenticator: DecisionAuthenticator | None = None,
        state: RuntimeStateStore | None = None,
        require_authenticated_decisions: bool = False,
        require_replay_protection: bool = False,
        require_decision_expiry: bool = False,
        require_canonical_decision: bool = False,
    ) -> None:
        self.catalog = catalog
        self.live_enabled = bool(live_enabled)
        # Optional transport authentication + one-shot anti-replay + decision
        # expiry, mirroring DockerComposeAdapter's doctrine. When an
        # authenticator is injected the edge_decision's HMAC signature is
        # verified fail-closed; when a state store is injected the
        # edge_decision_id is consumed one-shot so a replayed (or
        # forged-then-replayed) "approved" decision is refused on the second
        # use; when the decision carries an expires_at it is enforced against
        # the caller-supplied as_of so a captured decision cannot be replayed
        # indefinitely into the future.
        #
        # The three ``require_*`` flags each promote one protection from
        # opportunistic to mandatory, so a strict live posture fails closed
        # when the corresponding protection is not actually wired (rather than
        # silently shipping without it):
        #   * require_authenticated_decisions -> an authenticator must be set
        #   * require_replay_protection       -> a state store must be set
        #   * require_decision_expiry         -> the decision must carry expires_at
        self.decision_authenticator = decision_authenticator
        self.state = state
        self.require_authenticated_decisions = bool(require_authenticated_decisions)
        self.require_replay_protection = bool(require_replay_protection)
        self.require_decision_expiry = bool(require_decision_expiry)
        # When set, only a valid canonical Fabric EnvironmentTransitionDecision
        # is accepted; the interim ``{transition_id, edge_decision_id, status:
        # "approved"}`` dict is rejected. This is the posture a live integration
        # uses so a decision is always the authoritative, schema-versioned,
        # expiry-bearing contract rather than an ad-hoc mapping.
        self.require_canonical_decision = bool(require_canonical_decision)
        # Seal/trust the digest the catalog carried at construction time.
        # Recomputed digests are always compared back to *this* value, never
        # to whatever `self.catalog.catalog_digest` happens to read as later.
        self._sealed_digest = catalog.catalog_digest

    def _verify_catalog_integrity(self) -> None:
        try:
            recomputed = catalog_content_digest(self.catalog)
        except Exception as exc:  # pragma: no cover - defensive, never crash open
            raise RuntimeGateError(f"catalog digest computation failed: {exc}") from exc
        if recomputed != self._sealed_digest:
            raise RuntimeGateError(
                "transition catalog digest mismatch: catalog is tampered or has "
                f"drifted since sealing (sealed={self._sealed_digest!r} "
                f"recomputed={recomputed!r})"
            )
        if self.catalog.catalog_digest != self._sealed_digest:
            raise RuntimeGateError(
                "transition catalog's declared catalog_digest no longer matches "
                "the digest sealed at TransitionExecutor construction"
            )

    def _lookup_transition(self, transition_id: str) -> FiniteStateTransition:
        by_id = {t.transition_id: t for t in self.catalog.transitions}
        transition = by_id.get(transition_id)
        if transition is None:
            raise RuntimeGateError(
                f"transition_id {transition_id!r} is not present in frozen "
                f"catalog {self.catalog.catalog_id!r}"
            )
        # Re-confirm existence through the catalog's own authoritative
        # from/to lookup path -- the same fail-closed gate Fabric defines for
        # "AZ-06 executes only catalog entries" -- rather than trusting the
        # id-keyed dict alone.
        try:
            resolved = select_transition(
                self.catalog,
                current_state=transition.from_state,
                target_state=transition.to_state,
            )
        except TransitionNotInCatalog as exc:
            raise RuntimeGateError(str(exc)) from exc
        if resolved.transition_id != transition_id:
            raise RuntimeGateError(
                f"transition_id {transition_id!r} does not resolve consistently "
                "in the catalog"
            )
        return resolved

    @staticmethod
    def _authorize(edge_decision: Any, transition_id: str, environment_id: str) -> str:
        """Fail-closed check that Edge approved exactly this transition.

        Minimal expected shape: a mapping with ``transition_id`` matching the
        requested transition, a non-empty ``edge_decision_id``, and
        ``status == "approved"``. Anything absent, mismatched, or not
        explicitly approved is refused -- there is no default-open case.

        When the decision carries an ``environment_id`` it must match the
        environment being transitioned: an approval minted for one environment
        can never be replayed against another. (It is optional only so that
        callers minting a decision without an explicit environment binding stay
        backward-compatible; a present-but-mismatched binding always fails.)
        """

        if not isinstance(edge_decision, dict):
            raise RuntimeGateError("edge_decision must be a mapping")
        decision_transition_id = edge_decision.get("transition_id")
        if decision_transition_id != transition_id:
            raise RuntimeGateError(
                "edge_decision does not authorize this transition_id "
                f"(decision={decision_transition_id!r} requested={transition_id!r})"
            )
        decision_environment_id = edge_decision.get("environment_id")
        if decision_environment_id is not None and decision_environment_id != environment_id:
            raise RuntimeGateError(
                "edge_decision does not authorize this environment_id "
                f"(decision={decision_environment_id!r} requested={environment_id!r})"
            )
        edge_decision_id = edge_decision.get("edge_decision_id")
        if not isinstance(edge_decision_id, str) or not edge_decision_id:
            raise RuntimeGateError("edge_decision is missing a non-empty edge_decision_id")
        status = edge_decision.get("status")
        if status != _APPROVED_STATUS:
            raise RuntimeGateError(
                f"edge_decision status is not {_APPROVED_STATUS!r}: {status!r}"
            )
        return edge_decision_id

    @staticmethod
    def _is_canonical_decision(edge_decision: dict[str, Any]) -> bool:
        version = edge_decision.get("schema_version")
        return isinstance(version, str) and version.startswith(_TRANSITION_SCHEMA_PREFIX)

    def _bind_canonical_decision(
        self,
        edge_decision: dict[str, Any],
        environment_id: str,
        current_state: str,
        transition: FiniteStateTransition,
        as_of: str,
    ) -> str:
        """Validate a canonical Fabric ``EnvironmentTransitionDecision`` and
        bind it to this exact environment/transition/time.

        The decision is parsed through the Fabric model (``extra="forbid"``,
        ``schema_version`` a fail-closed ``Literal``, ``expires_at >
        effective_at`` enforced by the contract). Beyond that the decision must:

        * be executable -- ``status`` in accepted/modified (a rejected or any
          other status is refused);
        * bind to this environment -- ``decision.environment_id`` equals the
          caller's ``environment_id``;
        * bind to the caller's observed state and to the catalog transition --
          ``decision.current_state`` equals both ``current_state`` and the
          transition's ``from_state``, and ``decision.target_state`` equals the
          transition's ``to_state``; and
        * be within its own validity window -- ``effective_at <= as_of <
          expires_at`` (deterministic: both are supplied, never wall-clock).

        Returns the canonical ``decision_id`` (the one-shot anti-replay key).
        """

        payload = {k: v for k, v in edge_decision.items() if k != DEFAULT_SIGNATURE_FIELD}
        try:
            decision = EnvironmentTransitionDecision.model_validate(payload)
        except ValidationError as exc:
            raise RuntimeGateError(f"edge_decision is not a valid transition decision: {exc}") from exc

        if decision.status not in _EXECUTABLE_STATUSES:
            raise RuntimeGateError(
                f"edge_decision status is not executable: {decision.status!r}"
            )
        if decision.environment_id != environment_id:
            raise RuntimeGateError(
                "edge_decision does not authorize this environment_id "
                f"(decision={decision.environment_id!r} requested={environment_id!r})"
            )
        if decision.current_state != current_state:
            raise RuntimeGateError(
                "edge_decision current_state does not match the reported current_state "
                f"(decision={decision.current_state!r} reported={current_state!r})"
            )
        if decision.current_state != transition.from_state:
            raise RuntimeGateError(
                "edge_decision current_state does not match the transition's from_state "
                f"(decision={decision.current_state!r} from_state={transition.from_state!r})"
            )
        if decision.target_state != transition.to_state:
            raise RuntimeGateError(
                "edge_decision target_state does not match the transition's to_state "
                f"(decision={decision.target_state!r} to_state={transition.to_state!r})"
            )

        as_of_dt = _parse_iso_aware(as_of, field="as_of")
        effective_dt = _parse_iso_aware(decision.effective_at.isoformat(), field="edge_decision.effective_at")
        expiry_dt = _parse_iso_aware(decision.expires_at.isoformat(), field="edge_decision.expires_at")
        if as_of_dt < effective_dt:
            raise RuntimeGateError(
                "edge_decision is not yet effective as of the decision-time context "
                f"(as_of={as_of!r} < effective_at={decision.effective_at.isoformat()!r})"
            )
        if as_of_dt >= expiry_dt:
            raise RuntimeGateError(
                "edge_decision is expired as of the decision-time context "
                f"(as_of={as_of!r} >= expires_at={decision.expires_at.isoformat()!r})"
            )
        return decision.decision_id

    def _authenticate_decision(self, edge_decision: dict[str, Any]) -> None:
        """Verify the decision's transport authenticity (fail-closed).

        Skipped only when no authenticator is configured *and* the strict
        ``require_authenticated_decisions`` posture is off — matching the
        DockerComposeAdapter contract that a forged/tampered decision cannot
        pass once authentication is wired, and that the strict posture refuses
        to run at all without an authenticator.
        """

        if self.require_authenticated_decisions and self.decision_authenticator is None:
            raise RuntimeGateError(
                "authenticated Edge decision required but no authenticator is configured"
            )
        try:
            require_authenticated_decision(edge_decision, self.decision_authenticator)
        except DecisionAuthenticationError as exc:
            raise RuntimeGateError(str(exc)) from exc

    def _check_decision_expiry(self, edge_decision: dict[str, Any], as_of: str) -> None:
        """Reject an expired (or expiry-required-but-absent) Edge decision.

        Deterministic: compares two caller-supplied timestamps (the decision's
        ``expires_at`` and ``as_of``), never the wall clock. When the decision
        carries an ``expires_at`` it is always enforced; ``require_decision_
        expiry`` additionally makes the field mandatory so a strict posture will
        not accept an unbounded, never-expiring decision.
        """

        expires_at = edge_decision.get("expires_at")
        if expires_at is None:
            if self.require_decision_expiry:
                raise RuntimeGateError("edge_decision is missing a required expires_at")
            return
        expiry_dt = _parse_iso_aware(expires_at, field="edge_decision.expires_at")
        as_of_dt = _parse_iso_aware(as_of, field="as_of")
        if as_of_dt >= expiry_dt:
            raise RuntimeGateError(
                "edge_decision is expired as of the decision-time context "
                f"(as_of={as_of!r} >= expires_at={expires_at!r})"
            )

    def _consume_decision(self, edge_decision_id: str, environment_id: str, as_of: str) -> None:
        """One-shot anti-replay: refuse a decision id already exercised.

        Deterministic — the consume record is stamped with the caller-supplied
        ``as_of`` (the decision-time context), never a wall-clock read, so this
        executor keeps its no-``datetime.now`` invariant. A no-op when no state
        store is injected, unless ``require_replay_protection`` is set, in which
        case a missing store fails closed rather than silently skipping.
        """

        if self.state is None:
            if self.require_replay_protection:
                raise RuntimeGateError(
                    "replay protection required but no state store is configured"
                )
            return
        consumed = self.state.consume_decision(
            edge_decision_id,
            {
                "decision_id": edge_decision_id,
                "kind": "transition",
                "environment_id": environment_id,
                "consumed_as_of": as_of,
            },
        )
        if not consumed:
            raise RuntimeGateError(f"Edge decision already consumed: {edge_decision_id}")

    @staticmethod
    def _validate_bounds_and_conditions(transition: FiniteStateTransition) -> None:
        # FiniteStateTransition already makes these fields mandatory at
        # construction time; this is a defense-in-depth re-check at the
        # execution gate rather than trusting that every catalog object in
        # process memory necessarily passed full validation.
        if transition.bounds is None:
            raise RuntimeGateError("transition is missing declared resource bounds")
        if not transition.bounds.max_duration_seconds or transition.bounds.max_duration_seconds <= 0:
            raise RuntimeGateError("transition bounds are missing a positive time bound")
        if transition.network_egress_allowed is not False:
            raise RuntimeGateError("transition does not declare bounded (denied) network egress")
        if not transition.rollback_state:
            raise RuntimeGateError("transition is missing a declared rollback_state")
        if not transition.termination_conditions:
            raise RuntimeGateError("transition is missing declared termination_conditions")

    def execute(
        self,
        *,
        environment_id: str,
        current_state: str,
        transition_id: str,
        edge_decision: dict[str, Any],
        as_of: str,
    ) -> dict[str, Any]:
        """Validate and (non-executingly, by default) apply one transition.

        Deterministic: identical inputs always yield an identical result
        dict. Fail-closed at every step via :class:`RuntimeGateError`.
        """

        if not environment_id:
            raise RuntimeGateError("environment_id is required")
        if not current_state:
            raise RuntimeGateError("current_state is required")
        if not as_of:
            raise RuntimeGateError("as_of is required")

        # Accept either the canonical Fabric model instance or its dict/JSON
        # envelope; normalize to a dict so authentication and validation share
        # one path.
        if isinstance(edge_decision, EnvironmentTransitionDecision):
            edge_decision = edge_decision.model_dump(mode="json")
        if not isinstance(edge_decision, dict):
            raise RuntimeGateError("edge_decision must be a mapping or EnvironmentTransitionDecision")

        # 1. Catalog digest integrity: a tampered/drifted catalog is
        #    rejected before any transition-specific logic runs.
        self._verify_catalog_integrity()

        # 2. The transition must exist in the frozen catalog.
        transition = self._lookup_transition(transition_id)

        # 3. Transport authenticity: a forged/tampered decision is rejected
        #    before its self-declared fields are trusted (fail-closed when an
        #    authenticator is configured or the strict posture demands one).
        self._authenticate_decision(edge_decision)

        # 4. Authorize + bind the decision. The canonical Fabric contract is
        #    preferred (and mandatory under require_canonical_decision); the
        #    interim dict shape remains only for un-migrated callers and is
        #    rejected outright in a strict posture.
        canonical = self._is_canonical_decision(edge_decision)
        if self.require_canonical_decision and not canonical:
            raise RuntimeGateError(
                "a canonical EnvironmentTransitionDecision is required "
                f"(schema_version={_TRANSITION_SCHEMA_VERSION!r})"
            )
        if canonical:
            # The canonical path binds environment, current/target state, status,
            # and the effective/expiry window from the contract itself.
            edge_decision_id = self._bind_canonical_decision(
                edge_decision, environment_id, current_state, transition, as_of
            )
        else:
            edge_decision_id = self._authorize(edge_decision, transition_id, environment_id)
            # A decision carrying an expiry must not be exercised past it (and,
            # under a strict posture, must carry one at all) -- so a captured
            # approval cannot be replayed indefinitely into the future.
            self._check_decision_expiry(edge_decision, as_of)
            # The caller's reported current_state must match the transition's
            # declared from-state -- executing from the wrong state is refused.
            if current_state != transition.from_state:
                raise RuntimeGateError(
                    "current_state does not match the transition's declared "
                    f"from_state (current={current_state!r} "
                    f"expected={transition.from_state!r})"
                )

        # 5. Bounds and rollback/termination conditions must be declared.
        self._validate_bounds_and_conditions(transition)

        # 6. One-shot anti-replay: exercising this decision id consumes it, so
        #    a replayed approval cannot drive a second transition.
        self._consume_decision(edge_decision_id, environment_id, as_of)

        result: dict[str, Any] = {
            "environment_id": environment_id,
            "transition_id": transition.transition_id,
            "from_state": transition.from_state,
            "to_state": transition.to_state,
            "edge_decision_id": edge_decision_id,
            "as_of": as_of,
            "live_enabled": self.live_enabled,
            "enforcement_applied": False,
            "rollback_state": transition.rollback_state,
            "termination_conditions": list(transition.termination_conditions),
            "catalog_id": self.catalog.catalog_id,
            "catalog_digest": self._sealed_digest,
        }
        if self.live_enabled:
            result["status"] = "would_execute"
            result["note"] = (
                "live_enabled is True, but TransitionExecutor performs no "
                "container action itself; materializing this transition is "
                "the responsibility of a runtime adapter."
            )
        else:
            result["status"] = "shadow_simulated"
        return result
