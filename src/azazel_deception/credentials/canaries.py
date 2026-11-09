"""Bounded, package-scoped local canary preparation and observation (#74).

This is an in-memory, default-unwired helper, not an activation path or HTTP
server. Tokens are separate from public evidence identifiers. Existing synthetic
lure validity/invalidation is reused; token touches never establish AI identity,
malice, belief, diversion or authorization. All timestamps are caller-supplied.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .lures import LureRegistry, mint_lure

_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}\Z")


def _id(value: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise ValueError("invalid bounded canary reference")
    return value


def _time(value: str) -> datetime:
    if type(value) is not str or len(value) > 64:
        raise ValueError("invalid timestamp")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("timezone is required")
    return result


@dataclass(frozen=True)
class CanaryScope:
    package_id: str
    package_sha256: str
    environment_id: str
    boot_id: str
    session_id: str
    surface_id: str

    def __post_init__(self):
        for value in (self.package_id, self.environment_id, self.boot_id, self.session_id, self.surface_id):
            _id(value)
        if type(self.package_sha256) is not str or re.fullmatch(r"[0-9a-f]{64}", self.package_sha256) is None:
            raise ValueError("invalid package digest")


@dataclass(frozen=True)
class IssuedCanary:
    lure_id: str
    expires_at: str
    token: str = field(repr=False)

    def local_path(self) -> str:
        return "/__azazel_canary__/" + self.token

    def public_reference(self) -> dict[str, str]:
        return {"lure_id": self.lure_id, "expires_at": self.expires_at}


@dataclass
class _Entry:
    lure_id: str
    issued_at: datetime
    presentation_ref: str | None = None
    presentation_at: datetime | None = None


class CanaryRegistry:
    """One immutable environment/boot/session; reset permanently closes it.

    Caller-owned admission/isolation must precede any actual presentation. This
    helper cannot check those runtime facts and never asserts an active service.
    Restart does not restore tokens: a new registry is fail-closed for old tokens.
    """

    def __init__(self, scope: CanaryScope, *, max_tokens: int = 128, max_events: int = 2048):
        if not isinstance(scope, CanaryScope):
            raise ValueError("scope must be validated")
        if type(max_tokens) is not int or not 1 <= max_tokens <= 4096 or type(max_events) is not int or not 1 <= max_events <= 8192:
            raise ValueError("invalid canary capacity")
        self.scope = scope
        self.max_tokens, self.max_events = max_tokens, max_events
        self._lures = LureRegistry()
        self._tokens: dict[str, _Entry] = {}
        self._by_lure: dict[str, _Entry] = {}
        self._event_ids: set[str] = set()
        self._closed = False
        self._audit_failures = 0
        self._reset_at: str | None = None
        self._latest_seen: datetime | None = None

    def issue(self, *, issued_at: str, ttl_seconds: int = 600) -> IssuedCanary:
        when = _time(issued_at)
        if self._closed or len(self._tokens) >= self.max_tokens:
            raise ValueError("canary registry closed or at capacity")
        if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 3600:
            raise ValueError("invalid canary TTL")
        token = secrets.token_urlsafe(32)
        if _TOKEN.fullmatch(token) is None:
            raise ValueError("invalid entropy result")
        digest = hashlib.sha256(token.encode()).hexdigest()
        if digest in self._tokens:
            raise ValueError("duplicate token entropy")
        scope_seed = json.dumps(self.scope.__dict__, sort_keys=True, separators=(",", ":"))
        lure = mint_lure(self.scope.package_id, self.scope.surface_id, issued_at=issued_at,
                         ttl_seconds=ttl_seconds, seed=hashlib.sha256((scope_seed + token).encode()).hexdigest())
        self._lures.add(lure)
        entry = _Entry(lure.credential_id, when)
        self._tokens[digest] = entry
        self._by_lure[lure.credential_id] = entry
        self._latest_seen = max(self._latest_seen or when, when)
        return IssuedCanary(lure.credential_id, lure.expires_at.isoformat(), token)

    def present(self, lure_id: str, *, scope: CanaryScope, evidence_ref: str, as_of: str) -> None:
        _id(evidence_ref)
        when = _time(as_of)
        entry = self._by_lure.get(lure_id)
        if self._closed or scope != self.scope or entry is None or when < entry.issued_at:
            raise ValueError("invalid canary presentation scope/time")
        if not self._lures.authorize(lure_id, target_surface_id=scope.surface_id, as_of=as_of):
            raise ValueError("inactive canary presentation")
        if entry.presentation_ref is not None:
            if entry.presentation_ref != evidence_ref or entry.presentation_at != when:
                raise ValueError("presentation evidence is immutable")
            return
        entry.presentation_ref, entry.presentation_at = evidence_ref, when
        self._latest_seen = max(self._latest_seen or when, when)

    def touch(self, token: str, *, scope: CanaryScope, event_id: str, evidence_ref: str, as_of: str) -> dict[str, Any]:
        """Return minimized observation facts; no raw token is ever returned."""
        _id(event_id)
        _id(evidence_ref)
        when = _time(as_of)
        if self._closed or scope != self.scope or type(token) is not str or _TOKEN.fullmatch(token) is None:
            return {"accepted": False, "reason": "inactive_or_scope_mismatch"}
        entry = self._tokens.get(hashlib.sha256(token.encode()).hexdigest())
        if entry is None or when < entry.issued_at or not self._lures.authorize(entry.lure_id, target_surface_id=scope.surface_id, as_of=as_of):
            return {"accepted": False, "reason": "unknown_expired_or_invalidated"}
        if event_id in self._event_ids:
            return {"accepted": False, "reason": "duplicate_event"}
        if len(self._event_ids) >= self.max_events:
            return {"accepted": False, "reason": "event_capacity_exhausted"}
        self._event_ids.add(event_id)
        self._latest_seen = max(self._latest_seen or when, when)
        presented = entry.presentation_at is not None and entry.presentation_at <= when
        return {"accepted": True, "kind": "follow_through_observed" if presented else "touch_without_presentation",
                "lure_id": entry.lure_id, "event_id": event_id, "evidence_ref": evidence_ref,
                "presentation_ref": entry.presentation_ref if presented else None,
                "observed_at": when.isoformat(), "scope": dict(self.scope.__dict__),
                "limitations": ["presentation_and_interaction_evidence_reported_unverified", "scanner_prefetch_replay_and_copied_link_are_alternative_explanations", "no_AI_identity_malice_belief_or_tactical_verdict"]}

    def reset(self, *, as_of: str) -> dict[str, Any]:
        when = _time(as_of)
        if self._latest_seen is not None and when < self._latest_seen:
            raise ValueError("reset predates known canary observations")
        self._reset_at = self._reset_at or as_of
        self._lures.invalidate_all("environment_reset", as_of=as_of)
        self._closed = True
        return {"closed": True, "invalidated_count": len(self._tokens), "scope": dict(self.scope.__dict__), "as_of": self._reset_at}

    def status(self) -> dict[str, Any]:
        return {"closed": self._closed, "tokens": len(self._tokens), "events": len(self._event_ids),
                "token_capacity": self.max_tokens, "event_capacity": self.max_events, "audit_failures": self._audit_failures}


def synthetic_openapi(canary: IssuedCanary) -> str:
    """Reviewable decoy-only document; relative local path, no external callback."""
    if not isinstance(canary, IssuedCanary) or _TOKEN.fullmatch(canary.token) is None:
        raise ValueError("invalid prepared canary")
    return json.dumps({"openapi": "3.0.3", "info": {"title": "Synthetic local service", "version": "1"},
                       "paths": {canary.local_path(): {"get": {"responses": {"204": {"description": "Synthetic local marker"}}}}}}, sort_keys=True)


def record_canary_touch(observer, registry: CanaryRegistry, token: str, *, scope: CanaryScope,
                        event_id: str, evidence_ref: str, as_of: str) -> dict[str, Any]:
    """Project a matched local fact through the existing evidence emitter.

    Source presentation claims remain unverified; caller-owned live gates are
    unchanged. A failed evidence append is explicit and consumes the bounded
    event identity, preferring evidence loss over retry/activation/backpressure.
    """
    if observer.environment_id != scope.environment_id or observer.package_id != scope.package_id:
        raise ValueError("canary observer scope mismatch")
    result = registry.touch(token, scope=scope, event_id=event_id, evidence_ref=evidence_ref, as_of=as_of)
    if not result["accepted"]:
        return result
    refs = [evidence_ref]
    if result["presentation_ref"]:
        refs.append(result["presentation_ref"])
    try:
        observation = observer.record(
            observation_class="interaction", surface="config_breadcrumb",
            reaction_kind=None, lure_id=result["lure_id"],
            evidence_refs=refs, observed_at=_time(as_of),
            confounder_tags=["unknown"],
            metadata={"package_sha256": scope.package_sha256, "boot_id": scope.boot_id,
                      "session_id": scope.session_id, "event_id": event_id,
                      "surface_ref": scope.surface_id, "interaction_kind": result["kind"],
                      "limitations": ";".join(result["limitations"])},
        )
    except (OSError, ValueError):
        registry._audit_failures += 1
        return {"accepted": False, "reason": "evidence_unavailable"}
    return {**result, "observation_id": observation.observation_id}
