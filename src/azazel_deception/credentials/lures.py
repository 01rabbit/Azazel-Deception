"""AZ-06 credential-lure lifecycle (Deception#6).

Doctrine
--------
Credential lures are **fully synthetic**. They are never derived from, nor
capable of authenticating against, any real system: they are valid only
against controlled decoy targets described by a deception package's
``DecoySurface``/``target_surface_id`` scope. Every lure is:

* **uniquely identifiable** -- ``credential_id`` is deterministically derived
  from the minting inputs, never randomly generated;
* **scoped** -- bound to exactly one ``target_surface_id`` (the decoy
  target); a lure never validates against any other surface;
* **expiring** -- carries an ``expires_at`` computed from an injected
  ``issued_at`` plus a TTL, never a wall-clock timestamp;
* **invalidatable** -- can be individually invalidated, or all-invalidated
  at once (engagement termination / reset), with the reason and time of
  invalidation retained for audit.

This module consumes the canonical Fabric contract,
``azazel_fabric.deception_contracts.CredentialLure``, as the wire/storage
shape for a minted lure. It adds no fields to that model; the synthetic
secret material *is* the deterministic, hashlib-derived ``credential_id``
itself (the honeytoken value), so the contract's existing identifier field
doubles as the planted synthetic credential.

Determinism
-----------
Nothing in this module reads the wall clock or a process-global RNG.
``mint_lure`` takes ``issued_at`` (ISO 8601 string) and ``ttl_seconds``
explicitly; ``LureRegistry`` methods that need "now" take an explicit
``as_of`` (ISO 8601 string) argument. Secret material is derived with
``hashlib.sha256`` over the minting inputs, not ``random`` or ``uuid4``.
No LLM involvement of any kind.

Fail-closed
-----------
``LureRegistry.is_valid`` returns ``False`` for every failure mode: unknown
``lure_id``, expired lure, invalidated lure, or a target-scope mismatch.
There is no path that returns ``True`` by default or by omission.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from azazel_fabric.deception_contracts import CredentialLure

__all__ = ["mint_lure", "LureRegistry", "LureInvalidationInfo"]

_LURE_ID_PREFIX = "az06-lure"
_PERSONA_ID_PREFIX = "az06-persona"


def _digest(*parts: str) -> str:
    """Deterministic SHA-256 digest over an ordered sequence of parts.

    A NUL separator is written between parts so that, e.g., ``("ab", "c")``
    and ``("a", "bc")`` never collide.
    """
    hasher = hashlib.sha256()
    for part in parts:
        hasher.update(part.encode("utf-8"))
        hasher.update(b"\x00")
    return hasher.hexdigest()


def _parse_iso8601(value: str) -> datetime:
    """Parse an ISO 8601 timestamp string into an aware ``datetime``.

    Accepts a trailing ``Z`` (UTC) in addition to the forms
    ``datetime.fromisoformat`` natively accepts. Naive input is treated as
    UTC. This never consults the wall clock.
    """
    if not isinstance(value, str) or not value:
        raise ValueError("timestamp must be a non-empty ISO 8601 string")
    text = value.strip()
    if text.endswith("Z") or text.endswith("z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _as_aware(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def mint_lure(
    package_id: str,
    decoy_target: str,
    *,
    issued_at: str,
    ttl_seconds: int,
    seed: str,
    index: int = 0,
) -> CredentialLure:
    """Mint a fully synthetic, uniquely identifiable credential lure.

    The returned :class:`CredentialLure` is scoped to ``decoy_target`` only
    (``target_surface_id``), traceable back to the minting package
    (``source_artifact_id``), and expires at ``issued_at + ttl_seconds``.

    ``credential_id`` -- which also serves as the planted synthetic secret
    value -- is derived deterministically from
    ``(package_id, decoy_target, seed, index)`` via SHA-256: the same
    inputs always mint an identical lure, and distinct inputs (including a
    distinct ``index``, which lets a caller mint several lures for the same
    package/target/seed) never collide by construction of the hash input.

    Parameters
    ----------
    package_id:
        Identifier of the deception package this lure is planted by.
    decoy_target:
        Identifier of the decoy surface (``target_surface_id``) this lure
        is valid against, and *only* against.
    issued_at:
        ISO 8601 timestamp the lure is considered minted at. Never the
        wall clock -- always supplied by the caller.
    ttl_seconds:
        Lifetime of the lure in seconds; must be positive.
    seed:
        Caller-supplied entropy source for the deterministic derivation
        (e.g. a package-run seed). Must be non-empty.
    index:
        Distinguishes multiple lures minted from otherwise-identical
        inputs (e.g. several lures per decoy target). Must be
        non-negative.

    Raises
    ------
    ValueError:
        If any input is missing/invalid (fail-closed: a malformed request
        never silently mints a degenerate lure).
    """
    if not package_id:
        raise ValueError("package_id must be non-empty")
    if not decoy_target:
        raise ValueError("decoy_target must be non-empty")
    if not seed:
        raise ValueError("seed must be non-empty")
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive")
    if index < 0:
        raise ValueError("index must be non-negative")

    issued_dt = _parse_iso8601(issued_at)
    expires_dt = issued_dt + timedelta(seconds=ttl_seconds)

    credential_digest = _digest(
        "az06-credential-lure-v1", package_id, decoy_target, seed, str(index)
    )
    credential_id = f"{_LURE_ID_PREFIX}-{credential_digest[:32]}"

    persona_digest = _digest("az06-lure-persona-v1", package_id, seed)
    owner_persona_id = f"{_PERSONA_ID_PREFIX}-{persona_digest[:16]}"

    return CredentialLure(
        credential_id=credential_id,
        owner_persona_id=owner_persona_id,
        target_surface_id=decoy_target,
        source_artifact_id=package_id,
        decoy_only=True,
        expires_at=expires_dt,
    )


@dataclass(frozen=True)
class LureInvalidationInfo:
    """Invalidation reason + timestamp for one lure."""

    reason: str
    invalidated_at: str


@dataclass
class _LureRecord:
    lure: CredentialLure
    invalidation: LureInvalidationInfo | None = None


class LureRegistry:
    """In-memory store of active credential lures.

    All time-dependent behaviour takes an explicit ``as_of`` ISO 8601
    string; nothing here reads the wall clock. Validity checks are
    fail-closed: any failure mode (unknown id, expired, invalidated, wrong
    target scope) returns ``False``, never ``True``.
    """

    def __init__(self) -> None:
        self._records: dict[str, _LureRecord] = {}

    def add(self, lure: CredentialLure) -> None:
        """Register a minted lure as active.

        Raises ``ValueError`` if a lure with the same ``credential_id`` is
        already registered -- this store never silently overwrites an
        existing lure's identity or invalidation state.
        """
        if lure.credential_id in self._records:
            raise ValueError(f"lure already registered: {lure.credential_id}")
        self._records[lure.credential_id] = _LureRecord(lure=lure)

    def is_valid(
        self,
        lure_id: str,
        *,
        as_of: str,
        target_surface_id: str | None = None,
    ) -> bool:
        """Return whether ``lure_id`` is currently valid.

        ``True`` only if the lure is known, has not been invalidated, has
        not expired as of ``as_of``, and (when ``target_surface_id`` is
        given) is scoped to that exact target. Every other case --
        including any error in parsing ``as_of`` -- fails closed to
        ``False``.
        """
        record = self._records.get(lure_id)
        if record is None:
            return False
        if record.invalidation is not None:
            return False
        if target_surface_id is not None and record.lure.target_surface_id != target_surface_id:
            return False
        try:
            as_of_dt = _parse_iso8601(as_of)
        except ValueError:
            return False
        expires_dt = _as_aware(record.lure.expires_at)
        return as_of_dt < expires_dt

    def authorize(
        self,
        lure_id: str,
        *,
        target_surface_id: str,
        as_of: str,
    ) -> bool:
        """Return whether ``lure_id`` may be presented at ``target_surface_id``.

        Unlike :meth:`is_valid`, the target surface is **mandatory**: this is
        the gate a caller uses to decide "may this honeytoken authenticate
        against *this* surface right now". A lure minted for one surface can
        never authorize against another, and a lure with no scoped target (or
        an empty/blank ``target_surface_id`` argument) fails closed. This
        exists so an authorization decision cannot accidentally omit the scope
        check the way an ``is_valid(lure_id, as_of=...)`` call (target defaulted
        to ``None``) silently would.
        """
        if not target_surface_id or not target_surface_id.strip():
            return False
        record = self._records.get(lure_id)
        if record is None:
            return False
        if not record.lure.target_surface_id:
            return False  # an unscoped lure authorizes nothing, fail closed
        return self.is_valid(lure_id, as_of=as_of, target_surface_id=target_surface_id)

    def invalidate(self, lure_id: str, reason: str, *, as_of: str) -> None:
        """Invalidate a single lure, recording ``reason`` and ``as_of``.

        Raises ``KeyError`` for an unknown ``lure_id`` and ``ValueError``
        for an empty ``reason`` -- invalidation bookkeeping is never left
        ambiguous.
        """
        if not reason:
            raise ValueError("reason must be non-empty")
        record = self._records.get(lure_id)
        if record is None:
            raise KeyError(f"unknown lure_id: {lure_id}")
        record.invalidation = LureInvalidationInfo(reason=reason, invalidated_at=as_of)

    def invalidate_all(self, reason: str, *, as_of: str) -> None:
        """Invalidate every registered lure (engagement termination/reset).

        A lure already invalidated keeps its original invalidation record
        (first invalidation wins) so a reset never masks an earlier,
        more-specific reason.
        """
        if not reason:
            raise ValueError("reason must be non-empty")
        for record in self._records.values():
            if record.invalidation is None:
                record.invalidation = LureInvalidationInfo(reason=reason, invalidated_at=as_of)

    def active(self, as_of: str) -> list[CredentialLure]:
        """Return the lures that are currently valid as of ``as_of``."""
        return [
            record.lure
            for lure_id, record in self._records.items()
            if self.is_valid(lure_id, as_of=as_of)
        ]

    def get(self, lure_id: str) -> CredentialLure | None:
        """Return the registered lure for ``lure_id``, or ``None``."""
        record = self._records.get(lure_id)
        return record.lure if record is not None else None

    def invalidation_info(self, lure_id: str) -> LureInvalidationInfo | None:
        """Return the invalidation reason/timestamp for ``lure_id``.

        ``None`` if the lure is unknown or has not been invalidated.
        """
        record = self._records.get(lure_id)
        if record is None:
            return None
        return record.invalidation
