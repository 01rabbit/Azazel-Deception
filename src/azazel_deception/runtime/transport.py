"""Authenticated Edge-decision transport verification for AZ-06.

Azazel-Edge owns engagement decisions and Azazel-Fabric owns the wire contract;
AZ-06 does not define either. What AZ-06 owns is *verifying*, before it acts,
that an incoming Edge decision is authentic and untampered on the transport.

This module provides that verification side: an HMAC-SHA256 signature over the
canonical decision bytes (the decision minus its signature field, serialized
deterministically). The shared key is supplied by the operator/integration
boundary — it is never stored in the repository. Combined with the existing
one-shot decision ledger (anti-replay) and decision expiry, an authenticator
gives authenticity + integrity + freshness for the decision transport.

The ``sign_decision`` helper is the symmetric counterpart used by Edge-side
tooling, tests, and the local lab to produce a signed decision. It does not
grant any authority; a signature only proves origin/integrity.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Callable, Mapping
from typing import Any

DEFAULT_SIGNATURE_FIELD = "decision_signature"

DecisionAuthenticator = Callable[[Mapping[str, Any]], bool]


def _as_key(key: str | bytes) -> bytes:
    return key.encode("utf-8") if isinstance(key, str) else bytes(key)


def canonical_decision_bytes(
    decision: Mapping[str, Any],
    *,
    signature_field: str = DEFAULT_SIGNATURE_FIELD,
) -> bytes:
    """Return the deterministic bytes an Edge signature covers.

    The signature field itself is excluded; every other field is bound.
    """

    payload = {k: v for k, v in dict(decision).items() if k != signature_field}
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def compute_decision_signature(
    decision: Mapping[str, Any],
    key: str | bytes,
    *,
    signature_field: str = DEFAULT_SIGNATURE_FIELD,
) -> str:
    return hmac.new(
        _as_key(key),
        canonical_decision_bytes(decision, signature_field=signature_field),
        hashlib.sha256,
    ).hexdigest()


def sign_decision(
    decision: Mapping[str, Any],
    key: str | bytes,
    *,
    signature_field: str = DEFAULT_SIGNATURE_FIELD,
) -> dict[str, Any]:
    """Return a copy of ``decision`` with an HMAC signature attached."""

    signed = dict(decision)
    signed[signature_field] = compute_decision_signature(
        decision, key, signature_field=signature_field
    )
    return signed


class HmacDecisionAuthenticator:
    """Verify an HMAC-SHA256 signature over the canonical decision bytes.

    Fail-closed: rejects a missing/empty/non-string signature, a signature that
    does not match, or any error. Uses a constant-time comparison.
    """

    def __init__(
        self,
        key: str | bytes,
        *,
        signature_field: str = DEFAULT_SIGNATURE_FIELD,
    ) -> None:
        self._key = _as_key(key)
        if not self._key:
            raise ValueError("decision authenticator key must not be empty")
        self._signature_field = signature_field

    def __call__(self, decision: Mapping[str, Any]) -> bool:
        try:
            provided = decision.get(self._signature_field)
            if not isinstance(provided, str) or not provided:
                return False
            expected = compute_decision_signature(
                decision, self._key, signature_field=self._signature_field
            )
            return hmac.compare_digest(provided, expected)
        except Exception:
            return False


class DecisionAuthenticationError(ValueError):
    pass


def require_authenticated_decision(
    decision: Mapping[str, Any],
    authenticator: DecisionAuthenticator | None,
) -> None:
    """Optionally require an authentic Edge decision before acting on it.

    When no authenticator is injected this gate is skipped (making authenticated
    transport mandatory for every live decision is a remaining live-gate step).
    When one is injected it is enforced fail-closed.
    """

    if authenticator is None:
        return
    try:
        authentic = authenticator(decision)
    except Exception as exc:
        raise DecisionAuthenticationError(
            f"decision authenticator failed: {exc}"
        ) from exc
    if authentic is not True:
        raise DecisionAuthenticationError("Edge decision failed authentication")
