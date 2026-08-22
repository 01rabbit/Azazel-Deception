"""Frozen cross-repo byte-identity anchor for the decision-signature transport.

AZ-06's ``canonical_decision_bytes`` / ``compute_decision_signature`` MUST stay
byte-for-byte identical to Azazel-Fabric's authoritative
``azazel_fabric.deception_contracts.decision_signing`` -- that byte-identity is
what lets a signature minted by Edge (or by Fabric's golden generator) verify
here, and vice versa. The shared golden vectors normally guard this, but the
cross-repo interop tests only execute once the Fabric pin is bumped to the
release that ships them (>= 0.8.0); until then they ``importorskip`` themselves,
leaving AZ-06's copy of the canonicalization unguarded against silent drift.

This anchor closes that gap. It freezes -- as literals -- the exact canonical
bytes and HMAC signature Fabric publishes for its ``decision_signed_valid``
golden vector, and asserts AZ-06's own transport reproduces them, with **no
dependency on the installed azazel_fabric version**. If AZ-06's canonicalization
ever drifts from the contract, this fails immediately rather than waiting for a
pin bump and the interop tests to re-activate.

``_GOLDEN_KEY`` is the documented, non-secret key Fabric signs its golden
fixtures with; it is never a real transport key.
"""

from __future__ import annotations

import pytest

from azazel_deception.runtime.transport import (
    HmacDecisionAuthenticator,
    canonical_decision_bytes,
    compute_decision_signature,
    sign_decision,
)

# The published Fabric golden vector body (decision_signed_valid), signature
# field excluded. Kept as literals so this test is independent of the installed
# azazel_fabric version.
_GOLDEN_BODY = {
    "current_state": "baseline",
    "decision_authority": "azazel-edge",
    "decision_id": "golden-trans-signed",
    "effective_at": "2026-08-20T00:00:00Z",
    "environment_id": "env-1",
    "evidence_refs": [],
    "expires_at": "2026-08-22T00:00:00Z",
    "reason_codes": [],
    "schema_version": "environment-transition-decision/v0.1",
    "status": "accepted",
    "target_state": "smb-share-open",
}
_GOLDEN_KEY = "golden-fixture-transport-key-v1"  # documented non-secret fixture key
_GOLDEN_CANONICAL = (
    b'{"current_state":"baseline","decision_authority":"azazel-edge",'
    b'"decision_id":"golden-trans-signed","effective_at":"2026-08-20T00:00:00Z",'
    b'"environment_id":"env-1","evidence_refs":[],'
    b'"expires_at":"2026-08-22T00:00:00Z","reason_codes":[],'
    b'"schema_version":"environment-transition-decision/v0.1",'
    b'"status":"accepted","target_state":"smb-share-open"}'
)
_GOLDEN_SIGNATURE = "2d1cea1fb7cc04e1a6129b75007bb6f32fa5c32ac41e13e426b5fb4bdcf82e1c"


def test_canonical_bytes_match_fabric_golden_exactly():
    assert canonical_decision_bytes(_GOLDEN_BODY) == _GOLDEN_CANONICAL


def test_signature_matches_fabric_golden_exactly():
    assert compute_decision_signature(_GOLDEN_BODY, _GOLDEN_KEY) == _GOLDEN_SIGNATURE


def test_signature_field_is_excluded_from_canonical_bytes():
    signed = sign_decision(_GOLDEN_BODY, _GOLDEN_KEY)
    assert signed["decision_signature"] == _GOLDEN_SIGNATURE
    # Re-canonicalizing the signed envelope must drop the signature field, so the
    # covered bytes are unchanged and the signature still verifies.
    assert canonical_decision_bytes(signed) == _GOLDEN_CANONICAL
    assert HmacDecisionAuthenticator(_GOLDEN_KEY)(signed) is True


def test_non_bytes_key_is_rejected_not_silently_degenerate():
    # bytes(n) for an int n returns n zero bytes -- NOT an encoding of n -- so a
    # misconfigured int key would otherwise silently become a predictable
    # all-zero key. Non-str/bytes keys must fail loudly, in the transport
    # primitives and in the authenticator constructor alike.
    with pytest.raises(TypeError):
        compute_decision_signature(_GOLDEN_BODY, 16)
    with pytest.raises(TypeError):
        sign_decision(_GOLDEN_BODY, 16)
    with pytest.raises(TypeError):
        HmacDecisionAuthenticator(16)
