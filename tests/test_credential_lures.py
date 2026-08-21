"""Tests for the AZ-06 credential-lure lifecycle (Deception#6)."""

from __future__ import annotations

import pytest
from azazel_fabric.deception_contracts import CredentialLure

from azazel_deception.credentials import LureRegistry, mint_lure

PACKAGE_ID = "municipal-linux-v1"
DECOY_TARGET = "decoy-ssh-01"
OTHER_TARGET = "decoy-smb-02"
SEED = "engagement-seed-abc123"
ISSUED_AT = "2026-08-21T00:00:00+00:00"
TTL_SECONDS = 3600


def _mint(**overrides):
    kwargs = dict(
        package_id=PACKAGE_ID,
        decoy_target=DECOY_TARGET,
        issued_at=ISSUED_AT,
        ttl_seconds=TTL_SECONDS,
        seed=SEED,
    )
    kwargs.update(overrides)
    return mint_lure(**kwargs)


def test_minted_lure_is_fully_synthetic_and_scoped():
    lure = _mint()

    # Uniquely identifiable.
    assert lure.credential_id
    assert lure.credential_id.startswith("az06-lure-")

    # Scoped to exactly the decoy target -- never a real host/service.
    assert lure.target_surface_id == DECOY_TARGET

    # Fully synthetic: doctrine-enforced by the contract itself.
    assert lure.decoy_only is True

    # Traceable to the minting package, but not equal to any raw input
    # (i.e. not literally a copy of a real secret/identifier).
    assert lure.source_artifact_id == PACKAGE_ID
    assert lure.credential_id not in (PACKAGE_ID, DECOY_TARGET, SEED)

    # Expiring.
    assert lure.expires_at is not None


def test_expires_at_is_issued_at_plus_ttl():
    lure = _mint(ttl_seconds=120)
    expected = "2026-08-21T00:02:00+00:00"
    assert lure.expires_at.isoformat() == expected


def test_mint_is_deterministic_for_identical_inputs():
    lure_a = _mint()
    lure_b = _mint()
    assert lure_a == lure_b
    assert lure_a.credential_id == lure_b.credential_id


def test_mint_differs_on_seed_target_or_index():
    base = _mint()
    assert _mint(seed="different-seed").credential_id != base.credential_id
    assert _mint(decoy_target=OTHER_TARGET).credential_id != base.credential_id
    assert _mint(index=1).credential_id != base.credential_id


def test_mint_never_uses_wallclock_or_random(monkeypatch):
    # Poison random so any accidental use fails loudly rather than silently
    # making the result nondeterministic. datetime.now cannot be
    # monkeypatched directly (immutable C type) -- that path is instead
    # covered by the static source check below and by the repeated-call
    # determinism asserted elsewhere in this file.
    import random as random_module

    def _boom(*_args, **_kwargs):
        raise AssertionError("mint_lure must not consult the RNG")

    monkeypatch.setattr(random_module, "random", _boom)
    monkeypatch.setattr(random_module, "randint", _boom)

    lure_a = _mint()
    lure_b = _mint()
    assert lure_a == lure_b


def test_lures_module_source_has_no_wallclock_or_random_calls():
    import inspect

    from azazel_deception.credentials import lures as lures_module

    source = inspect.getsource(lures_module)
    forbidden = ["datetime.now(", "utcnow(", "import random", "random.random(", "random.randint("]
    for token in forbidden:
        assert token not in source, f"forbidden nondeterministic construct found: {token!r}"


def test_mint_fails_closed_on_bad_inputs():
    with pytest.raises(ValueError):
        _mint(package_id="")
    with pytest.raises(ValueError):
        _mint(decoy_target="")
    with pytest.raises(ValueError):
        _mint(seed="")
    with pytest.raises(ValueError):
        _mint(ttl_seconds=0)
    with pytest.raises(ValueError):
        _mint(ttl_seconds=-1)
    with pytest.raises(ValueError):
        _mint(index=-1)


def test_minted_lure_validates_as_the_fabric_model():
    lure = _mint()
    assert isinstance(lure, CredentialLure)

    # Round-trips through the contract's own validation unchanged.
    revalidated = CredentialLure.model_validate(lure.model_dump())
    assert revalidated == lure

    # The contract itself refuses a non-decoy-only lure -- doctrine is
    # enforced at the type level, not just by our own code.
    with pytest.raises(Exception):
        CredentialLure(
            credential_id="x",
            owner_persona_id="y",
            target_surface_id="z",
            expires_at=lure.expires_at,
            decoy_only=False,
        )


def test_registry_is_valid_true_within_window_and_scope():
    registry = LureRegistry()
    lure = _mint()
    registry.add(lure)

    as_of_mid_window = "2026-08-21T00:30:00+00:00"
    assert registry.is_valid(lure.credential_id, as_of=as_of_mid_window) is True
    assert (
        registry.is_valid(
            lure.credential_id,
            as_of=as_of_mid_window,
            target_surface_id=DECOY_TARGET,
        )
        is True
    )


def test_registry_is_valid_false_when_expired():
    registry = LureRegistry()
    lure = _mint(ttl_seconds=60)
    registry.add(lure)

    after_expiry = "2026-08-21T00:05:00+00:00"
    assert registry.is_valid(lure.credential_id, as_of=after_expiry) is False

    # Boundary: exactly at expires_at is not valid (strict as_of < expires_at).
    at_expiry = lure.expires_at.isoformat()
    assert registry.is_valid(lure.credential_id, as_of=at_expiry) is False


def test_registry_is_valid_false_for_wrong_scope():
    registry = LureRegistry()
    lure = _mint()
    registry.add(lure)

    as_of_mid_window = "2026-08-21T00:30:00+00:00"
    assert (
        registry.is_valid(
            lure.credential_id,
            as_of=as_of_mid_window,
            target_surface_id=OTHER_TARGET,
        )
        is False
    )


def test_registry_is_valid_false_for_unknown_lure_id():
    registry = LureRegistry()
    assert registry.is_valid("nonexistent-lure-id", as_of=ISSUED_AT) is False


def test_registry_invalidate_tracks_reason_and_timestamp():
    registry = LureRegistry()
    lure = _mint()
    registry.add(lure)

    as_of_mid_window = "2026-08-21T00:30:00+00:00"
    revoke_at = "2026-08-21T00:31:00+00:00"
    registry.invalidate(lure.credential_id, "operator-revoked", as_of=revoke_at)

    assert registry.is_valid(lure.credential_id, as_of=as_of_mid_window) is False

    info = registry.invalidation_info(lure.credential_id)
    assert info is not None
    assert info.reason == "operator-revoked"
    assert info.invalidated_at == revoke_at


def test_registry_invalidate_unknown_lure_fails_closed():
    registry = LureRegistry()
    with pytest.raises(KeyError):
        registry.invalidate("nonexistent-lure-id", "reason", as_of=ISSUED_AT)


def test_registry_invalidate_all_is_reset_semantics():
    registry = LureRegistry()
    lure_1 = _mint(index=0)
    lure_2 = _mint(index=1)
    registry.add(lure_1)
    registry.add(lure_2)

    as_of_mid_window = "2026-08-21T00:30:00+00:00"
    assert registry.is_valid(lure_1.credential_id, as_of=as_of_mid_window) is True
    assert registry.is_valid(lure_2.credential_id, as_of=as_of_mid_window) is True

    reset_at = "2026-08-21T00:31:00+00:00"
    registry.invalidate_all("engagement-terminated", as_of=reset_at)

    assert registry.is_valid(lure_1.credential_id, as_of=as_of_mid_window) is False
    assert registry.is_valid(lure_2.credential_id, as_of=as_of_mid_window) is False
    assert registry.active(as_of_mid_window) == []

    info_1 = registry.invalidation_info(lure_1.credential_id)
    info_2 = registry.invalidation_info(lure_2.credential_id)
    assert info_1.reason == "engagement-terminated"
    assert info_2.reason == "engagement-terminated"
    assert info_1.invalidated_at == reset_at


def test_registry_active_lists_only_currently_valid_lures():
    registry = LureRegistry()
    short_lived = _mint(index=0, ttl_seconds=60)
    long_lived = _mint(index=1, ttl_seconds=7200)
    registry.add(short_lived)
    registry.add(long_lived)

    later = "2026-08-21T00:10:00+00:00"
    active_ids = {lure.credential_id for lure in registry.active(later)}
    assert active_ids == {long_lived.credential_id}


def test_registry_add_rejects_duplicate_id():
    registry = LureRegistry()
    lure = _mint()
    registry.add(lure)
    with pytest.raises(ValueError):
        registry.add(lure)
