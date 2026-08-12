"""Canonical package-integrity contract tests.

These lock down the AZ-06 digest semantics:

* the digest is representation-invariant (raw dict / model / YAML / JSON agree);
* the on-disk reference digest equals a freshly sealed canonical digest;
* every security-relevant field is bound (semantic mutation fails closed);
* only the detached ``signature_ref`` locator is excluded from the digest.
"""

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from azazel_deception.package import (
    calculate_package_digest,
    canonical_package_payload,
    canonical_package_payload_bytes,
    load_package,
    normalize_package,
    parse_package,
    seal_package_digest,
    validate_package,
)

PACKAGE = Path("examples/packages/municipal-linux-v1/package.yaml")


def _raw():
    return load_package(PACKAGE)


# --------------------------------------------------------------------------- #
# Representation invariance (section 1)
# --------------------------------------------------------------------------- #

def test_digest_is_identical_across_representations():
    raw = _raw()
    model = normalize_package(raw)

    from_raw = calculate_package_digest(raw)
    from_model_dump = calculate_package_digest(model.model_dump(mode="json"))
    from_yaml_reload = calculate_package_digest(yaml.safe_load(yaml.safe_dump(raw)))
    from_json_roundtrip = calculate_package_digest(json.loads(json.dumps(raw)))

    assert from_raw == from_model_dump == from_yaml_reload == from_json_roundtrip


def test_int_float_ambiguity_does_not_change_digest():
    # cpu_cores authored as int 2 must hash identically to float 2.0, because
    # the digest is computed from the normalized model, not the raw mapping.
    raw = _raw()
    baseline = calculate_package_digest(raw)
    raw["runtime_requirements"]["minimum"]["cpu_cores"] = 2.0
    raw["maximum_budget"]["cpu_cores"] = 4.0
    assert calculate_package_digest(raw) == baseline


def test_omitted_default_field_does_not_change_digest():
    # Explicitly writing an optional default must not drift from omitting it.
    raw = _raw()
    baseline = calculate_package_digest(raw)
    raw["runtime_requirements"]["minimum"]["bandwidth_kbps"] = None
    assert calculate_package_digest(raw) == baseline


def test_canonical_payload_excludes_digest_and_signature_ref():
    payload = canonical_package_payload(_raw())
    assert "package_digest" not in payload
    assert "signature_ref" not in payload
    # signer identity stays bound
    assert payload["signer_ref"].startswith("github:")


def test_canonical_payload_bytes_are_deterministic_sorted_utf8():
    data = canonical_package_payload_bytes(_raw())
    reparsed = json.loads(data.decode("utf-8"))
    assert data == json.dumps(
        reparsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def test_sha256_of_canonical_payload_bytes_equals_package_digest():
    # The attestation workflow signs these exact bytes and asserts their SHA-256
    # equals package_digest; the package/runtime verifier reconstructs the same
    # bytes. This is the contract that binds signature semantics to the digest.
    import hashlib

    raw = _raw()
    data = canonical_package_payload_bytes(raw)
    assert "sha256:" + hashlib.sha256(data).hexdigest() == raw["package_digest"]


# --------------------------------------------------------------------------- #
# Reference package sealing (section 4)
# --------------------------------------------------------------------------- #

def test_reference_digest_equals_freshly_sealed_digest():
    raw = _raw()
    sealed = seal_package_digest(raw)
    assert sealed["package_digest"] == raw["package_digest"]
    assert calculate_package_digest(raw) == raw["package_digest"]


def test_seal_does_not_mutate_input():
    raw = _raw()
    before = copy.deepcopy(raw)
    seal_package_digest(raw)
    assert raw == before


def test_seal_reload_validate_recompute_roundtrip(tmp_path):
    raw = _raw()
    sealed = seal_package_digest(raw)
    path = tmp_path / "sealed.yaml"
    path.write_text(yaml.safe_dump(sealed, sort_keys=False, allow_unicode=True), encoding="utf-8")
    reloaded = load_package(path)
    assert validate_package(reloaded) == []
    assert calculate_package_digest(reloaded) == sealed["package_digest"]


def test_cli_digest_matches_declared_package_digest():
    result = subprocess.run(
        [sys.executable, "-m", "azazel_deception", "digest", str(PACKAGE)],
        stdout=subprocess.PIPE,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == _raw()["package_digest"]


def test_cli_seal_does_not_touch_source_file():
    before = PACKAGE.read_bytes()
    subprocess.run(
        [sys.executable, "-m", "azazel_deception", "seal", str(PACKAGE)],
        stdout=subprocess.DEVNULL,
        check=True,
    )
    assert PACKAGE.read_bytes() == before


# --------------------------------------------------------------------------- #
# Adversarial mutation matrix (section 5)
# --------------------------------------------------------------------------- #

def _mutate(mutation):
    raw = _raw()
    mutation(raw)
    return raw


# Mutations that keep the package schema-valid; they must be caught by the
# content digest (declared != recomputed) rather than a schema constraint.
DIGEST_BOUND_MUTATIONS = {
    "narrative_purpose": lambda p: p["narrative"].update(purpose="tampered purpose"),
    "image_manifest_digest": lambda p: p["components"][0]["image"].update(
        manifest_digest="sha256:" + "9" * 64
    ),
    "platform_digest": lambda p: p["components"][0]["image"]["platforms"][0].update(
        digest="sha256:" + "8" * 64
    ),
    "sbom_ref": lambda p: p["components"][0]["image"].update(sbom_ref="tampered:sbom"),
    "provenance_ref": lambda p: p["components"][0]["image"].update(
        provenance_ref="tampered:provenance"
    ),
    "maximum_budget": lambda p: p["maximum_budget"].update(memory_mb=999999),
    "signer_ref": lambda p: p.update(signer_ref="github:attacker/workflow.yml"),
    "image_verified_flag": lambda p: p["components"][0]["image"].update(verified=False),
}

# Mutations Fabric rejects at the schema layer (Literal constraints) — an even
# stronger fail-closed than digest mismatch. They must never validate.
SCHEMA_REJECTED_MUTATIONS = {
    "synthetic_only": lambda p: p["narrative"].update(synthetic_only=False),
    "safety_outbound_allowed": lambda p: p["safety"].update(outbound_allowed=True),
    "safety_production_access": lambda p: p["safety"].update(production_access=True),
    "deployment_tier": lambda p: p["deployment_tiers"][0].update(tier_id="tampered-tier"),
}

ALL_MUTATIONS = {**DIGEST_BOUND_MUTATIONS, **SCHEMA_REJECTED_MUTATIONS}


@pytest.mark.parametrize("name", sorted(ALL_MUTATIONS))
def test_semantic_mutation_without_reseal_fails_closed(name):
    tampered = _mutate(ALL_MUTATIONS[name])
    assert validate_package(tampered), name
    with pytest.raises(Exception):
        parse_package(tampered)


@pytest.mark.parametrize("name", sorted(DIGEST_BOUND_MUTATIONS))
def test_digest_bound_mutation_reports_digest_mismatch(name):
    baseline = calculate_package_digest(_raw())
    tampered = _mutate(DIGEST_BOUND_MUTATIONS[name])
    # Field is bound by the content digest: recomputed digest drifts...
    assert calculate_package_digest(tampered) != baseline, name
    # ...and validation reports it specifically as a digest mismatch.
    assert any("package_digest mismatch" in error for error in validate_package(tampered)), name


@pytest.mark.parametrize("name", sorted(SCHEMA_REJECTED_MUTATIONS))
def test_schema_rejected_mutation_cannot_even_be_sealed(name):
    tampered = _mutate(SCHEMA_REJECTED_MUTATIONS[name])
    # A dangerous mutation the schema forbids must not be seal-able into a
    # "valid-looking" package: canonical digest computation itself fails closed.
    with pytest.raises(Exception):
        calculate_package_digest(tampered)
    with pytest.raises(Exception):
        seal_package_digest(tampered)


# --------------------------------------------------------------------------- #
# Bootstrap compatibility input must also be fail-closed (no silent repair)
# --------------------------------------------------------------------------- #

def _bootstrap():
    return {
        "schema_version": "deception-package/bootstrap-v0.1",
        "package_id": "legacy-x",
        "version": "0.1.0",
        "package_digest": "sha256:" + "a" * 64,  # bogus declared digest
        "narrative": {"purpose": "legacy"},
        "runtime_requirements": {
            "architectures": ["arm64"],
            "runtime_adapter": "docker_compose",
        },
        "components": [
            {
                "id": "web",
                "image": "nginx",
                "required": True,
                "container_port": 8080,
                "exposed_service": "http",
            }
        ],
        "deployment_tiers": {
            "lite": {
                "minimum": {"cpu_cores": 1, "memory_mb": 512, "storage_mb": 1024},
                "include": ["web"],
            }
        },
        "safety": {},
    }


def test_bootstrap_with_wrong_digest_fails_closed():
    errors = validate_package(_bootstrap())
    assert any("package_digest mismatch" in error for error in errors)
    with pytest.raises(Exception):
        parse_package(_bootstrap())


def test_bootstrap_without_digest_fails_closed():
    boot = _bootstrap()
    boot.pop("package_digest")
    assert validate_package(boot)


def test_bootstrap_is_usable_only_after_explicit_seal():
    sealed = seal_package_digest(_bootstrap())
    assert validate_package(sealed) == []
    # Tampering after sealing is still caught.
    sealed["narrative"]["purpose"] = "TAMPERED"
    assert validate_package(sealed)


def test_signature_ref_change_does_not_change_content_digest():
    baseline = calculate_package_digest(_raw())
    rotated = _mutate(
        lambda p: p.update(signature_ref="github-attestation:rotated-detached-locator")
    )
    # A detached signature locator can be updated post-signing without breaking
    # the content digest or validation.
    assert calculate_package_digest(rotated) == baseline
    assert validate_package(rotated) == []
