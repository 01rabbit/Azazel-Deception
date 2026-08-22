import hashlib

import pytest
from pydantic import ValidationError

from azazel_deception.honey import (
    HoneyArtifactManifest,
    SyntheticGuardViolation,
    assert_synthetic_only,
    generate_honey_artifacts,
)

PACKAGE = {
    "package_id": "municipal-linux-v1",
    "narrative": {
        "purpose": "reference static municipal-office Linux decoy",
        "environment_profile_id": "municipal-public-health",
        "locale": "ja-JP",
        "timezone": "Asia/Tokyo",
    },
    "components": [
        {"component_id": "intranet-web"},
        {"component_id": "evidence-sidecar-placeholder"},
    ],
}

SEED = "test-seed-alpha"
AS_OF = "2026-08-21T00:00:00Z"


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def test_manifest_validates_as_pydantic_model():
    manifest = generate_honey_artifacts(PACKAGE, seed=SEED, as_of=AS_OF)
    assert isinstance(manifest, HoneyArtifactManifest)
    assert manifest.package_id == "municipal-linux-v1"
    assert manifest.synthetic is True
    assert len(manifest.artifacts) > 0

    # Round-tripping through dict form must re-validate cleanly (extra="forbid").
    dumped = manifest.model_dump(mode="json")
    HoneyArtifactManifest.model_validate(dumped)


def test_all_expected_kinds_are_present():
    manifest = generate_honey_artifacts(PACKAGE, seed=SEED, as_of=AS_OF)
    kinds = {artifact.kind for artifact in manifest.artifacts}
    assert kinds == {
        "file",
        "document",
        "config_breadcrumb",
        "service_history",
        "metadata",
        "revision",
    }


def test_artifacts_trace_to_manifest_and_content_hash_matches():
    manifest = generate_honey_artifacts(PACKAGE, seed=SEED, as_of=AS_OF)

    artifact_ids = [artifact.artifact_id for artifact in manifest.artifacts]
    assert len(artifact_ids) == len(set(artifact_ids)), "artifact_id values must be unique"

    for artifact in manifest.artifacts:
        assert artifact.artifact_id in artifact_ids
        assert artifact.provenance == "synthetic"

        # content_sha256 must match the sha256 of the synthetic content the
        # artifact carries (materialization payload lives in metadata["content"]).
        content = artifact.metadata["content"]
        expected = "sha256:" + _sha256_hex(content)
        assert artifact.content_sha256 == expected

        # Every revision entry's own content hash must also be internally
        # consistent / traceable.
        for index, revision in enumerate(artifact.revision_history):
            reconstructed = (
                f"{artifact.artifact_id}|revision-{index}|{revision.summary}|{artifact.content_sha256}"
            )
            assert revision.content_sha256 == "sha256:" + _sha256_hex(reconstructed)


def test_determinism_same_inputs_produce_equal_manifest():
    manifest_a = generate_honey_artifacts(PACKAGE, seed=SEED, as_of=AS_OF)
    manifest_b = generate_honey_artifacts(PACKAGE, seed=SEED, as_of=AS_OF)

    assert manifest_a == manifest_b
    assert manifest_a.model_dump_json() == manifest_b.model_dump_json()


def test_determinism_different_seed_produces_different_manifest():
    manifest_a = generate_honey_artifacts(PACKAGE, seed=SEED, as_of=AS_OF)
    manifest_b = generate_honey_artifacts(PACKAGE, seed="different-seed", as_of=AS_OF)

    assert manifest_a.manifest_id != manifest_b.manifest_id
    assert manifest_a.model_dump_json() != manifest_b.model_dump_json()


def test_determinism_different_as_of_produces_different_manifest():
    manifest_a = generate_honey_artifacts(PACKAGE, seed=SEED, as_of=AS_OF)
    manifest_b = generate_honey_artifacts(PACKAGE, seed=SEED, as_of="2026-01-01T00:00:00Z")

    assert manifest_a.manifest_id != manifest_b.manifest_id
    assert manifest_a.model_dump_json() != manifest_b.model_dump_json()


def test_synthetic_guard_rejects_private_key_header_directly():
    with pytest.raises(SyntheticGuardViolation):
        assert_synthetic_only(
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQ...\n-----END RSA PRIVATE KEY-----",
            context="unit-test",
        )


def test_synthetic_guard_rejects_credit_card_pattern_directly():
    with pytest.raises(SyntheticGuardViolation):
        assert_synthetic_only("card on file: 4111 1111 1111 1111", context="unit-test")


def test_synthetic_guard_rejects_ssn_pattern_directly():
    with pytest.raises(SyntheticGuardViolation):
        assert_synthetic_only("ssn: 219-09-9999", context="unit-test")


import pytest as _pytest

# NOTE: the token-shaped strings below are assembled from fragments at runtime
# rather than written as contiguous literals. They are 100% synthetic, but a
# realistic *contiguous* token in source trips repository push-protection
# secret scanners; splitting them keeps the guard's regexes exercised on the
# assembled value while leaving no scannable secret in the file.
_UNDERSCORE = "_"
_HYPHEN = "-"


def _secret_shaped_samples() -> list[str]:
    aws = "AWS" + _UNDERSCORE + "SECRET" + _UNDERSCORE + "ACCESS" + _UNDERSCORE + "KEY"
    return [
        aws + "=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "token: " + "ghp" + _UNDERSCORE + "016C7bA0aBcDeFgHiJkLmNoPqRsTuVwXyZ12",
        "slack: " + "xoxb" + _HYPHEN + "EXAMPLE" + _HYPHEN + "EXAMPLE" + _HYPHEN + "EXAMPLETOKEN",
        "stripe key " + "sk" + _UNDERSCORE + "live" + _UNDERSCORE + "EXAMPLEEXAMPLEEXAMPLE",
        "google maps " + "AIza" + "Sy0123456789abcdefghijklmnopqrstuvw",  # AIza + 35
        "openai " + "sk" + _HYPHEN + "proj" + _HYPHEN + "abcdefghijklmnopqrstuvwx1234",
        "jwt " + "eyJ" + "hbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkw.dozjgNryP4J3jVmNHl0w",
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBF...\n-----END PGP PRIVATE KEY BLOCK-----",
        "temporary creds " + "ASIA1234567890ABCDEF",
    ]


@_pytest.mark.parametrize("sample", _secret_shaped_samples())
def test_synthetic_guard_rejects_modern_secret_shapes(sample):
    with _pytest.raises(SyntheticGuardViolation):
        assert_synthetic_only(sample, context="unit-test")


def test_synthetic_guard_allows_clean_synthetic_content():
    assert_synthetic_only("service_name=intranet-web\nbind_address=192.0.2.10\n", context="unit-test")
    # Benign strings that superficially resemble a token prefix must not trip
    # the guard (no false-positive on ordinary decoy config).
    assert_synthetic_only("host=skywalker-01\nregion=us-east-1\n", context="unit-test")


def test_mis_authored_package_with_injected_secret_fails_closed():
    tainted = {
        "package_id": "municipal-linux-v1",
        "narrative": {
            "purpose": "-----BEGIN PRIVATE KEY-----\nMIIEvQ...\n-----END PRIVATE KEY-----",
        },
        "components": [{"component_id": "intranet-web"}],
    }
    with pytest.raises(SyntheticGuardViolation):
        generate_honey_artifacts(tainted, seed=SEED, as_of=AS_OF)


def test_package_id_with_injected_secret_fails_closed():
    # package_id is woven into generated paths, so a secret-shaped id must be
    # rejected directly rather than riding into a path unguarded.
    tainted = {
        "package_id": "pkg-" + "ghp" + _UNDERSCORE + "016C7bA0aBcDeFgHiJkLmNoPqRsTuVwXyZ12",
        "narrative": {"purpose": "benign"},
        "components": [{"component_id": "intranet-web"}],
    }
    with pytest.raises(SyntheticGuardViolation):
        generate_honey_artifacts(tainted, seed=SEED, as_of=AS_OF)


def test_missing_package_id_fails_closed():
    with pytest.raises(Exception):
        generate_honey_artifacts({"narrative": {}}, seed=SEED, as_of=AS_OF)


def test_empty_seed_fails_closed():
    with pytest.raises(Exception):
        generate_honey_artifacts(PACKAGE, seed="", as_of=AS_OF)


def test_invalid_as_of_fails_closed():
    with pytest.raises(Exception):
        generate_honey_artifacts(PACKAGE, seed=SEED, as_of="not-a-timestamp")


def test_manifest_rejects_unknown_fields():
    manifest = generate_honey_artifacts(PACKAGE, seed=SEED, as_of=AS_OF)
    dumped = manifest.model_dump(mode="json")
    dumped["unexpected_field"] = "nope"
    with pytest.raises(ValidationError):
        HoneyArtifactManifest.model_validate(dumped)


def test_generates_reasonable_artifacts_for_package_with_no_components():
    package = {
        "package_id": "bare-package",
        "narrative": {"purpose": "bare decoy with no declared components"},
        "components": [],
    }
    manifest = generate_honey_artifacts(package, seed=SEED, as_of=AS_OF)
    assert len(manifest.artifacts) > 0
    kinds = {artifact.kind for artifact in manifest.artifacts}
    assert "file" in kinds
    assert "config_breadcrumb" in kinds
