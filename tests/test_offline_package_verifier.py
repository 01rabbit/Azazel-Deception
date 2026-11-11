"""Offline wrapper controls; mocked success is not Sigstore-positive evidence."""

from dataclasses import replace
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace

import pytest

from azazel_deception.package import load_package, parse_package
from azazel_deception.runtime import offline_package_verifier as offline
from azazel_deception.runtime.verifier import GitHubAttestationPackageVerifier
from azazel_fabric.deception_integrity import canonical_package_signing_bytes

PACKAGE = Path("examples/packages/municipal-linux-v1/package.yaml")


def package():
    return parse_package(load_package(PACKAGE))


@pytest.fixture
def material():
    # Linux /tmp is intentionally refused as an untrusted writable ancestor.
    # Put only these generated public fixtures below the user's protected HOME.
    directory = Path(
        tempfile.mkdtemp(prefix="az06-public-verifier-test-", dir=Path.home().resolve())
    )
    try:
        cli, root, bundle = (
            directory / name for name in ("gh", "trusted_root.jsonl", "bundle.jsonl")
        )
        cli.write_bytes(b"synthetic-test-cli-not-executed")
        cli.chmod(0o500)
        root.write_bytes(b"synthetic-root-not-a-cryptographic-fixture")
        bundle.write_bytes(b"synthetic-bundle-not-a-cryptographic-fixture")
        yield offline.OfflineGitHubAttestationPackageVerifier(
            gh_path=cli,
            gh_sha256=hashlib.sha256(cli.read_bytes()).hexdigest(),
            bundle_path=bundle,
            trusted_root_path=root,
            trusted_root_sha256=hashlib.sha256(root.read_bytes()).hexdigest(),
        )
    finally:
        shutil.rmtree(directory)


def test_fixed_policy_snapshots_canonical_bytes_and_clean_environment(
    material, monkeypatch
):
    seen = []
    monkeypatch.setenv("GH_TOKEN", "not-a-real-token")
    monkeypatch.setenv("GITHUB_TOKEN", "not-a-real-token")
    monkeypatch.setenv("HTTPS_PROXY", "http://invalid.local")
    monkeypatch.setenv("GH_HOST", "invalid.local")
    monkeypatch.setenv("LD_PRELOAD", "/invalid/library")

    def invoke(command, **kwargs):
        seen.append(command)
        artifact = Path(command[3])
        assert artifact.name == "package.signing.json"
        assert artifact.read_bytes() == canonical_package_signing_bytes(package())
        assert Path(command[0]) != material.gh_path
        assert Path(command[0]).read_bytes() == material.gh_path.read_bytes()
        assert Path(command[0]).stat().st_mode & 0o777 == 0o500
        assert (
            Path(command[command.index("--bundle") + 1]).read_bytes()
            == material.bundle_path.read_bytes()
        )
        assert (
            Path(command[command.index("--custom-trusted-root") + 1]).read_bytes()
            == material.trusted_root_path.read_bytes()
        )
        assert (
            command[command.index("--repo") + 1]
            == GitHubAttestationPackageVerifier().repository
        )
        assert (
            command[command.index("--signer-workflow") + 1]
            == GitHubAttestationPackageVerifier().signer_workflow
        )
        assert command[command.index("--source-ref") + 1] == "refs/heads/main"
        assert "--deny-self-hosted-runners" in command
        assert command[command.index("--predicate-type") + 1] == offline.PREDICATE
        assert not any(value.startswith("oci://") for value in command)
        environment = kwargs["env"]
        assert (
            not {"GH_TOKEN", "GITHUB_TOKEN", "HTTPS_PROXY", "LD_PRELOAD"}
            & environment.keys()
        )
        assert environment["GH_HOST"] == "github.com"
        assert not list(Path(environment["HOME"]).iterdir())
        assert not list(Path(environment["GH_CONFIG_DIR"]).iterdir())
        assert (
            kwargs["stdin"]
            == kwargs["stdout"]
            == kwargs["stderr"]
            == subprocess.DEVNULL
        )
        assert kwargs["timeout"] == 30 and kwargs["close_fds"] is True
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(offline.subprocess, "run", invoke)
    before = {
        p: p.read_bytes()
        for p in (material.gh_path, material.bundle_path, material.trusted_root_path)
    }
    assert material(package()) is True  # Wrapper contract only; CLI mocked.
    assert len(seen) == 1 and not Path(seen[0][0]).exists()
    assert all(p.read_bytes() == data for p, data in before.items())


@pytest.mark.parametrize(
    "fault",
    [
        "gh_hash",
        "root_hash",
        "bad_hash",
        "missing",
        "empty",
        "symlink",
        "hardlink",
        "writable",
        "writable_parent",
        "ancestor_symlink",
        "oversized",
        "not_executable",
        "invalid_path",
    ],
)
def test_unsafe_or_unpinned_inputs_refuse_before_cli(material, monkeypatch, fault):
    if fault == "gh_hash":
        material = replace(material, gh_sha256="0" * 64)
    elif fault == "root_hash":
        material = replace(material, trusted_root_sha256="0" * 64)
    elif fault == "bad_hash":
        material = replace(material, gh_sha256="not-a-pin")
    elif fault == "missing":
        material.bundle_path.unlink()
    elif fault == "empty":
        material.bundle_path.write_bytes(b"")
    elif fault == "writable":
        material.bundle_path.chmod(0o666)
    elif fault == "writable_parent":
        material.bundle_path.parent.chmod(0o777)
    elif fault == "oversized":
        monkeypatch.setattr(offline, "MAX_BUNDLE_BYTES", 1)
    elif fault == "invalid_path":
        material = replace(material, bundle_path=None)
    elif fault == "not_executable":
        material.gh_path.chmod(0o600)
    elif fault == "hardlink":
        os.link(material.bundle_path, material.bundle_path.with_name("alias"))
    elif fault == "symlink":
        original = material.bundle_path.with_name("original")
        material.bundle_path.rename(original)
        material.bundle_path.symlink_to(original)
    else:
        alias = material.bundle_path.parent / "alias-dir"
        alias.symlink_to(material.bundle_path.parent, target_is_directory=True)
        material = replace(material, bundle_path=alias / material.bundle_path.name)
    monkeypatch.setattr(
        offline.subprocess, "run", lambda *a, **k: pytest.fail("unsafe CLI invocation")
    )
    assert material(package()) is False


@pytest.mark.parametrize("fault", ["bad_signer", "bad_signature_scheme", "bad_content"])
def test_package_integrity_refuses_before_artifact_reads(material, monkeypatch, fault):
    p = package()
    p = p.model_copy(
        update={
            "bad_signer": {"signer_ref": "github:other/workflow"},
            "bad_signature_scheme": {"signature_ref": "https://invalid.local"},
            "bad_content": {"package_digest": "sha256:" + "0" * 64},
        }[fault]
    )
    monkeypatch.setattr(
        offline,
        "_read_protected",
        lambda *a, **k: pytest.fail("untrusted artifact read"),
    )
    assert material(p) is False


@pytest.mark.parametrize("fault", ["nonzero", "timeout", "exec_failure"])
def test_cli_failure_refuses_without_fallback(material, monkeypatch, fault):
    calls = []

    def invoke(*a, **k):
        calls.append(a)
        if fault == "timeout":
            raise subprocess.TimeoutExpired(a[0], 30)
        if fault == "exec_failure":
            raise OSError("invalid binary")
        return SimpleNamespace(returncode=1)

    monkeypatch.setattr(offline.subprocess, "run", invoke)
    assert material(package()) is False and len(calls) == 1


def test_artifact_replacement_during_read_is_refused(material, monkeypatch):
    real = offline.os.read
    altered = False

    def read(fd, size):
        nonlocal altered
        chunk = real(fd, size)
        if chunk and not altered:
            altered = True
            replacement = material.gh_path.with_name("replacement")
            replacement.write_bytes(material.gh_path.read_bytes())
            replacement.chmod(0o500)
            replacement.replace(material.gh_path)
        return chunk

    monkeypatch.setattr(offline.os, "read", read)
    monkeypatch.setattr(
        offline.subprocess, "run", lambda *a, **k: pytest.fail("changed executable")
    )
    assert material(package()) is False


def test_real_prestaged_sigstore_package_verification(material, monkeypatch):
    """Opt-in real gh success and corrupted-input failures; run network-disabled."""
    if os.environ.get("AZ06_OFFLINE_ATTESTATION_TEST") != "1":
        pytest.skip(
            "explicit prestaged public Sigstore material and trusted CLI required"
        )
    verifier = offline.OfflineGitHubAttestationPackageVerifier(
        gh_path=Path(os.environ["AZ06_OFFLINE_GH_PATH"]),
        gh_sha256=os.environ["AZ06_OFFLINE_GH_SHA256"],
        bundle_path=Path(os.environ["AZ06_OFFLINE_BUNDLE_PATH"]),
        trusted_root_path=Path(os.environ["AZ06_OFFLINE_ROOT_PATH"]),
        trusted_root_sha256=os.environ["AZ06_OFFLINE_ROOT_SHA256"],
    )
    assert verifier(package()) is True
    assert replace(verifier, trusted_root_sha256="0" * 64)(package()) is False
    assert replace(verifier, gh_sha256="0" * 64)(package()) is False

    # Corruption must reach actual Sigstore/CLI rejection, not just a hash-pin
    # mismatch. These are fresh generated negative fixtures; originals remain.
    bad_bundle = material.bundle_path
    bad_bundle.write_bytes(b"{}\n")
    assert replace(verifier, bundle_path=bad_bundle)(package()) is False
    bad_root = material.trusted_root_path
    bad_root.write_bytes(b"{}\n")
    assert (
        replace(
            verifier,
            trusted_root_path=bad_root,
            trusted_root_sha256=hashlib.sha256(bad_root.read_bytes()).hexdigest(),
        )(package())
        is False
    )
    # Test-only altered policy proves the real CLI rejects a wrong source ref.
    monkeypatch.setattr(offline, "SOURCE_REF", "refs/heads/not-the-reviewed-main")
    assert verifier(package()) is False
