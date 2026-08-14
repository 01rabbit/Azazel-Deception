from pathlib import Path
from types import SimpleNamespace

from azazel_deception.package import load_package, parse_package
from azazel_deception.runtime import verifier as verifier_module
from azazel_deception.runtime.verifier import GitHubAttestationPackageVerifier
from azazel_fabric.deception_integrity import canonical_package_signing_bytes

PACKAGE = Path("examples/packages/municipal-linux-v1/package.yaml")


def _package():
    return parse_package(load_package(PACKAGE))


def test_github_attestation_verifier_rejects_wrong_signer():
    package = _package().model_copy(update={"signer_ref": "github:unexpected/workflow.yml"})
    verifier = GitHubAttestationPackageVerifier()
    assert verifier(package) is False


def test_github_attestation_verifier_fails_closed_without_gh(monkeypatch):
    monkeypatch.setattr(verifier_module.shutil, "which", lambda command: None)
    assert GitHubAttestationPackageVerifier()(_package()) is False


def test_github_attestation_verifier_reconstructs_canonical_payload(monkeypatch):
    package = _package()
    expected = canonical_package_signing_bytes(package)
    observed = {}

    monkeypatch.setattr(verifier_module.shutil, "which", lambda command: "/usr/bin/gh")

    def fake_run(command, **kwargs):
        artifact = Path(command[3])
        observed["bytes"] = artifact.read_bytes()
        observed["command"] = command
        return SimpleNamespace(returncode=0, stdout="verified")

    monkeypatch.setattr(verifier_module.subprocess, "run", fake_run)
    assert GitHubAttestationPackageVerifier()(package) is True
    assert observed["bytes"] == expected
    assert observed["command"][:3] == ["/usr/bin/gh", "attestation", "verify"]
    assert observed["command"][4:6] == ["--repo", "01rabbit/Azazel-Deception"]
    assert "--signer-workflow" in observed["command"]
    assert "--deny-self-hosted-runners" in observed["command"]
    # Source git ref is pinned so the workflow path alone cannot be trusted on
    # an arbitrary branch/tag.
    cmd = observed["command"]
    assert cmd[cmd.index("--source-ref") + 1] == "refs/heads/main"


def test_github_attestation_verifier_pins_configurable_source_ref(monkeypatch):
    package = _package()
    monkeypatch.setattr(verifier_module.shutil, "which", lambda command: "/usr/bin/gh")
    seen = {}

    def fake_run(command, **kwargs):
        seen["command"] = command
        return SimpleNamespace(returncode=0, stdout="verified")

    monkeypatch.setattr(verifier_module.subprocess, "run", fake_run)
    verifier = GitHubAttestationPackageVerifier(source_ref="refs/tags/v1.2.3")
    assert verifier(package) is True
    cmd = seen["command"]
    assert cmd[cmd.index("--source-ref") + 1] == "refs/tags/v1.2.3"


def test_github_attestation_verifier_omits_source_ref_when_unset(monkeypatch):
    package = _package()
    monkeypatch.setattr(verifier_module.shutil, "which", lambda command: "/usr/bin/gh")
    seen = {}
    monkeypatch.setattr(
        verifier_module.subprocess,
        "run",
        lambda command, **k: seen.__setitem__("command", command)
        or SimpleNamespace(returncode=0, stdout="verified"),
    )
    assert GitHubAttestationPackageVerifier(source_ref="")(package) is True
    assert "--source-ref" not in seen["command"]


def test_github_attestation_verifier_returns_false_on_cli_failure(monkeypatch):
    monkeypatch.setattr(verifier_module.shutil, "which", lambda command: "/usr/bin/gh")
    monkeypatch.setattr(
        verifier_module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout="verification failed"),
    )
    assert GitHubAttestationPackageVerifier()(_package()) is False


def test_github_attestation_verifier_rejects_non_attestation_signature_ref():
    package = _package().model_copy(
        update={"signature_ref": "s3://attacker-bucket/detached.sig"}
    )
    assert GitHubAttestationPackageVerifier()(package) is False


def test_github_attestation_verifier_returns_false_on_subprocess_exception(monkeypatch):
    monkeypatch.setattr(verifier_module.shutil, "which", lambda command: "/usr/bin/gh")

    def boom(*args, **kwargs):
        raise OSError("gh crashed")

    monkeypatch.setattr(verifier_module.subprocess, "run", boom)
    assert GitHubAttestationPackageVerifier()(_package()) is False


def test_github_attestation_verifier_returns_false_on_timeout(monkeypatch):
    import subprocess as real_subprocess

    monkeypatch.setattr(verifier_module.shutil, "which", lambda command: "/usr/bin/gh")

    def timeout(*args, **kwargs):
        raise real_subprocess.TimeoutExpired(cmd="gh", timeout=30)

    monkeypatch.setattr(verifier_module.subprocess, "run", timeout)
    assert GitHubAttestationPackageVerifier()(_package()) is False


def test_github_attestation_verifier_package_id_cannot_escape_tempdir(monkeypatch, tmp_path):
    # A malicious, self-sealed package with a traversal package_id must not write
    # the signing artifact outside the managed temp directory.
    from azazel_deception.package import calculate_package_digest

    escape_target = tmp_path / "ESCAPED.signing.json"
    raw = load_package(PACKAGE)
    raw["package_id"] = f"../../../../../../../../../..{escape_target.with_suffix('')}"
    raw["package_digest"] = calculate_package_digest(raw)  # re-seal over the tampered id
    package = parse_package(raw)

    monkeypatch.setattr(verifier_module.shutil, "which", lambda command: "/usr/bin/gh")
    written = {}

    def fake_run(command, **kwargs):
        artifact = Path(command[3])
        written["path"] = artifact
        written["exists_during"] = artifact.exists()
        return SimpleNamespace(returncode=1, stdout="verification failed")

    monkeypatch.setattr(verifier_module.subprocess, "run", fake_run)
    assert GitHubAttestationPackageVerifier()(package) is False
    # The artifact stayed inside a temp dir with a fixed basename, and nothing
    # leaked to the attacker-chosen absolute/relative destination.
    assert written["path"].name == "package.signing.json"
    assert not escape_target.exists()


def test_github_attestation_verifier_rejects_content_digest_mismatch(monkeypatch):
    # A package whose declared digest does not match its content must be rejected
    # before any external attestation call is made.
    monkeypatch.setattr(verifier_module.shutil, "which", lambda command: "/usr/bin/gh")
    called = {"run": False}

    def spy(*args, **kwargs):
        called["run"] = True
        return SimpleNamespace(returncode=0, stdout="verified")

    monkeypatch.setattr(verifier_module.subprocess, "run", spy)
    tampered = _package().model_copy(update={"package_digest": "sha256:" + "0" * 64})
    assert GitHubAttestationPackageVerifier()(tampered) is False
    assert called["run"] is False
