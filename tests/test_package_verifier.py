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


def test_github_attestation_verifier_returns_false_on_cli_failure(monkeypatch):
    monkeypatch.setattr(verifier_module.shutil, "which", lambda command: "/usr/bin/gh")
    monkeypatch.setattr(
        verifier_module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout="verification failed"),
    )
    assert GitHubAttestationPackageVerifier()(_package()) is False
