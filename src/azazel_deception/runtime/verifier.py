"""Trusted package-verifier implementations for AZ-06 live preflight."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from azazel_fabric.deception_contracts import DeceptionPackage
from azazel_fabric.deception_integrity import (
    PackageIntegrityError,
    assert_package_content_digest,
    canonical_package_signing_bytes,
)


@dataclass(frozen=True)
class GitHubAttestationPackageVerifier:
    """Verify a canonical package payload against a GitHub artifact attestation.

    This verifier intentionally reconstructs the canonical detached signing
    payload from the validated Fabric model.  The artifact passed to GitHub CLI
    therefore has exactly the bytes bound by ``package_digest``; YAML formatting
    and the detached ``signature_ref`` cannot influence verification.

    The verifier constrains both repository and signer workflow identity and can
    reject attestations produced by self-hosted runners.  It makes no network or
    runtime authorization decision; returning ``True`` only satisfies the
    package-authenticity gate used by the AZ-06 lifecycle adapter.
    """

    repository: str = "01rabbit/Azazel-Deception"
    signer_workflow: str = "01rabbit/Azazel-Deception/.github/workflows/reference-package.yml"
    gh_binary: str = "gh"
    deny_self_hosted_runners: bool = True

    @property
    def expected_signer_ref(self) -> str:
        return f"github:{self.signer_workflow}"

    def __call__(self, package: DeceptionPackage) -> bool:
        if package.signer_ref != self.expected_signer_ref:
            return False
        if not package.signature_ref.startswith("github-attestation:"):
            return False

        try:
            assert_package_content_digest(package)
        except PackageIntegrityError:
            return False

        executable = shutil.which(self.gh_binary)
        if executable is None:
            return False

        payload = canonical_package_signing_bytes(package)
        try:
            with tempfile.TemporaryDirectory(prefix="az06-package-verify-") as temp_dir:
                artifact = Path(temp_dir) / f"{package.package_id}.signing.json"
                artifact.write_bytes(payload)
                command = [
                    executable,
                    "attestation",
                    "verify",
                    str(artifact),
                    "--repo",
                    self.repository,
                    "--signer-workflow",
                    self.signer_workflow,
                ]
                if self.deny_self_hosted_runners:
                    command.append("--deny-self-hosted-runners")
                result = subprocess.run(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=30,
                    check=False,
                )
        except (OSError, subprocess.SubprocessError):
            return False
        return result.returncode == 0
