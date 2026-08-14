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

    The verifier constrains the repository, the signer workflow *path*, and the
    source git ref (``--signer-workflow`` alone matches the workflow on any ref,
    so ``source_ref`` additionally pins the branch/tag the attestation was built
    from — production trusts only ``refs/heads/main``). It can reject
    attestations produced by self-hosted runners. It makes no network or runtime
    authorization decision; returning ``True`` only satisfies the
    package-authenticity gate used by the AZ-06 lifecycle adapter.
    """

    repository: str = "01rabbit/Azazel-Deception"
    signer_workflow: str = "01rabbit/Azazel-Deception/.github/workflows/reference-package.yml"
    source_ref: str = "refs/heads/main"
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
                # Fixed basename: package_id is attacker-influenced (self-sealed)
                # and unconstrained, so it must never form the write path or it
                # becomes a pre-verification arbitrary-file-write primitive.
                artifact = Path(temp_dir) / "package.signing.json"
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
                if self.source_ref:
                    command += ["--source-ref", self.source_ref]
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


@dataclass(frozen=True)
class GitHubSbomVerifier:
    """Verify the OCI-attached SPDX SBOM attestation for verified images.

    For every component marked ``verified=true`` this runs
    ``gh attestation verify oci://<image> --predicate-type <spdx>`` against the
    pinned repository, so the ``verified`` claim is backed by a cryptographically
    attested SBOM, not merely a reference string. It is fail-closed: it returns
    ``False`` when ``gh`` is absent, when any image lacks a valid SBOM
    attestation, on a non-digest-pinned image reference, or on any subprocess
    error. It makes no runtime authorization decision.
    """

    repository: str = "01rabbit/Azazel-Deception"
    predicate_type: str = "https://spdx.dev/Document"
    gh_binary: str = "gh"
    deny_self_hosted_runners: bool = True

    def __call__(self, package: DeceptionPackage) -> bool:
        executable = shutil.which(self.gh_binary)
        if executable is None:
            return False

        images = [
            component.image.image
            for component in package.components
            if component.image.verified
        ]
        for image in images:
            # Only immutable, digest-pinned references may be SBOM-verified.
            if "@sha256:" not in image:
                return False
            command = [
                executable,
                "attestation",
                "verify",
                f"oci://{image}",
                "--repo",
                self.repository,
                "--predicate-type",
                self.predicate_type,
            ]
            if self.deny_self_hosted_runners:
                command.append("--deny-self-hosted-runners")
            try:
                result = subprocess.run(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=60,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError):
                return False
            if result.returncode != 0:
                return False
        return True


@dataclass(frozen=True)
class OciAttachedSbomVerifier:
    """Verify the OCI-attached SPDX SBOM bound to each verified image digest.

    The reference image attaches per-platform SPDX SBOMs as OCI referrers
    (buildkit ``sbom:true``). This verifier retrieves them at the immutable
    ``@sha256:`` digest via ``docker buildx imagetools inspect`` and requires a
    well-formed SPDX document for every declared platform. Because the reference
    is digest-addressed, retrieval integrity is bound to the pinned digest.

    It is fail-closed: it returns ``False`` when ``docker`` is absent, on a
    non-digest-pinned reference, on any inspect error, on unparasable output, or
    when any verified image/platform lacks a valid SPDX document. It performs no
    runtime authorization.
    """

    docker_binary: str = "docker"

    def __call__(self, package: DeceptionPackage) -> bool:
        import json

        executable = shutil.which(self.docker_binary)
        if executable is None:
            return False

        for component in package.components:
            if not component.image.verified:
                continue
            image = component.image.image
            if "@sha256:" not in image:
                return False
            platforms = [p.architecture for p in component.image.platforms] or [None]
            try:
                result = subprocess.run(
                    [
                        executable,
                        "buildx",
                        "imagetools",
                        "inspect",
                        image,
                        "--format",
                        "{{json .SBOM}}",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=60,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError):
                return False
            if result.returncode != 0:
                return False
            try:
                sbom = json.loads(result.stdout or "null")
            except json.JSONDecodeError:
                return False
            if not self._sbom_is_valid(sbom, platforms):
                return False
        return True

    @staticmethod
    def _sbom_is_valid(sbom: object, platforms: list) -> bool:
        if not isinstance(sbom, dict) or not sbom:
            return False

        def _one(entry: object) -> bool:
            return (
                isinstance(entry, dict)
                and isinstance(entry.get("SPDX"), dict)
                and entry["SPDX"].get("SPDXID") == "SPDXRef-DOCUMENT"
            )

        # Multi-platform form: {"linux/amd64": {"SPDX": {...}}, ...}
        keyed = {k: v for k, v in sbom.items() if isinstance(v, dict) and "SPDX" in v}
        if keyed:
            required = {f"linux/{arch}" for arch in platforms if arch}
            if required and not required.issubset(set(keyed)):
                return False
            return all(_one(v) for v in keyed.values())
        # Single-document form.
        return _one(sbom)
