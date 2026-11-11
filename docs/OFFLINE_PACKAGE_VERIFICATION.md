# Optional offline package authenticity

`OfflineGitHubAttestationPackageVerifier` verifies the existing canonical
Deception package bytes with a separately provisioned GitHub CLI, local Sigstore
bundle and local trusted-root snapshot. It is an optional injected verifier;
reference adapters, production defaults, activation and network configuration
are unchanged. It supplies only the package-authenticity gate. SBOM verification,
Edge authorization, isolation, runtime identity and admission remain separate.

The fixed policy matches the existing reference package verifier:

- repository `01rabbit/Azazel-Deception`;
- signer workflow `01rabbit/Azazel-Deception/.github/workflows/reference-package.yml`;
- source ref `refs/heads/main`, GitHub Actions OIDC and no self-hosted runners;
- predicate `https://slsa.dev/provenance/v1`;
- existing `signer_ref`, `github-attestation:` locator and canonical content
  digest validation before the CLI runs.

The signed subject is the reconstructed canonical semantic payload, never YAML
formatting or the detached signature locator. Package IDs never form filenames.
The CLI performs Sigstore cryptography; this module implements no signature,
certificate, timestamp or transparency-log verification of its own.

## Online preparation, separate from offline verification

Prestage these public artifacts through a trusted, reviewed preparation process.
Use a new private directory; do not overwrite previous evidence:

```sh
mkdir -m 700 /absolute/new-offline-package-stage
python -m azazel_deception canonical-payload \
  examples/packages/municipal-linux-v1/package.yaml \
  --output /absolute/new-offline-package-stage/package.signing.json
cd /absolute/new-offline-package-stage
gh attestation download package.signing.json \
  --repo 01rabbit/Azazel-Deception \
  --predicate-type https://slsa.dev/provenance/v1
gh attestation trusted-root > trusted_root.jsonl
```

These preparation commands use the network. The download produces a
`sha256:DIGEST.jsonl` bundle. The trusted-root command obtains roots covering
GitHub's and Sigstore Public Good instances; older package attestations may use
the latter. Provision the exact platform-native trusted CLI binary as well.
Independently retain/review SHA-256 fingerprints for that binary and trusted-root
snapshot. Never derive those trust anchors from the untrusted package or bundle,
and never accept a root supplied inside a bundle as its own authority.

The installed CLI documentation checked for this implementation is **gh 2.96.0**
(`gh attestation verify --help` and `gh attestation trusted-root --help`). It
supports `--bundle`, `--custom-trusted-root`, `--repo`, `--signer-workflow`,
`--source-ref`, `--deny-self-hosted-runners`, `--predicate-type` and `--hostname`.
It has no `--offline` switch. Explicit local bundle/root files remove those fetch
requirements; use an independently network-disabled environment to demonstrate
that the complete invocation succeeds without networking. A Mac CLI binary
cannot serve as the Linux executable. Older/unsupported CLI behavior refuses.

## Local use and file boundary

Construct the optional verifier explicitly with:

```python
OfflineGitHubAttestationPackageVerifier(
    temporary_parent=Path("/opt/offline-workspace"),
    gh_path=Path("/opt/offline-trust/gh"),
    gh_sha256=reviewed_cli_sha256,
    bundle_path=Path("/opt/offline-trust/package.bundle.jsonl"),
    trusted_root_path=Path("/opt/offline-trust/trusted_root.jsonl"),
    trusted_root_sha256=reviewed_root_sha256,
)
```

The required `temporary_parent` must already exist and be operator-provisioned.
Every physical ancestor and the directory itself must be root/current-UID owned,
without group/other writes or symlinks. Snapshot subdirectories are private 0700.
The module always passes this explicit parent to temporary-directory creation;
ambient TMPDIR/TEMP/TMP and cached stdlib temp paths are ignored. The same trusted
owner/root limitation applies: this is not isolation from malicious same-UID code.

Every input must be a bounded regular single-link file with an absolute literal
path, owned by root or the verifier's UID, without group/other writes, setuid or
setgid. The CLI must be executable. Every ancestor is opened without following
symlinks and must also be root/current-UID owned and protected from group/other
writes. This deliberately rejects symlinked CLI aliases and world-writable
ancestors, including `/tmp`; use the actual installed binary or protected staged
copies. A host-UID-owned bind mount may not qualify for container-root verification.
Limits are 128 MiB CLI, 8 MiB bundle/canonical payload and 1 MiB trusted root.

Reads pin descriptors and compare metadata/identity before and after the bounded
read and against the named entry. Original inputs are never rewritten. Private
fixed-name temporary snapshots include the already hashed CLI, preventing a
hash-one-file/execute-another pathname race. The native loader, platform shared
libraries, OS/kernel and trusted owner remain trusted. This is no defense against
malicious same-UID/root code or an independently approved malicious CLI/root.

The child has fresh private HOME and GH_CONFIG_DIR directories, a fixed minimal
environment and no inherited tokens, proxies, dynamic-loader variables, GitHub
configuration or prompts. It receives no stdin, stdout/stderr are discarded,
and verification has a 30-second deadline. No OCI URL, custom command argument,
network fallback, key, credential or registry retrieval is involved. A missing,
unsafe, oversized, changed, unpinned or rejected artifact, unsupported CLI,
subprocess error or timeout returns false. There is no trust-checkbox bypass.

Offline verification uses the reviewed root snapshot and bundle's verifiable
historical proofs; it cannot fetch current distrust, revocation or root rotation
state. Updating trust snapshots is a separate reviewed operation. Neither a
passing verification nor a package hash authorizes runtime execution.

## Validation and remaining SBOM boundary

`tests/test_offline_package_verifier.py` exercises wrapper policy, path/permission
and identity-change refusals, input bounds, exact independent pins, preserved
files, isolated child configuration and subprocess errors. Mocked CLI success is
explicitly **not** cryptographic-positive evidence.

The opt-in real test requires `AZ06_OFFLINE_ATTESTATION_TEST=1` plus
`AZ06_OFFLINE_GH_PATH`, `AZ06_OFFLINE_GH_SHA256`, `AZ06_OFFLINE_BUNDLE_PATH`,
`AZ06_OFFLINE_ROOT_PATH`, `AZ06_OFFLINE_ROOT_SHA256` and the precreated protected
`AZ06_OFFLINE_TEMP_PARENT`. Run it inside a
network-disabled Linux environment with protected prestaged material. It requires
an actual successful canonical-package verification and actual CLI refusal for
corrupted bundle/root and wrong source-ref, in addition to pin mismatch refusals.
Without that execution, the real test is skipped and offline cryptographic
success remains unproven. Preserve the public source artifacts and fingerprints
with the result; no runtime attestation or activation is performed.

A prestaged Docker image is insufficient to satisfy the SBOM gate. The existing
SPDX attestation workflow signs the image-index digest as its subject and places
SPDX in its predicate. Those bundles cannot verify a standalone SPDX file whose
hash differs. Future offline SBOM work requires the exact local raw OCI
index/manifest bytes matching the package digest, applicable signed bundles,
verified subject-name/digest and platform binding, plus the separately reviewed
SBOM-content policy. This module never substitutes a pin or returns SBOM approval.
