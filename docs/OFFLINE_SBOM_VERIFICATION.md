# Optional offline SPDX authentication and platform binding

`OfflineGitHubSbomVerifier` is an optional injected verifier for the reference
image's existing SPDX attestations and immutable OCI graph. It performs no
registry/API retrieval, Docker operation, publication, activation or default
configuration change. Package authenticity still requires the separate package
verifier; Edge authorization and runtime isolation remain independent gates.

The reference-only scope is deliberately finite: one unique verified image,
exactly declared Linux amd64 and arm64 platforms, four index descriptors and
one unambiguous attestation attachment per platform. Unsupported layouts refuse;
this is not a generic OCI resolver. The optional unverified component remains
outside this verifier, as in the existing SBOM verifier.

## Provisioned interface

Reuse the protected CLI/root fingerprints and explicit workspace described in
[offline package verification](OFFLINE_PACKAGE_VERIFICATION.md). Supply one
operator-provisioned mapping from the exact digest-pinned image URI to:

```python
OfflineImageArtifacts(
    index_path=Path("/opt/offline-trust/index.json"),
    bundle_path=Path("/opt/offline-trust/spdx.bundle.jsonl"),
    artifacts={
        "sha256:ATTESTATION_MANIFEST_DIGEST": Path("/opt/offline-trust/manifest.json"),
        "sha256:SPDX_STATEMENT_DIGEST": Path("/opt/offline-trust/statement.json"),
        # The second platform's exact manifest and statement are also required.
    },
)
```

The constructor is `OfflineGitHubSbomVerifier(gh_path, gh_sha256,
trusted_root_path, trusted_root_sha256, temporary_parent, images)`. Its `images`
map is keyed by the exact image URI, including `@sha256:…`. Artifact paths are
explicit local paths, never names derived from package-controlled strings or
URLs. Require 4–8 digest/path entries; every required graph artifact must be
mapped. Public online staging is a separate trusted preparation operation; the
verifier never downloads missing material or invents a replacement publisher.

The inherited protected-read rules reject symlinks, hardlinks, writable or
untrusted-owner ancestors, changed files and unsafe executables. Snapshots,
including the independently pinned CLI bytes, live in a private directory under
the required protected `temporary_parent`. Ambient temporary directories,
authentication tokens, proxies and GitHub configuration are not inherited.
Original staged artifacts are never rewritten.

## Required proof chain

The verifier checks canonical package content integrity and requires its image
URI, manifest digest and distinct declared platform digests to agree. Then:

1. Raw index bytes must hash to that image-index digest.
2. Each declared platform must have its exact Linux/architecture descriptor and
   one unique unknown/unknown attestation descriptor with
   `vnd.docker.reference.type=attestation-manifest` and the correct
   `vnd.docker.reference.digest`.
3. The mapped attestation manifest must match its exact descriptor byte size and
   SHA-256. Its own OCI subject descriptor must match the platform manifest's
   digest, media type and size.
4. Exactly one layer explicitly marked `https://spdx.dev/Document` must use the
   in-toto media type. The mapped raw layer must match its exact size and hash.
5. Its in-toto statement must carry that SPDX predicate type and 1–4 unique
   subject names, **every** subject digest equal to the platform manifest digest.
   Names and purls are never parsed to infer architecture.
6. The complete strictly parsed SPDX predicate must equal one of the distinct
   predicates returned by the actual successful GitHub CLI verification.

The CLI verifies the raw local index file with the staged Sigstore bundle and
custom trusted root. It preserves the existing `GitHubSbomVerifier` policy:
repository `01rabbit/Azazel-Deception`, predicate
`https://spdx.dev/Document`, GitHub Actions issuer and self-hosted runners denied.
It does not silently add or remove signer-workflow/source-ref constraints: the
existing SBOM verifier has neither, unlike the package verifier. Its two verified
statements must identify the exact image name and index digest. No OCI URL or
fetch fallback is used.

The index/hash graph supplies platform binding; genuine CLI verification supplies
Sigstore authentication. Both are mandatory. A correctly hashed unsigned graph,
a saved verification-result JSON file, a matching SPDXID, a plausible package
inventory or an architecture-looking name cannot independently satisfy the gate.
Duplicate/ambiguous links, duplicate predicates or JSON keys, nonfinite numbers,
missing platforms/artifacts, malformed subjects and predicate mismatches refuse.

## Bounds and process cleanup

Raw index and attestation manifests are limited to 1 MiB each; SPDX statements
are limited to 8 MiB each; the complete selected graph is limited to 20 MiB.
The bundle limit is 8 MiB, root 1 MiB and CLI 128 MiB. SPDX support is currently
2.3, with at most 4,096 packages and 20,000 file entries per document. These are
software bounds, not target Pi resource acceptance.

CLI stdout is read incrementally with a 16 MiB cap and one absolute 30-second
verification deadline. Receiving another output chunk never resets that
deadline. A nonzero exit, timeout, excess output or invalid JSON refuses. Stderr
and stdin are disabled; no raw CLI output, SPDX or credentials are echoed. Every
exit attempts process kill when still alive, bounded reap (up to five extra
seconds for cleanup), and pipe closure. Cleanup failure cannot produce success.
The native loader, shared libraries, trusted CLI/root owners and kernel remain
trusted, as for the offline package verifier.

## Validation and remaining gates

Synthetic graph tests exercise each binding and process/output failure. Their
mocked CLI success is explicitly not cryptographic-positive evidence. The opt-in
real test uses `AZ06_OFFLINE_SPDX_TEST=1`, `AZ06_OFFLINE_SPDX_MAP` and the existing
`AZ06_OFFLINE_GH_PATH`, `AZ06_OFFLINE_GH_SHA256`, `AZ06_OFFLINE_ROOT_PATH`,
`AZ06_OFFLINE_ROOT_SHA256`, `AZ06_OFFLINE_TEMP_PARENT`. The map is JSON with the
same image/index_path/bundle_path/artifacts structure above. Run inside a
network-disabled environment with protected prestaged files and a platform-native
CLI. It requires actual successful verification plus corrupted-bundle, mismatched
index and wrong-root-pin refusals. Without that execution the real test skips;
no fresh offline Sigstore success is claimed from synthetic or saved JSON tests.

The result authenticates the exact SPDX contents and their platform association.
It does not approve licenses/components, validate every SPDX semantic constraint,
prove completeness or vulnerability freedom, attest a running container, establish
fresh revocation state, approve production materialization, or close reviewed
SBOM-content, efficacy, network isolation or hardware/HIL gates. Root rotation and
trust snapshots remain independently provisioned, reviewed inputs.
