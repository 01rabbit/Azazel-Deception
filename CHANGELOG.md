# Changelog

All notable changes to **AZ-06 Azazel-Deception** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

No stable version has been released yet: the project is in Phase 0–1 bootstrap
and live attacker-facing activation remains disabled by default. Work in progress
lives under **[Unreleased]**; on a release it is renamed to the version and dated,
and a fresh empty [Unreleased] is started.

## [Unreleased]

Development toward `0.2.0`: canonical Azazel-Fabric contracts plus the Phase-1
integrity, supply-chain, transport, and operational-control foundation. Live
activation stays default-off; Phase 2 is not started; physical/HIL properties
are not proven (see `docs/live-gate-checklist.md`).

### Added

- **Canonical package content digest** — a normalize-first, representation-invariant
  `package_digest` pipeline (raw/bootstrap → Fabric model → canonical payload →
  deterministic JSON → SHA-256). Same meaning hashes identically across raw dict,
  model, YAML reload, and JSON round-trip. `seal_package_digest` (authoring) and
  `validate`/`parse` (runtime, fail-closed) are separated.
- **Package attestation verification** — `GitHubAttestationPackageVerifier` verifies
  the reconstructed canonical payload bytes (not YAML) against a GitHub artifact
  attestation, pinning repository, signer-workflow path, and source git ref
  (`--source-ref`, default `refs/heads/main`), denying self-hosted runners. New
  `.github/workflows/reference-package.yml` signs the canonical payload (keyless
  OIDC/Sigstore) and re-verifies it; proven end-to-end in CI.
- **SBOM verification** — `OciAttachedSbomVerifier` validates the OCI-attached SPDX
  SBOM of every verified image at its immutable digest (proven against the real
  reference image); `GitHubSbomVerifier` covers the GitHub SPDX-attestation variant.
- **Authenticated Edge-decision transport** — `HmacDecisionAuthenticator` /
  `sign_decision` verify an HMAC-SHA256 over the canonical decision bytes before
  AZ-06 acts, fail-closed and before the one-shot decision is consumed;
  `heartbeat_is_fresh` fails closed on stale/absent/future heartbeats.
- **Strict live posture** — `require_sbom_verification` / `require_authenticated_decisions`
  make the injected gates mandatory for live activation (default off).
- **Operator kill switch and status surface** — `emergency_stop` halts an environment
  on operator authority alone (no Edge decision), fail-safe; read-only `health()`
  and `reconcile_with_edge()` operator surfaces.
- **Tamper-evident evidence** — evidence is a hash chain (`verify_evidence_chain`),
  with `evidence_head_hash` as an external anchor primitive.
- **Supply-chain binding** — a verified selected component must carry real,
  non-placeholder provenance and SBOM references; static tests bind the reference
  Compose image to the package manifest by immutable digest.
- **Virtual Phase-1 Lab** — `make virtual-lab` (`scripts/dev/virtual_phase1_lab.py`)
  drives package → placement → preflight → activation → evidence → termination →
  reset against a real container, with `--sbom-verify`, `--authenticate`, `--strict`.
  Software-lifecycle proof only, not physical isolation.
- **CLI commands** — `digest`, `canonical-payload`, `seal`, `runtime-status`,
  `runtime-reconcile`; **Make targets** — `digest`, `seal`, `canonical-payload`,
  `virtual-lab`.

### Added

- **Authenticated Edge shadow/replay service** —
  `azazel_deception.runtime.shadow_server` provides the strictly non-executing
  network boundary for Edge integration (issue #5): HMAC-SHA256-signed
  request/response envelopes, Edge-identity allowlisting, AZ-06 node binding,
  `issued_at` freshness, one-shot request anti-replay, and deterministic
  rejection reason codes. Actions cover capability discovery, package
  identity, decision-bound deterministic placement plans, and
  activation/termination rehearsal via new `DockerComposeAdapter`
  `shadow_activation`/`shadow_termination` methods that run the canonical
  validation and binding gates without consuming the one-shot decision
  ledger, writing runtime state, or starting a container. Every request is
  appended to the tamper-evident evidence log for Edge audit. The matching
  Edge client and a real networked E2E (full bootstrap session over HTTP with
  zero container start) live in Azazel-Edge.
- **GH-store SPDX attestation for the pinned reference image** — the SBOM
  workflow gains an `attest-existing-sbom` dispatch path that republishes the
  SPDX documents already attached to an immutable manifest digest as GitHub
  SPDX attestations and self-verifies with the exact `gh attestation verify`
  invocation `GitHubSbomVerifier` uses. No rebuild: the pinned digest and the
  sealed `package_digest` stay unchanged. Executed green for
  `sha256:c187c4ce…` (run `31798338588`), so the GitHub-attestation SBOM
  verifier now passes against the reference image.
- **Real-Docker lifecycle integration tests** —
  `tests/test_docker_integration.py` (opt-in, `AZAZEL_DECEPTION_DOCKER_TESTS=1`)
  drives the actual adapter against a real daemon and the pinned reference
  image: gated activation with runtime isolation assertions (read-only rootfs,
  `cap_drop ALL`, no-new-privileges, non-root, internal-only network, no
  published ports, CPU/memory/PID limits), attacker-modification destruction
  across termination/re-activation, container-crash recovery via the operator
  kill switch, an injected teardown fault failing closed with kill-switch
  recovery, Edge reconciliation divergence reporting, deterministic reset with
  evidence preservation, and evidence-chain tamper detection.

### Changed

- Azazel-Fabric dependency pin moved from the reviewed development commit to
  the stable release tag `v0.5.0` (`pyproject.toml`, `docs/fabric-pin.md`);
  field/release packaging now consumes a tagged Fabric release as required by
  the live-gate checklist.
- Reference package `examples/packages/municipal-linux-v1/package.yaml` re-sealed
  via tooling (canonical digest), not a hand-copied CI value.
- Bootstrap compatibility adapter preserves the caller's declared digest so
  bootstrap input is also fail-closed (usable only after an explicit seal).
- Documentation reconciled to the actually-pinned reference image and updated
  across `README.md`, `docs/implementation-status.md`, `docs/live-gate-checklist.md`,
  and `docs/development-mac-arm64.md`.

### Fixed

- **Root cause of the Package integrity CI failures**: `package_digest` was
  derived from the raw YAML mapping (int `2`, omitted fields) while validation
  recomputed it from the normalized Fabric model (float `2.0`, explicit `null`).
- Verifier temp-file path traversal via an attacker-influenced `package_id`.
- Operator kill switch reporting `terminated` on a retry after a failed stop
  while the container could still be running.
- `heartbeat_is_fresh` rejecting `Z`-suffixed UTC timestamps on Python 3.10.
- `health()` / `reconcile_with_edge()` crashing on a single corrupt state file.

### Security

- All new runtime gates are fail-closed and run before the one-shot Edge decision
  is consumed; a rejected decision is not burned.
- Live activation remains **default-off**; the responsibility boundary is preserved
  (Edge owns decisions, Fabric owns wire contracts, AZ-06 only verifies). Phase 2
  and physical/HIL certification are explicitly out of scope for this cycle.

## [0.1.0] - 2026-08-13

### Added

- Initial AZ-06 Azazel-Deception repository and ratified responsibility boundary.
- Bootstrap control plane: host capability discovery, fail-closed package
  validation, deterministic non-executing placement planning, a synthetic Linux
  reference package, isolated Docker Compose reference assets, CI, tests, and
  safety/integration documentation.
- Adoption of the canonical Azazel-Fabric deception contracts (pinned commit) and
  a multi-architecture reference OCI image with attached SPDX SBOMs and
  GitHub/Sigstore build provenance.
