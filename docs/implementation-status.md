# AZ-06 Implementation Status

Last updated: 2026-09-19

This document separates **implemented software properties** from **field/HIL
properties that are not yet proven**. A green unit/CI suite is not a claim of
safe live deception deployment.

## Implemented now

### Canonical contracts

AZ-06 consumes the Azazel-Fabric `azazel_fabric.deception_contracts`
family through an exact stable release tag. The pinned tag is stated in exactly
one place — the `azazel-fabric` requirement in `pyproject.toml`, described in
[`docs/fabric-pin.md`](fabric-pin.md). This document deliberately does not
restate the version, so it cannot drift out of date behind a pin bump.

Implemented canonical boundaries include:

- `DeceptionPackage`
- `HostCapabilities`
- `RuntimeRequirements`
- `DeploymentTier`
- `ImageManifest`
- `PlacementPlan`
- Edge-owned activation / transition / termination decisions
- environment events and outcomes

The former `bootstrap-v0.1` package shape is compatibility input only and is
normalized immediately into the canonical model.

### Canonical package content digest

`package_digest` is a deterministic *semantic* content digest with exactly one
definition:

```text
raw mapping / bootstrap shape
    -> Fabric DeceptionPackage normalization (types, defaults, ordering)
    -> canonical semantic payload (package_digest + signature_ref removed)
    -> deterministic JSON serialization
    -> SHA-256
```

Because the digest is always computed from the *normalized model*, the same
semantic content yields an identical digest whether it arrives as a raw dict, a
Pydantic model dump, a YAML reload, or a JSON round-trip. Hashing an
un-normalized raw mapping is deliberately never done: integer/float coercion
(`2` vs `2.0`), omitted-vs-default fields (`bandwidth_kbps`), and key ordering
would otherwise cause digest drift. This closed the earlier integrity failure
where the declared digest was derived from the raw YAML while validation
recomputed it from the normalized model.

Sealing and validation are separated:

- `seal_package_digest` (authoring time) computes and stamps the digest and
  never mutates its input.
- `parse_package` / `validate_package` (runtime) only verify that a declared
  digest matches the recomputed canonical digest, fail-closed, and never
  silently repair a bad digest.

`package_digest` binds every semantic field — narrative, runtime requirements,
maximum budget, safety invariants, image manifest/platform digests,
provenance/SBOM references, deployment tiers, credentials, and `signer_ref` —
except the digest field itself and the detached `signature_ref` locator. The
detached locator can be rotated after signing without changing the content
digest. Dangerous mutations that Fabric encodes as closed literals
(`synthetic_only`, `outbound_allowed`, `production_access`, tier identity) fail
closed at the schema layer before the digest check.

CLI/Make surface: `azazel-deception digest`, `azazel-deception canonical-payload`,
and `azazel-deception seal` (seal emits to stdout/`--output`; it never rewrites
the source package in place).

### Portable placement and development hosts

- `arm64` and `amd64` are canonical Phase-1 architectures.
- Capability reports are `descriptive_only`.
- Placement plans are `descriptive_only`.
- Package-authored tiers may not omit required components.
- Shared Fabric golden fixtures are consumed by both AZ-06 and Azazel-Edge CI.
- Apple Silicon macOS capability discovery is supported for development; memory is read through native `sysctl`, while KVM/network-namespace/nftables remain correctly absent from the macOS host capability claim.
- GitHub Actions validates the same contracts natively on Linux `amd64`, Linux `arm64`, and macOS `arm64`.
- Native Linux ARM64 and AMD64 jobs start the same digest-pinned reference Compose runtime and archive machine-readable portability evidence.

The current developer profile is documented in `docs/development-mac-arm64.md`.
A physical AMD64 workstation is not a Phase-1 software-development blocker;
field/HIL claims remain separate.

### Reference multi-architecture OCI image

`ghcr.io/01rabbit/azazel-deception-reference-web` is built from the repository
source on native GitHub-hosted Linux runners for both architectures.

Current Phase-1 immutable image metadata:

This metadata must match the digests pinned in
`examples/packages/municipal-linux-v1/package.yaml` and
`runtime/compose/reference-linux.compose.yaml`:

- multi-architecture manifest: `sha256:c187c4ce32a244a45848bceee7ce9aa5c0146bd42e5dc0e03844e56083e2a043`
- AMD64 manifest: `sha256:c5a93538074b500e3bc4e1b6387655aeb23c31e68e42c4370822cd92fc3160f8`
- ARM64 manifest: `sha256:a91395cf3b1de630917d05387585fe2783609f859961f5813c99e0ff7e89e6da`
- GitHub build-provenance attestation: `github-attestation:40368115`
- SBOM: OCI-attached SPDX per platform (`oci-attached-spdx:…@sha256:c187c4ce…`)

The provenance attestation is signed through the public Sigstore service and
recorded by GitHub. The package and Compose reference the immutable
multi-architecture digest rather than a mutable tag.

The reference web component is marked `ImageManifest.verified: true`, justified
by the attached per-platform SPDX SBOM and GitHub/Sigstore build provenance.
This alone does **not** authorize live activation: an injected trusted
`PackageVerifier` (the GitHub attestation verifier) must still accept the
package, and package-level SBOM-policy verification remains pending. The
optional `evidence-sidecar-placeholder` (alpine) stays `verified: false`.

### Runtime lifecycle

The Docker Compose adapter now has bounded lifecycle methods for capability
inspection, validation, planning, activation, status, termination, reset, and
evidence export.

A strict live posture makes the injected security gates mandatory:
`require_sbom_verification` and `require_authenticated_decisions` reject a live
activation when the corresponding SBOM verifier or decision authenticator is not
configured (a trusted package verifier is always mandatory). `health()` reports
the posture and which gates are configured.

The strict posture is the **enforced default for the reference deployment**:
`build_reference_adapter()` (`runtime/posture.py`) sets both flags, and every
reference entry point — `runtime-status`, `runtime-reconcile`, and the virtual
lab — is constructed through it. The only relaxation is an explicit dev opt-out
(`--dev-relaxed-posture` / `AZAZEL_DECEPTION_RELAXED_POSTURE=1`). The library
`DockerComposeAdapter` keeps permissive explicit defaults for unit callers only,
so a direct constructor call is not a reference deployment.

An operator kill switch (`DockerComposeAdapter.emergency_stop`) halts an
environment on operator authority alone — no Edge decision required or consumed.
It is fail-safe: it always records the operator intent as evidence, best-effort
stops the container, and surfaces a stop failure as a `kill_switch_failed` state
rather than silently swallowing it. A descriptive status/health surface
(`DockerComposeAdapter.health` and `azazel-deception runtime-status`) reports
adapter configuration and local runtime state; it authorizes nothing.

A Virtual Phase-1 Lab (`make virtual-lab`, `scripts/dev/virtual_phase1_lab.py`)
drives the complete software lifecycle — package, placement, preflight,
controlled activation, evidence, termination, reset — against a real container
with the real GitHub attestation verifier, on an internal-only network with no
published host ports.

The lab is a **manual developer command**, not recorded evidence: no workflow
invokes it, and its report is written to `artifacts/lab/virtual-phase1-lab.json`,
which `.gitignore` excludes. `tests/test_virtual_lab.py` covers the driver's
logic with the compose invocation monkeypatched and starts no container. So the
real-container lifecycle gate is **open**, not checked — see
[`live-gate-checklist.md`](live-gate-checklist.md). The lab is also explicitly
**not** a physical/HIL isolation proof.

Live activation has multiple independent gates:

1. `AZAZEL_DECEPTION_LIVE=1` must be explicitly configured.
2. An accepted/modified, unexpired Azazel-Edge activation decision is required.
3. Decision ID, package ID/digest, target node, tier, and placement binding must match.
4. The selected tier minimum must fit inside the Edge allocation.
5. The Edge allocation must fit inside the package maximum resource budget.
6. Live allocation must contain an explicit finite bandwidth budget.
7. Every **placement-selected** component OCI manifest must be `verified=true`; unselected optional components do not incorrectly block a smaller tier.
8. Every verified selected component must carry a real (non-placeholder, non-`bootstrap:`) `provenance_ref` and `sbom_ref`.
9. The Compose asset must pass the static isolation policy.
10. A trusted package-verification hook must be configured and accept the package; `verified=true` metadata alone is insufficient.
11. The selected Package component set must exactly match the Compose service set, and every Compose `image:` must match the package manifest.
12. The Edge decision ID is consumed atomically and cannot be reused.

Current `main` does **not** provide an activatable reference decoy. The
reference image carries attached SPDX SBOMs and build provenance, the canonical
package-attestation verifier exists, and its end-to-end attestation run has been
executed green (run `31660034975`, below). What is still pending is reviewed
SBOM-*content* policy verification; live activation stays default-off behind the
trusted `PackageVerifier` gate and the open items in
[`live-gate-checklist.md`](live-gate-checklist.md).

### Authenticated Edge-decision transport

AZ-06 does not own Edge decision authority or the wire contract, but it does
verify, before acting, that an incoming Edge decision is authentic and
untampered. `HmacDecisionAuthenticator` checks an HMAC-SHA256 signature over the
canonical decision bytes (the decision minus its signature field), fail-closed,
using an operator-supplied key that is never stored in the repository. It is
wired as an injected gate on both activation and termination, runs
before the decision is consumed, and combines with the one-shot decision ledger
(anti-replay) and decision expiry (freshness) to protect the decision transport.
`sign_decision` is the symmetric Edge-side helper used by tests and the lab.
The authenticator is **mandatory** for the reference deployment
(`require_authenticated_decisions=True` in `build_reference_adapter`); it stays
optional only for direct library callers. What remains open is the *proof* of a
full networked, mutually-authenticated Edge↔AZ-06 transport in a lab, and
continuous key distribution/rotation — see
[`live-gate-checklist.md`](live-gate-checklist.md).

### Edge heartbeat freshness and state reconciliation

`heartbeat_is_fresh` fails closed on a stale, absent, or implausibly-future Edge
heartbeat, so a live control plane can refuse to act on outdated authority.
`DockerComposeAdapter.reconcile_with_edge` (and the read-only `runtime-reconcile`
CLI) reports divergence between local runtime state and Edge's authoritative
active set — `local_only_active` (running locally but unauthorized; kill-switch
candidates) and `edge_only_active` (Edge expects active but missing locally). It
is descriptive-only: acting on a divergence still requires an Edge decision or
the operator kill switch.

The authenticated `heartbeat` / `reconcile` actions on the AZ-06 shadow/replay
service are implemented and covered by `tests/test_shadow_heartbeat.py`, and the
polling `HeartbeatLoop` exists on the Edge side. The **end-to-end proof is
open**: `Azazel-Edge/tests/test_deception_shadow_heartbeat_e2e.py` begins with
`pytest.importorskip("azazel_deception")` and Edge CI never installs this
package, so that test skips in every recorded run. See
[`live-gate-checklist.md`](live-gate-checklist.md).

### Static runtime isolation policy

Compose validation rejects at least:

- local `build:` directives
- missing image declarations
- root/default-root decoy execution
- capability re-addition after `cap_drop: ALL`
- privileged containers
- host network / host PID / host IPC / host user namespace
- published host ports
- missing read-only rootfs
- missing `cap_drop: ALL`
- missing `no-new-privileges`
- missing CPU, memory, or PID limits
- non-internal network attachment
- Docker/Podman/containerd socket mounts
- sensitive `/proc`, `/sys`, or `/dev` host mounts

The reference web decoy runs as UID/GID `101:101` on unprivileged TCP/8080,
uses a read-only root filesystem with a bounded `/tmp` tmpfs, has all Linux
capabilities dropped, and publishes no host port. Edge remains responsible for
attacker-flow channeling/routing.

### Supply-chain/runtime binding

- `ImageManifest.verified` is treated as evidence state, not cryptographic proof.
- A component selected to run and marked `verified=true` must carry a real
  (non-placeholder, non-`bootstrap:`) `provenance_ref` and `sbom_ref`; the live
  activation gate fails closed otherwise, before Docker is touched. This binds
  the `verified` flag to actual supply-chain references but is not itself
  cryptographic SBOM verification.
- Live runtime requires an injected trusted `PackageVerifier`.
- `OciAttachedSbomVerifier` retrieves the OCI-attached SPDX SBOM for every
  verified image at its immutable `@sha256:` digest and requires a well-formed
  per-platform SPDX document, fail-closed. It is wired as an optional injected
  live gate (`sbom_verifier`) and required by the reference deployment's strict
  posture. `GitHubSbomVerifier` provides the stronger Sigstore-attestation
  variant for when the image publishes a GitHub SPDX attestation. The
  `make virtual-lab --sbom-verify` run against the real image is a manual
  developer run, not recorded evidence. What remains is reviewed SBOM-*content*
  policy (license/component allow-lists).
- `GitHubAttestationPackageVerifier` verifies the reconstructed canonical
  payload bytes (not YAML) against a GitHub artifact attestation. It pins the
  repository, signer-workflow identity, and source git ref (`--source-ref`,
  default `refs/heads/main`, so an attestation built from another branch/tag is
  rejected), passes `--deny-self-hosted-runners`,
  fails closed when `gh` is absent, on any CLI non-zero exit, on subprocess
  exception/timeout, on a non-`github-attestation:` `signature_ref`, and on a
  content-digest mismatch before any external call. A `verified: true` field in
  attestation output alone never grants trust.
- The `Reference Package Attestation` workflow
  (`.github/workflows/reference-package.yml`) reconstructs the canonical
  payload, asserts its SHA-256 equals `package_digest`, produces a GitHub
  artifact attestation over those exact bytes, and re-verifies with the pinned
  signer identity. No secret signing key is stored in the repository. This
  workflow has an executed green run on `main` (run `31660034975`): the
  in-workflow `gh attestation verify` against the real Sigstore attestation
  passed, so the package-attestation path is proven end-to-end, not only in
  mocked unit tests.
- Local Compose services cannot add an unmanifested workload or omit a selected workload.
- Local Compose image substitution fails closed.
- Local image builds are forbidden in attacker-facing Compose assets.
- Runtime failure after decision consumption produces explicit `failed` state and failure evidence; the consumed Edge decision is not restored.
- The reference image is digest-pinned and has real per-platform OCI digests plus GitHub/Sigstore build provenance.

### Anti-replay and reset

- Edge activation/termination decision IDs use an atomic one-shot ledger.
- A consumed decision stays consumed even if the later runtime operation fails; retry requires a new Edge decision.
- Termination decisions expire.
- Reset refuses an active environment.
- Runtime state is deleted on reset while required evidence is retained.
- Evidence is a tamper-evident hash chain: each record embeds its sequence
  number, the previous record's hash, and its own hash, so any in-place edit,
  reordering, or middle deletion/truncation of a record breaks
  `verify_evidence_chain` (`DockerComposeAdapter.verify_evidence`), as
  `tests/test_evidence_chain.py` and
  `tests/test_shadow_server.py::test_every_request_is_audited_with_intact_evidence_chain`
  prove. The virtual lab asserts the same end-to-end, but is a manual run (see
  above). Two cases are out of local scope:
  a full-file rewrite (unkeyed chain) and tail truncation (dropping only the
  last records leaves a valid prefix). Both are covered by exporting
  `evidence_head_hash` to an external append-only anchor, whose value changes
  under either.

### Edge shadow/replay

Azazel-Edge has a Fabric-backed AZ-06 shadow evaluator that validates package,
capability, placement, architecture, runtime, component set, provenance, and
Edge decision binding.

It returns only `would_accept` / `would_reject` and fixes
`enforcement_applied=false`. It contains no Docker, VM, nftables, tc, route,
or other execution logic.

## Not yet proven / deliberately disabled

The following are still open gates:

- reviewed SBOM-*content* policy (e.g. license/component allow-lists) in the trusted verifier; SBOM *attestation* verification itself is implemented (`OciAttachedSbomVerifier` / `GitHubSbomVerifier`) and required by the reference deployment's default strict posture
- HIL proof of protected-network isolation and denied decoy egress
- physical NIC/VLAN and management-plane separation validation
- host-restart and route-drift failure injection in an appropriate Linux lab. Runtime-daemon restart and resource exhaustion are *written* in `tests/test_docker_integration.py`, but that module is opt-in behind `AZAZEL_DECEPTION_DOCKER_TESTS=1` and no workflow sets it, so it has never been executed in a recorded run
- any real-container proof: the full activation/evidence/termination/reset lifecycle and the attacker-modified termination/reset with evidence finalization are asserted only by the same opt-in, never-executed `tests/test_docker_integration.py`, and by the manual `make virtual-lab` whose report is git-ignored
- the combined networked Edge→AZ-06 live flow and HMAC key distribution/rotation. The authenticated bi-directional transport, heartbeat loop and state reconciliation are implemented on both sides, but the cross-repo E2E (`Azazel-Edge/tests/test_deception_shadow_heartbeat_e2e.py`) `importorskip`s `azazel_deception` and Edge CI does not install it, so it skips in every recorded run
- end-to-end operator kill-switch control against a live, attacker-modified container (HIL)
- live routing/channeling integration from Edge
- Knowledge outcome ingest/effectiveness loop
- dynamic narrative, honey artifacts, credential lures, personas, or finite-state transitions

Native Linux ARM64/AMD64 software portability is now continuously exercised in
GitHub Actions. A later physical AMD64 machine may strengthen field
certification, but is not required to continue current software development.

## Phase gate

Do not begin Phase 2 (`Azazel-Deception#6`) merely because the current CI is
green. Phase 2 starts only after Phase 1 proves authority, provenance/SBOM and
package verification, portability, isolation, evidence, and reset properties
at the required assurance level.

## Current issue map

Issue states below were read from GitHub on 2026-09-19. **Open trackers are
`#3`, `#6`, `#28`, `#30`, `#31`, `#35`.** `#1`, `#2`, `#4` and `#5` are closed
and are listed only as history — do not route work to them.

### Open

- `Azazel-Deception#3` — prove one signed reference package on ARM64 and AMD64.
  Native ARM64/AMD64 OCI build/run, immutable multi-arch digest, and provenance
  are integrated; the canonical package-attestation verifier and workflow are
  integrated, unit-tested, and proven by an executed green attestation run on
  `main`. Still open: reviewed SBOM-*content* policy verification, and
  equivalent end-to-end activation/evidence/termination/reset semantics
  demonstrated on both architectures.
- `Azazel-Deception#6` — Phase 2. Intentionally not started; gated by the phase
  gate above.
- `Azazel-Deception#28` — separate Deception lifecycle state from Edge/Gadget
  Defensive State (integration).
- `Azazel-Deception#30` — Presented Terrain engine research: transition,
  fingerprint, and outcome-evidence discipline.
- `Azazel-Deception#31` — static Presented Terrain vertical slice. **The v0
  slice it specifies is delivered**: `src/azazel_deception/runtime/
  presented_terrain.py` with `tests/test_presented_terrain_evidence.py`,
  `tests/test_presented_terrain_producer_evidence.py` and
  `tests/test_presented_terrain_outcome_export.py` (21 tests), merged as PR #32
  / #34, CI and Portability green on `main`. Every acceptance box in the issue
  body is checked. It remains open as the tracker for the follow-on work its
  body explicitly excludes: adaptive transitions, live dynamic route control,
  static-vs-adaptive fingerprint experiments, the full
  materialization-to-Knowledge benchmark, and credential-invalidation
  implementation beyond evidence-reference semantics.
- `Azazel-Deception#35` — reconcile AZ-06 assurance evidence and define bounded
  Nexus/Boot Lite profiles.

### Closed (history only)

- `Azazel-Deception#1` — canonical Fabric contract migration. Closed
  2026-08-22.
- `Azazel-Deception#2` — feature-disabled Docker Compose lifecycle adapter.
  Closed 2026-08-21.
- `Azazel-Deception#4` — isolation/evidence/termination/reset test harness.
  Closed 2026-08-21. HIL and physical failure injection did **not** close with
  it; they remain open in `docs/live-gate-checklist.md`.
- `Azazel-Deception#5` — Edge shadow/replay integration. Closed 2026-08-21.
  The combined networked live flow remains an open live-gate item.
