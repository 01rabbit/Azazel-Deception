# AZ-06 Implementation Status

Last updated: 2026-08-13

This document separates **implemented software properties** from **field/HIL
properties that are not yet proven**. A green unit/CI suite is not a claim of
safe live deception deployment.

## Implemented now

### Canonical contracts

AZ-06 consumes the unreleased Azazel-Fabric `0.5.0.dev0`
`azazel_fabric.deception_contracts` family through an exact reviewed commit
pin.

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

- multi-architecture manifest: `sha256:7278ffb05be16e2f93501c938a26cad371b92a8a8452368dd05c8ea23888433e`
- AMD64 manifest: `sha256:c17897ab9f1d2d0b09901283adb738b6c4e39af339600ad73b5466f2f85eecaf`
- ARM64 manifest: `sha256:9da14c58e96c42b9a87b2a8bb05a361d4be882b9863c0e3c1dd155789f0816ca`
- GitHub build-provenance attestation: repository attestation `40366214`
- source workflow run: `31640821303`

The provenance attestation is signed through the public Sigstore service and
recorded by GitHub. The package and Compose reference the immutable
multi-architecture digest rather than a mutable tag.

**SBOM and package-level signing are still pending**, therefore the canonical
`ImageManifest.verified` state deliberately remains `false` and live activation
remains blocked.

### Runtime lifecycle

The Docker Compose adapter now has bounded lifecycle methods for capability
inspection, validation, planning, activation, status, termination, reset, and
evidence export.

Live activation has multiple independent gates:

1. `AZAZEL_DECEPTION_LIVE=1` must be explicitly configured.
2. An accepted/modified, unexpired Azazel-Edge activation decision is required.
3. Decision ID, package ID/digest, target node, tier, and placement binding must match.
4. The selected tier minimum must fit inside the Edge allocation.
5. The Edge allocation must fit inside the package maximum resource budget.
6. Live allocation must contain an explicit finite bandwidth budget.
7. Every **placement-selected** component OCI manifest must be `verified=true`; unselected optional components do not incorrectly block a smaller tier.
8. The Compose asset must pass the static isolation policy.
9. A trusted package-verification hook must be configured and accept the package; `verified=true` metadata alone is insufficient.
10. The selected Package component set must exactly match the Compose service set, and every Compose `image:` must match the package manifest.
11. The Edge decision ID is consumed atomically and cannot be reused.

Current `main` does **not** provide an activatable reference decoy because the
reference package still lacks SBOM-backed image verification and a production
package-signature verifier.

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
- Live runtime requires an injected trusted `PackageVerifier`.
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

### Edge shadow/replay

Azazel-Edge has a Fabric-backed AZ-06 shadow evaluator that validates package,
capability, placement, architecture, runtime, component set, provenance, and
Edge decision binding.

It returns only `would_accept` / `would_reject` and fixes
`enforcement_applied=false`. It contains no Docker, VM, nftables, tc, route,
or other execution logic.

## Not yet proven / deliberately disabled

The following are still open gates:

- no stable Azazel-Fabric `v0.5.x` release exists yet; stable remains `v0.4.0`
- SBOM generation/attachment and reviewed SBOM verification for the reference image
- production package signing and trusted package-signature verifier
- canonical calculation/replacement of the current package-level bootstrap digest/signature fields
- HIL proof of protected-network isolation and denied decoy egress
- physical NIC/VLAN and management-plane separation validation
- resource-exhaustion and runtime-daemon/host failure injection in an appropriate Linux lab
- Edge-to-AZ-06 authenticated transport / heartbeat / state reconciliation
- real evidence finalization and reset after an attacker-modified live container
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

- `Azazel-Deception#1` — canonical Fabric contract migration: code integrated; stable tag/migration exit still open
- `Azazel-Deception#2` — lifecycle adapter: code integrated and heavily gated; live lab/signing validation still open
- `Azazel-Deception#3` — native ARM64/AMD64 OCI build/run + immutable digest + provenance integrated; SBOM/package signing verification still open
- `Azazel-Deception#4` — native Compose isolation evidence + static reset/anti-replay tests integrated; HIL/failure injection still open
- `Azazel-Deception#5` — Edge shadow evaluator integrated; authenticated E2E shadow transport still open
- `Azazel-Deception#6` — intentionally not started
