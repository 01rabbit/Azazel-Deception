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

### Portable placement

- `arm64` and `amd64` are canonical Phase-1 architectures.
- Capability reports are `descriptive_only`.
- Placement plans are `descriptive_only`.
- Package-authored tiers may not omit required components.
- Shared Fabric golden fixtures are consumed by both AZ-06 and Azazel-Edge CI.

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
7. All component OCI manifests must be `verified=true`.
8. The Compose asset must pass the static isolation policy.
9. A trusted package-verification hook must be configured and accept the package; `verified=true` metadata alone is insufficient.
10. The selected Package component set must exactly match the Compose service set, and every Compose `image:` must match the package manifest.
11. The Edge decision ID is consumed atomically and cannot be reused.

The current reference package intentionally fails the supply-chain gates because
its OCI provenance/SBOM/digests remain bootstrap placeholders and no production
package-signature verifier is configured. Therefore current `main` does **not**
provide an activatable reference decoy.

### Static runtime isolation policy

Compose validation rejects at least:

- local `build:` directives
- missing image declarations
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

Edge remains responsible for attacker-flow channeling/routing; AZ-06 Compose
assets do not publish attacker-facing host ports themselves.

### Supply-chain/runtime binding

- `ImageManifest.verified` is treated as evidence state, not cryptographic proof.
- Live runtime requires an injected trusted `PackageVerifier`.
- Local Compose services cannot add an unmanifested workload or omit a selected workload.
- Local Compose image substitution fails closed.
- Local image builds are forbidden in attacker-facing Compose assets.
- Runtime failure after decision consumption produces explicit `failed` state and failure evidence; the consumed Edge decision is not restored.

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
- real OCI image digests, signatures/provenance, and SBOM verification
- production implementation of the trusted package-signature verifier
- one real signed package executed on both physical/emulated ARM64 and AMD64
- HIL proof of network isolation and denied decoy egress
- resource-exhaustion and runtime-daemon failure injection
- Edge-to-AZ-06 authenticated transport / heartbeat / state reconciliation
- real evidence finalization and reset after an attacker-modified live container
- live routing/channeling integration from Edge
- Knowledge outcome ingest/effectiveness loop
- dynamic narrative, honey artifacts, credential lures, personas, or finite-state transitions

## Phase gate

Do not begin Phase 2 (`Azazel-Deception#6`) merely because the current CI is
green. Phase 2 starts only after Phase 1 proves authority, provenance,
portability, isolation, evidence, and reset properties in an appropriate lab.

## Current issue map

- `Azazel-Deception#1` — canonical Fabric contract migration: code integrated; stable tag/migration exit still open
- `Azazel-Deception#2` — lifecycle adapter: code integrated and heavily gated; live lab/signing validation still open
- `Azazel-Deception#3` — shared ARM64/AMD64 semantic fixtures: CI integrated; real signed multi-arch package proof still open
- `Azazel-Deception#4` — static isolation/reset/anti-replay tests integrated; HIL/failure injection still open
- `Azazel-Deception#5` — Edge shadow evaluator integrated; authenticated E2E shadow transport still open
- `Azazel-Deception#6` — intentionally not started
