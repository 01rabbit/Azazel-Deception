# AZ-06 Live Activation Gate Checklist

Live attacker-facing activation remains prohibited until every mandatory item
below is satisfied for the target release/profile.

## Contract and authority

- [x] Canonical Fabric package/capability/placement/Edge decision models exist on development main.
- [x] Capability and placement data are descriptive-only.
- [x] Activation and termination require Edge-owned expiring decisions.
- [x] Edge decision IDs are one-shot at AZ-06.
- [x] Package maximum resource budgets exist and Edge allocations cannot exceed them.
- [x] Live Edge allocations require an explicit finite bandwidth budget.
- [ ] Stable compatible Azazel-Fabric `v0.5.x` release exists and consumers pin the tag. (Release prepared and pin moved to `v0.5.0` — Azazel-Fabric#10; flips once the owner pushes the `v0.5.0` tag and Fabric CI publishes the release.)

## Supply chain

- [x] Contract fields exist for image manifest/per-platform digest/provenance/SBOM/verification.
- [x] AZ-06 live adapter rejects `verified=false` selected images.
- [x] `verified=true` metadata alone cannot authorize live execution; an injected trusted `PackageVerifier` is mandatory.
- [x] Selected Package components must exactly match Compose services and image references.
- [x] Local Compose `build:` is forbidden for attacker-facing workloads.
- [x] Reference web image has real immutable multi-architecture OCI and per-platform digests.
- [x] Reference web image has GitHub/Sigstore build-provenance attestation.
- [x] `package_digest` is a normalize-first, representation-invariant canonical content digest; declared digest is sealed by tooling and re-derived in tests, not hand-copied.
- [x] Package attestation signs the reconstructed canonical payload bytes (not YAML); `GitHubAttestationPackageVerifier` pins repo + signer-workflow identity, denies self-hosted runners, and fails closed on missing `gh`, CLI failure, subprocess error/timeout, bad `signature_ref` scheme, or content-digest mismatch.
- [x] The `Reference Package Attestation` workflow has an executed green run on GitHub-hosted runners: it reconstructs the canonical payload, asserts its SHA-256 equals `package_digest`, generates a keyless Sigstore attestation, and re-verifies it with `gh attestation verify --deny-self-hosted-runners` against the pinned signer workflow (run `31660034975`).
- [x] The package attestation verifier is proven end-to-end against a real GitHub attestation (the in-workflow `gh attestation verify` step, not a mock, passes).
- [x] A verified selected component must carry a real (non-placeholder, non-`bootstrap:`) `provenance_ref` and `sbom_ref`; the live gate fails closed otherwise.
- [x] `OciAttachedSbomVerifier` retrieves and validates the OCI-attached SPDX SBOM for every verified image at its immutable `@sha256:` digest (fail-closed); it is available as an optional injected live gate and is exercised by `make virtual-lab --sbom-verify`.
- [x] The SBOM is additionally verified via a Sigstore-signed GitHub attestation: the `attest-existing-sbom` dispatch path of the SBOM workflow republishes the digest's attached SPDX documents as GitHub SPDX attestations (no rebuild, digest unchanged) and self-verifies with the exact `gh attestation verify --predicate-type https://spdx.dev/Document --deny-self-hosted-runners` invocation `GitHubSbomVerifier` uses (green run `31798338588` for the pinned `sha256:c187c4ce…` manifest).
- [x] The SBOM gate can be made mandatory via the strict live posture (`require_sbom_verification=True` rejects live activation when no SBOM verifier is configured).
- [x] The strict posture is the enforced default for the reference live deployment: `build_reference_adapter()` constructs the reference adapter with `require_sbom_verification=True` and `require_authenticated_decisions=True` by default, and every reference entry point (`runtime-status`, `runtime-reconcile`, `virtual_phase1_lab`) routes through it. The only relaxation is an explicit dev opt-out (`--dev-relaxed-posture` / `AZAZEL_DECEPTION_RELAXED_POSTURE=1`); the library `DockerComposeAdapter` keeps permissive explicit defaults for unit callers only.
- [x] Attestation signer identity is pinned to a git ref as well as the workflow path: the verifier passes `--source-ref` (default `refs/heads/main`, configurable) so an attestation built from any other branch/tag is rejected. Proven end-to-end — the real verifier accepts the live `refs/heads/main` attestation and rejects a wrong ref. The in-workflow self-verify pins `--source-ref ${{ github.ref }}`.

## Isolation

- [x] Static Compose policy rejects privileged/host namespace/runtime socket/published port/external network configurations.
- [x] Static Compose policy requires non-root execution, read-only rootfs, `cap_drop: ALL`, no capability re-addition, no-new-privileges, and resource limits.
- [x] Native Linux ARM64 and AMD64 CI smoke confirms the digest-pinned reference runtime starts with no host ports, an internal-only Compose network, read-only rootfs, dropped capabilities, no-new-privileges, and CPU/memory/PID limits.
- [ ] HIL confirms no route from decoy workload to protected production network.
- [ ] HIL confirms decoy egress is denied under runtime/route failure cases.
- [ ] HIL confirms attacker traffic cannot reach Edge/AZ-06 management APIs or runtime socket.

## Lifecycle and recovery

- [x] Live execution is default-off.
- [x] Termination decision expiry is enforced.
- [x] Activation/termination anti-replay ledger exists.
- [x] Runtime failure after decision consumption records explicit failure state/evidence and does not restore decision authority.
- [x] Reset preserves evidence while removing local runtime state.
- [x] A real container completes the full activation/evidence/termination/reset software lifecycle via the Virtual Phase-1 Lab (`make virtual-lab`) with the real attestation verifier, on an internal-only network with no published ports.
- [x] Real container termination/reset after **attacker modification** is demonstrated: `tests/test_docker_integration.py` (opt-in via `AZAZEL_DECEPTION_DOCKER_TESTS=1`) writes attacker state into the running decoy, confirms the read-only rootfs refuses persistence, terminates, and proves a fresh activation carries no attacker-modified state; it also demonstrates container-crash recovery and an injected teardown fault failing closed with kill-switch recovery, with the evidence chain finalized and verified.
- [ ] Runtime daemon restart / host restart / resource exhaustion / route drift failure injection passes in an appropriate Linux lab. (Covered in `tests/test_docker_integration.py`: container crash, injected teardown fault, **runtime daemon restart** — dockerd SIGTERM leaves fail-closed state and intact evidence, kill-switch recovers — and **resource exhaustion** — `pids_limit` caps a fork storm, `dd` hits ENOSPC on the 16m tmpfs, a runaway allocation is OOM-killed by `mem_limit` while the main process survives. Host restart and route drift remain HIL.)
- [x] Heartbeat freshness (`heartbeat_is_fresh`) and descriptive state reconciliation (`reconcile_with_edge` / `runtime-reconcile`) building blocks exist: a stale/absent heartbeat is fail-closed, and local-vs-Edge active-set divergence is reported (descriptive-only; acting on it still needs an Edge decision or the kill switch).
- [x] A full authenticated networked heartbeat + automatic state reconciliation loop with Edge is wired end-to-end: the shadow/replay service exposes authenticated `heartbeat` and `reconcile` actions (descriptive-only, all envelope gates applied), and the Edge-side `HeartbeatLoop` polls on an interval, tracks consecutive failures, drives a `reconcile` against the Edge active set after each beat, and fires an `on_divergence` reporting hook — fail-closed, never escaping the thread. Proven by a networked E2E in Azazel-Edge. Continuous key rotation/distribution remains a deployment concern.

## Portability

- [x] Canonical contracts and shared fixtures support ARM64 and AMD64 with one package identity.
- [x] Reference OCI source is built on native Linux ARM64 and native Linux AMD64 GitHub runners and combined into one immutable multi-architecture manifest.
- [x] The same digest-pinned multi-architecture reference runtime is exercised on native Linux ARM64 and AMD64 CI runners.
- [x] Machine-readable portability evidence is archived for both Linux architectures.
- [ ] The package itself is fully signed/verified and `ImageManifest.verified=true` is justified by provenance + SBOM policy.
- [ ] Equivalent end-to-end activation/evidence/termination/reset semantics are demonstrated on both architectures.

A physical AMD64 workstation is **not** a current software-development blocker.
Physical topology/hardware validation remains part of HIL/field certification,
not the native software portability gate.

## Operational integration

- [x] Edge shadow/replay evaluator exists and cannot enforce.
- [x] AZ-06 verifies Edge-decision authenticity before acting: `HmacDecisionAuthenticator` checks an HMAC-SHA256 signature over the canonical decision bytes, fail-closed, wired as an optional injected gate on both activation and termination (the key is operator-supplied, never stored in the repo). Together with the one-shot decision ledger and decision expiry this gives authenticity + anti-replay + freshness.
- [x] The decision authenticator can be made mandatory via the strict live posture (`require_authenticated_decisions=True` rejects live activation/termination when no authenticator is configured).
- [ ] A full networked, mutually-authenticated Edge-to-AZ-06 transport with heartbeat/state reconciliation, key distribution, and the strict posture enforced by default remains open. (Now implemented: mutually-authenticated HMAC transport in both directions with Edge allowlist, node binding, freshness, and anti-replay; the heartbeat + auto-reconciliation loop wired end-to-end and covered by a networked E2E; and the strict posture enforced by default on the reference deployment. Only key distribution/rotation remains as a deployment concern.)
- [ ] End-to-end Edge decision -> AZ-06 activation -> evidence -> termination -> reset is demonstrated in a lab. (Two halves are each demonstrated: the networked Edge shadow session — capabilities, package, decision-bound plan, activation/termination rehearsal, audited with an intact evidence chain and zero container start — and, separately, the local live decision -> activation -> evidence -> termination -> reset lifecycle on real containers in `tests/test_docker_integration.py`. The combined networked live flow remains an HIL item.)
- [x] An operator kill switch (`DockerComposeAdapter.emergency_stop`) halts an environment without an Edge decision, is fail-safe (records intent as evidence, surfaces a stop failure as `kill_switch_failed`), and a descriptive status/health surface (`health()` / `azazel-deception runtime-status`) reports adapter config and runtime state without authorizing anything. End-to-end operator control against a live/attacker-modified container is still an HIL item.

## Phase-2 gate

- [ ] All Phase-1 mandatory live gates above are satisfied before enabling
      dynamic narrative artifacts, credential lures, personas, or finite-state
      transitions tracked by `Azazel-Deception#6`.
