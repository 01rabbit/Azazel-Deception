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
- [ ] Stable compatible Azazel-Fabric `v0.5.x` release exists and consumers pin the tag.

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
- [ ] Reference web image has reviewed SBOM attachment/reference.
- [ ] Reference-package attestation workflow has an executed green run on GitHub-hosted runners (implemented; not yet run).
- [ ] Production package signing/verifier is proven end-to-end against a real GitHub attestation (unit-tested against a mocked `gh` today).
- [ ] Attestation signer identity is pinned to a git ref/tag as well as the workflow path (`gh attestation verify --signer-workflow` matches any ref of that workflow; consider `--source-ref`/`--cert-identity` before live).

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
- [ ] Real container termination/reset after attacker modification is demonstrated.
- [ ] Runtime daemon restart / host restart / resource exhaustion / route drift failure injection passes in an appropriate Linux lab.
- [ ] Edge heartbeat and authenticated state reconciliation are implemented.

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
- [ ] Authenticated Edge-to-AZ-06 transport exists.
- [ ] End-to-end Edge decision -> AZ-06 activation -> evidence -> termination -> reset is demonstrated in a lab.
- [ ] Operator kill switch and status/health surface are validated.

## Phase-2 gate

- [ ] All Phase-1 mandatory live gates above are satisfied before enabling
      dynamic narrative artifacts, credential lures, personas, or finite-state
      transitions tracked by `Azazel-Deception#6`.
