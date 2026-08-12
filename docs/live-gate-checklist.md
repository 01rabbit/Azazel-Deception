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
- [x] AZ-06 live adapter rejects `verified=false` images.
- [x] `verified=true` metadata alone cannot authorize live execution; an injected trusted `PackageVerifier` is mandatory.
- [x] Selected Package components must exactly match Compose services and image references.
- [x] Local Compose `build:` is forbidden for attacker-facing workloads.
- [ ] Reference package contains real verified multi-architecture OCI digests.
- [ ] Reference package has reviewed provenance and SBOM references.
- [ ] Production package signing/verifier implementation is implemented and tested.

## Isolation

- [x] Static Compose policy rejects privileged/host namespace/runtime socket/published port/external network configurations.
- [x] Static Compose policy requires read-only rootfs, dropped capabilities, no-new-privileges, and resource limits.
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
- [ ] Runtime daemon restart / host restart / resource exhaustion / route drift failure injection passes.
- [ ] Edge heartbeat and authenticated state reconciliation are implemented.

## Portability

- [x] Canonical contracts and shared fixtures support ARM64 and AMD64 with one package identity.
- [ ] A real signed reference package is built/verified/run on ARM64.
- [ ] The same signed package is built/verified/run on AMD64.
- [ ] Equivalent narrative, safety, evidence, and reset semantics are demonstrated on both.

## Operational integration

- [x] Edge shadow/replay evaluator exists and cannot enforce.
- [ ] Authenticated Edge-to-AZ-06 transport exists.
- [ ] End-to-end Edge decision -> AZ-06 activation -> evidence -> termination -> reset is demonstrated in a lab.
- [ ] Operator kill switch and status/health surface are validated.

## Phase-2 gate

- [ ] All Phase-1 mandatory live gates above are satisfied before enabling
      dynamic narrative artifacts, credential lures, personas, or finite-state
      transitions tracked by `Azazel-Deception#6`.
