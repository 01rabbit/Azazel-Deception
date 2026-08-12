# Roadmap

## Phase 0 — bootstrap and contracts

- [x] Create `01rabbit/Azazel-Deception`.
- [x] Establish container-first, capability-aware responsibility boundary.
- [x] Add bootstrap capability detector, package validator, dry-run placement planner, reference package, CI, and safety docs.
- [ ] Ratify `Deception` Form, `Host` Role, AZ-06, and `THEATRE` in the umbrella naming specification.
- [ ] Land canonical Fabric deception-environment contracts and golden fixtures (`Azazel-Fabric#9`).
- [ ] Add signed provenance / per-platform OCI digest validation.
- [ ] Add threat-model and abuse-case tests.

## Phase 1 — static coherent environment

- [ ] Docker Compose runtime adapter with live execution still feature-disabled by default.
- [ ] One static Linux environment on both ARM64 and AMD64.
- [ ] Evidence export, termination, reset, and credential invalidation acknowledgement.
- [ ] Edge shadow/replay consumer and explicit activation gate (`Azazel-Edge#325`).

## Phase 2 — deterministic narrative runtime

- [ ] Narrative consistency compiler.
- [ ] Honey files and synthetic metadata.
- [ ] Decoy-only credential lures.
- [ ] Deterministic persona/activity replay.
- [ ] Edge-approved finite-state transitions.

## Phase 3 — effectiveness loop

- [ ] Knowledge ingest of environment outcomes.
- [ ] Narrative/tier/runtime-aware effectiveness analysis.
- [ ] Advisory-only posture suggestions; Edge independently accepts/modifies/rejects.

## Phase 4 — additional runtime classes

- [ ] Podman adapter.
- [ ] KVM/libvirt adapter after container isolation/reset are proven.
- [ ] Windows and OT/IoT profiles.
- [ ] Multi-node/cluster adapter only after single-node authority and failure semantics are stable.
