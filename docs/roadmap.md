# Roadmap

Last reconciled against the tree, CI and GitHub issue states: 2026-09-19.

## How to read this file

A box is checked **only** when named evidence in this repository or its CI
backs every part of it: a file path, a workflow job, or a test module. Where a
box covered several things at different stages, it has been split so each part
can be honest. Unchecked boxes carry a note saying what is missing.

Status words follow `Azazel/docs/roadmaps/third-party-development-handoff.md`
§7 and are never collapsed: **target contract**, **implemented** (code and
focused tests exist), **verified** (the declared test/evidence gate has
passed), **supported**, **experimental**, **retired**. `implemented` is not
`verified`.

**A checked box here is a software/CI claim only.** No box on this page is a
physical or hardware-in-the-loop (HIL) claim. Isolation gates that need real
NICs, VLANs and a management plane live in
[`live-gate-checklist.md`](live-gate-checklist.md) and are unmet. A green CI
run never satisfies a gate that asks for hardware.

Authority is unchanged by anything below: Azazel-Deception materializes,
observes and resets an Edge-approved bounded environment. It does not select,
approve or widen authority. Azazel-Edge's deterministic arbiter is the only
decision and enforcement authority.

## Phase 0 — bootstrap and contracts

- [x] Create `01rabbit/Azazel-Deception`.
- [x] Establish container-first, capability-aware responsibility boundary.
- [x] Add bootstrap capability detector, package validator, dry-run placement planner, reference package, CI, and safety docs.
- [x] Ratify `Deception` Form, `Host` Role, AZ-06, and `THEATRE` in the umbrella naming specification.
      *Verified — `Azazel/docs/specs/naming.md` records the 2026-08-13 ratification of the `Deception` Form, `Host` Role, the `AZ-06` accession and codename `THEATRE`; `Azazel/docs/products/product-map.md` carries the same entry.*
- [x] Land canonical Fabric deception-environment contracts and golden fixtures (`Azazel-Fabric#9`).
      *Verified — `pyproject.toml` pins the Fabric release described in [`fabric-pin.md`](fabric-pin.md); `package.py`, `planner.py`, `capabilities.py`, `runtime/compose.py`, `runtime/preflight.py`, `runtime/transitions.py` and `runtime/verifier.py` all consume `azazel_fabric.deception_contracts` / `deception_integrity`; the shared golden factories are exercised by `tests/test_fabric_golden.py` and the released golden decision vectors by `tests/test_golden_decision_interop.py`. `Azazel-Deception#1` is closed. CI green on `main`.*
- [x] Add signed provenance / per-platform OCI digest validation.
      *Verified — `examples/packages/municipal-linux-v1/package.yaml` carries an immutable multi-architecture manifest digest plus per-platform `arm64`/`amd64` digests; `runtime/preflight.py::require_supply_chain_backed_images` fails closed on placeholder or `bootstrap:` `provenance_ref`/`sbom_ref`; `runtime/verifier.py` provides `GitHubAttestationPackageVerifier`, `OciAttachedSbomVerifier` and `GitHubSbomVerifier`; `.github/workflows/reference-package.yml` has an executed green attestation run on `main` (`31660034975`, head `58d494fa`), and the GitHub SPDX SBOM-attestation path has a green `workflow_dispatch` run (`31798338588`, run on the feature branch that added that dispatch path, against the pinned `sha256:c187c4ce…` manifest — not a `main` push run). Tests: `tests/test_package_verifier.py`, `tests/test_sbom_verifier.py`, `tests/test_supply_chain_policy.py`.*
      *Still open and tracked separately: reviewed SBOM **content** policy (license/component allow-lists) — see the Portability section of [`live-gate-checklist.md`](live-gate-checklist.md) and `Azazel-Deception#3`.*
- [x] Add threat-model and abuse-case tests.
      *Verified — [`safety-model.md`](safety-model.md) states the hostile-decoy adversary assumption, the invariants, the authority-failure model and the LLM boundary. Abuse cases are tested: `tests/test_runtime_policy.py` (privileged containers, host namespaces, runtime-socket mounts, published ports, capability re-addition after `cap_drop: ALL`, missing limits), `tests/test_supply_chain_policy.py` (image substitution, unmanifested workloads, local builds), `tests/test_package_integrity.py` (digest tamper), `tests/test_decision_transport.py` (forged/altered decisions), `tests/test_live_gate.py` (every activation gate), `tests/test_evidence_chain.py` (record edit, reorder, duplication, middle deletion).*
      *Scope note: this threat model is invariant-level. The adversary-capability cases that need hardware — route drift, host restart, physical NIC/VLAN separation — are **not** covered here and remain unmet in [`live-gate-checklist.md`](live-gate-checklist.md).*

## Phase 1 — static coherent environment

- [x] Docker Compose runtime adapter with live execution still feature-disabled by default.
      *Verified — `runtime/compose.py::DockerComposeAdapter` implements capability inspection, validation, planning, activation, status, termination, reset, evidence export and an operator kill switch. Live execution is default-off: `compose.py` reads `os.environ.get("AZAZEL_DECEPTION_LIVE", "0") == "1"`, and `runtime/posture.py` mirrors it for `TransitionExecutor`. Tests: `tests/test_runtime.py`, `tests/test_live_gate.py`, `tests/test_strict_live_posture.py`, `tests/test_reference_posture_default.py`. `Azazel-Deception#2` is closed.*
- [x] One static Linux environment starts, with its isolation posture inspected, on native ARM64 and AMD64.
      *Verified — `.github/workflows/portability.yml` jobs `native-compose-smoke (linux-amd64)` (`ubuntu-24.04`) and `native-compose-smoke (linux-arm64)` (`ubuntu-24.04-arm`) both succeeded on `main` at `11aab3d` (run `32939686192`). They run `scripts/dev/reference-compose-smoke.sh` against the digest-pinned `runtime/compose/reference-linux.compose.yaml` and assert the native image architecture, no published host ports, an internal-only network, read-only rootfs, `cap_drop: ALL`, `no-new-privileges`, and CPU/memory/PID limits; machine-readable evidence is archived per architecture. The `native-contract` jobs additionally validate the one package identity on Linux amd64, Linux arm64 and macOS arm64.*
- [ ] Equivalent end-to-end activation/evidence/termination/reset semantics demonstrated on **both** ARM64 and AMD64, with the package fully signed/verified.
      *Missing — the full lifecycle against a real container exists only in `tests/test_docker_integration.py`, which is opt-in behind `AZAZEL_DECEPTION_DOCKER_TESTS=1`; no CI job sets it, so neither architecture has a CI-recorded end-to-end lifecycle, and the two are not compared. Reviewed SBOM-content policy is also unverified, so `ImageManifest.verified=true` is not yet justified by provenance **and** SBOM policy. Both are the unchecked Portability items in [`live-gate-checklist.md`](live-gate-checklist.md); `Azazel-Deception#3` is open.*
- [x] Evidence export, termination, and deterministic reset.
      *Verified — `compose.py::terminate_environment` (expiring, one-shot, authenticated Edge decision), `::reset_environment` (refuses an active environment, preserves evidence, clears runtime state), `::export_evidence` / `::export_observations` / `::verify_evidence`. Evidence is a tamper-evident hash chain in `runtime/state.py`. Tests: `tests/test_evidence_chain.py`, `tests/test_state_durability.py`, `tests/test_runtime.py`. `Azazel-Deception#4` is closed — but note that closing it did **not** close the HIL and failure-injection gates, which stay open in [`live-gate-checklist.md`](live-gate-checklist.md).*
- [ ] Credential invalidation wired into the environment lifecycle.
      *Partly implemented, not wired. `credentials/lures.py::LureRegistry.invalidate` / `.invalidate_all` exist and fail closed after invalidation (`tests/test_credential_lures.py`), but nothing under `runtime/` calls the registry: `reset_environment` does not invalidate lures, and the reference package declares `credentials: []`. `Azazel-Deception#31` lists credential-invalidation implementation beyond evidence-reference semantics as explicitly not done. Cryptographic erase and a post-reset persistence scan (program plan §6.5 item 11) have not been started.*
- [x] Edge shadow/replay consumer and explicit activation gate (`Azazel-Edge#325`).
      *Verified — `runtime/shadow_server.py` is an authenticated, strictly non-executing boundary: HMAC-signed envelopes over the canonical decision bytes, Edge-caller allowlist, node-identity binding, `issued_at` freshness and a one-shot `request_id` ledger; every response is `descriptive_only` with `enforcement_applied=False`. `compose.py::shadow_activation` / `::shadow_termination` rehearse decisions with zero container start. The explicit activation gate is the twelve independent preconditions in `activate_environment` (`runtime/preflight.py`, `_assert_activation_binding`, `_consume_decision`). Tests: `tests/test_shadow_server.py`, `tests/test_shadow_heartbeat.py`, `tests/test_edge_reconciliation.py`, `tests/test_live_gate.py`. `Azazel-Deception#5` is closed.*
      *Still open: the combined **networked** Edge → AZ-06 activation → evidence → termination → reset flow, in [`live-gate-checklist.md`](live-gate-checklist.md).*

## Phase 2 — deterministic narrative runtime

**The Phase-2 gate has not passed, and nothing below is started.** Phase 2
(`Azazel-Deception#6`, open) begins only after Phase 1 proves authority,
provenance/SBOM and package verification, portability, isolation, evidence and
reset at the required assurance level — including the HIL gates in
[`live-gate-checklist.md`](live-gate-checklist.md). Do not begin Phase 2 merely
because the current CI is green.

Building blocks written ahead of the gate are **implemented**, never
**verified** for this phase, and none is wired into a live path:
`narrative/consistency.py`, `honey/artifacts.py`, `credentials/lures.py`,
`persona/runtime.py` and `runtime/transitions.py` are deterministic,
synthetic-only and non-executing, with focused tests. Their existence is not
phase entry and does not check any box below.

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
