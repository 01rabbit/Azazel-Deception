# AZ-06 Live Activation Gate Checklist

Live attacker-facing activation remains prohibited until every mandatory item
below is satisfied for the target release/profile.

## How to read this file

Every gate is in **exactly one** of three states, and a gate never carries a
residual claim of another state in its prose:

| State | Meaning |
|---|---|
| `- [x]` **checked** | Proven, and the line names the evidence that proves it. |
| `- [ ]` **open** | Not proven. The line says plainly what is missing. |
| `- [n/a]` **profile-not-applicable** | Does not apply to the profile, with the reason. |

**Evidence rule.** A gate may be `[x]` only when the line links evidence that
has actually been *executed and recorded*: a test in the default `pytest tests`
suite, or a named green GitHub Actions run. A test that exists but that no job
runs — an opt-in suite behind an environment variable, a cross-repository test
that `importorskip`s away, or a manual `make` target whose report is written to
the git-ignored `artifacts/` directory — is **not** proof and its gate stays
`[ ]`. The line still names that test, because it is what will close the gate
once a job executes it.

**A `[x]` here is a software/CI claim only.** No box on this page is a physical
or hardware-in-the-loop (HIL) claim; HIL gates are marked as such and no green
CI run can satisfy one.

No gate is currently `[n/a]`: this repository ships one profile (the reference
Linux container deployment) and every gate below applies to it. The state exists
for the bounded Nexus/Boot Lite profiles of `Azazel-Deception#35`, which are not
yet defined.

**Machine-readable counterpart.** The mandatory gates that block the live flip
are encoded in `azazel_deception.runtime.live_gate.LIVE_GATES` and listed in
[`live-flip-runbook.md`](live-flip-runbook.md). `evaluate_live_gate_readiness`
already enforces the evidence rule in code: a certification counts only when it
is `certified=True` **and** carries a non-empty `evidence_ref`
(`tests/test_live_gate.py::test_certified_true_but_no_evidence_is_uncertified_fail_closed`).

The two are kept in step **mechanically**. `tests/test_live_gate_checklist_sync.py`
fails when an open `[ ]` item below names no `LIVE_GATES` id — which would let
the machine-readable check report `ready=True` while this page still shows the
gate open — and fails when a gate id exists in code with no line on this page.
Every gate line names its id in the form ``LIVE_GATES`` id `<id>`; that phrase
is the parsed anchor, so removing it breaks the build rather than the
correspondence. The sole exemption is the Phase-2 meta-gate, which closes only
when the rest of this file does and is named in the test.

## Contract and authority

- [x] Canonical Fabric package/capability/placement/Edge decision models exist on development main.
      *Evidence: `tests/test_fabric_golden.py`, `tests/test_package.py`, `tests/test_planner.py`, `tests/test_golden_decision_interop.py`; `package.py`, `planner.py`, `capabilities.py`, `runtime/compose.py`, `runtime/preflight.py`, `runtime/transitions.py`, `runtime/verifier.py` all consume `azazel_fabric.deception_contracts` / `deception_integrity`.*
- [x] Capability and placement data are descriptive-only.
      *Evidence: `tests/test_planner.py::test_lite_plan_is_deterministic_and_descriptive_only` and `::test_edge_decision_reference_is_descriptive_binding_only`; the `native-contract` jobs of `.github/workflows/portability.yml` assert `capabilities["authority"] == "descriptive_only"` on Linux amd64/arm64 and macOS arm64.*
- [x] Activation and termination require Edge-owned expiring decisions.
      *Evidence: `tests/test_runtime.py::test_not_yet_effective_activation_is_rejected`, `::test_expired_termination_decision_is_rejected`, `::test_live_activation_is_disabled_by_default`.*
- [x] Edge decision IDs are one-shot at AZ-06.
      *Evidence: `tests/test_runtime.py::test_activation_decision_is_one_shot`, `::test_termination_decision_is_one_shot`, `::test_activation_failure_consumes_decision_and_records_failure`; durability in `tests/test_state_durability.py`.*
- [x] Package maximum resource budgets exist and Edge allocations cannot exceed them.
      *Evidence: `tests/test_runtime.py::test_edge_budget_cannot_exceed_package_maximum`, `::test_edge_budget_must_cover_selected_tier_minimum`.*
- [x] Live Edge allocations require an explicit finite bandwidth budget.
      *Evidence: `tests/test_runtime.py::test_live_allocation_requires_explicit_bandwidth_budget`.*
- [x] A stable compatible Azazel-Fabric release exists and consumers pin the exact tag. The pinned tag is stated only in `pyproject.toml` and described in [`docs/fabric-pin.md`](fabric-pin.md) — this checklist does not restate it, so the gate cannot go stale behind a pin bump. `docs/fabric-pin.md` records that the tag exists, that its GitHub Release is published (not draft, not prerelease), that Fabric cuts it through the tag-driven `release.yml` workflow (tag/version match check + tests), and that the AZ-06 suite is green against it on Linux amd64, Linux arm64 and macOS arm64 CI.
      *Evidence: the `azazel-fabric` requirement in `pyproject.toml`; [`docs/fabric-pin.md`](fabric-pin.md); `tests/test_golden_decision_interop.py` and `tests/test_canonical_bytes_anchor.py` consume the released golden decision vectors rather than skipping.*

## Supply chain

- [x] Contract fields exist for image manifest/per-platform digest/provenance/SBOM/verification.
      *Evidence: `tests/test_package.py`, `tests/test_supply_chain_policy.py::test_reference_verified_component_has_real_refs`; `examples/packages/municipal-linux-v1/package.yaml` carries `manifest_digest`, per-platform digests, `provenance_ref`, `sbom_ref`.*
- [x] AZ-06 live adapter rejects `verified=false` selected images.
      *Evidence: `tests/test_runtime.py::test_unverified_oci_blocks_live_before_docker`.*
- [x] `verified=true` metadata alone cannot authorize live execution; an injected trusted `PackageVerifier` is mandatory.
      *Evidence: `tests/test_runtime.py::test_verified_flag_alone_is_not_trusted_package_verification`.*
- [x] Selected Package components must exactly match Compose services and image references.
      *Evidence: `tests/test_runtime.py::test_compose_image_must_match_package_manifest`; `tests/test_runtime_policy.py::test_reference_compose_image_exactly_matches_package_manifest`.*
- [x] Local Compose `build:` is forbidden for attacker-facing workloads.
      *Evidence: `tests/test_runtime_policy.py::test_local_build_is_rejected_even_when_image_is_present`.*
- [x] Reference web image has real immutable multi-architecture OCI and per-platform digests.
      *Evidence: `tests/test_runtime_policy.py::test_reference_compose_image_is_immutable_digest_pinned`; the digests are recorded in [`implementation-status.md`](implementation-status.md) and pinned in `examples/packages/municipal-linux-v1/package.yaml` and `runtime/compose/reference-linux.compose.yaml`; built by `.github/workflows/reference-image.yml`.*
- [x] Reference web image has GitHub/Sigstore build-provenance attestation.
      *Evidence: `provenance_ref: github-attestation:40368115` in the reference package, produced by the `Generate GitHub provenance attestation` step of `.github/workflows/reference-image.yml`.*
- [x] `package_digest` is a normalize-first, representation-invariant canonical content digest; declared digest is sealed by tooling and re-derived in tests, not hand-copied.
      *Evidence: `tests/test_package_integrity.py` — `::test_digest_is_identical_across_representations`, `::test_int_float_ambiguity_does_not_change_digest`, `::test_reference_digest_equals_freshly_sealed_digest`, `::test_seal_does_not_mutate_input`.*
- [x] Package attestation signs the reconstructed canonical payload bytes (not YAML); `GitHubAttestationPackageVerifier` pins repo + signer-workflow identity, denies self-hosted runners, and fails closed on missing `gh`, CLI failure, subprocess error/timeout, bad `signature_ref` scheme, or content-digest mismatch.
      *Evidence: `tests/test_package_verifier.py` (11 tests covering each fail-closed path, including `::test_github_attestation_verifier_package_id_cannot_escape_tempdir`).*
- [x] The `Reference Package Attestation` workflow has an executed green run on GitHub-hosted runners: it reconstructs the canonical payload, asserts its SHA-256 equals `package_digest`, generates a keyless Sigstore attestation, and re-verifies it with `gh attestation verify --deny-self-hosted-runners` against the pinned signer workflow.
      *Evidence: run [`31660034975`](https://github.com/01rabbit/Azazel-Deception/actions/runs/31660034975), `push` to `main` at `58d494fa`, conclusion `success`. `examples/packages/municipal-linux-v1/package.yaml` and `src/azazel_deception/package.py` are unchanged since that commit, so the attested canonical payload is still the current one.*
- [x] The package attestation verifier is proven end-to-end against a real GitHub attestation (the in-workflow `gh attestation verify` step, not a mock, passes).
      *Evidence: the `Verify the attestation fails closed with pinned signer identity` step of `.github/workflows/reference-package.yml`, green in run [`31660034975`](https://github.com/01rabbit/Azazel-Deception/actions/runs/31660034975).*
- [x] A verified selected component must carry a real (non-placeholder, non-`bootstrap:`) `provenance_ref` and `sbom_ref`; the live gate fails closed otherwise.
      *Evidence: `tests/test_supply_chain_policy.py::test_verified_component_with_placeholder_provenance_fails_closed`, `::test_verified_component_with_bootstrap_sbom_fails_closed`, `::test_activation_gate_rejects_placeholder_provenance_before_docker`, `::test_unselected_unverified_optional_component_does_not_block`.*
- [x] `OciAttachedSbomVerifier` retrieves and validates the OCI-attached SPDX SBOM for every verified image at its immutable `@sha256:` digest (fail-closed); it is available as an injected live gate.
      *Evidence: `tests/test_sbom_verifier.py::test_oci_sbom_verifier_validates_per_platform_spdx` plus its four fail-closed cases, and `::test_injected_sbom_gate_rejects_before_docker`. The `make virtual-lab --sbom-verify` run against the real reference image is a manual developer run, not recorded evidence — see the Virtual Phase-1 Lab gate under Lifecycle and recovery.*
- [x] The SBOM is additionally verified via a Sigstore-signed GitHub attestation: the `attest-existing-sbom` dispatch path of the SBOM workflow republishes the digest's attached SPDX documents as GitHub SPDX attestations (no rebuild, digest unchanged) and self-verifies with the exact `gh attestation verify --predicate-type https://spdx.dev/Document --deny-self-hosted-runners` invocation `GitHubSbomVerifier` uses.
      *Evidence: run [`31798338588`](https://github.com/01rabbit/Azazel-Deception/actions/runs/31798338588), `workflow_dispatch`, conclusion `success`, against the pinned `sha256:c187c4ce…` manifest. Caveat, as recorded in [`roadmap.md`](roadmap.md): that run executed on the feature branch that added the dispatch path, not on a `main` push.*
- [x] The SBOM gate can be made mandatory via the strict live posture (`require_sbom_verification=True` rejects live activation when no SBOM verifier is configured).
      *Evidence: `tests/test_strict_live_posture.py::test_strict_sbom_requires_configured_verifier`, `::test_health_reports_strict_posture`, `::test_defaults_are_not_strict`.*
- [x] The strict posture is the enforced default for the reference live deployment: `build_reference_adapter()` constructs the reference adapter with `require_sbom_verification=True` and `require_authenticated_decisions=True` by default, and every reference entry point (`runtime-status`, `runtime-reconcile`, `virtual_phase1_lab`) routes through it. The only relaxation is an explicit dev opt-out (`--dev-relaxed-posture` / `AZAZEL_DECEPTION_RELAXED_POSTURE=1`); the library `DockerComposeAdapter` keeps permissive explicit defaults for unit callers only.
      *Evidence: `tests/test_reference_posture_default.py` (19 tests) — `::test_reference_adapter_is_strict_by_default`, `::test_class_default_stays_permissive`, `::test_reference_adapter_strict_activation_fails_closed_without_gates`, `::test_cli_runtime_status_is_strict_by_default`, `::test_lab_main_fails_closed_by_default_without_gates`.*
- [x] Attestation signer identity is pinned to a git ref as well as the workflow path: the verifier passes `--source-ref` (default `refs/heads/main`, configurable) so an attestation built from any other branch/tag is rejected. The in-workflow self-verify pins `--source-ref ${{ github.ref }}`.
      *Evidence: `tests/test_package_verifier.py::test_github_attestation_verifier_pins_configurable_source_ref`, `::test_github_attestation_verifier_omits_source_ref_when_unset`, `::test_github_attestation_verifier_rejects_wrong_signer`; the `--source-ref` argument in `.github/workflows/reference-package.yml`, green in run [`31660034975`](https://github.com/01rabbit/Azazel-Deception/actions/runs/31660034975).*

## Isolation

- [x] Static Compose policy rejects privileged/host namespace/runtime socket/published port/external network configurations.
      *Evidence: `tests/test_runtime_policy.py::test_published_port_is_rejected`, `::test_runtime_socket_and_external_network_are_rejected`, `::test_host_namespaces_and_privileged_are_rejected`.*
- [x] Static Compose policy requires non-root execution, read-only rootfs, `cap_drop: ALL`, no capability re-addition, no-new-privileges, and resource limits.
      *Evidence: `tests/test_runtime_policy.py::test_root_user_and_capability_readdition_are_rejected`, `::test_reference_compose_is_fail_closed_safe`.*
- [x] Native Linux ARM64 and AMD64 CI smoke confirms the digest-pinned reference runtime starts with no host ports, an internal-only Compose network, read-only rootfs, dropped capabilities, no-new-privileges, and CPU/memory/PID limits.
      *Evidence: the `native-compose-smoke (linux-amd64)` and `native-compose-smoke (linux-arm64)` jobs of `.github/workflows/portability.yml` running `scripts/dev/reference-compose-smoke.sh`, green on `main` at `11aab3d` in run [`32939686192`](https://github.com/01rabbit/Azazel-Deception/actions/runs/32939686192).*
- [ ] **HIL** — no route from a decoy workload to the protected production network.
      *Missing: hardware/lab certification. No software test can close this. `LIVE_GATES` id `hil_no_route_decoy_to_production`.*
- [ ] **HIL** — decoy egress is denied under runtime/route failure cases.
      *Missing: hardware/lab certification. `LIVE_GATES` id `hil_egress_denied_under_failure`.*
- [ ] **HIL** — attacker traffic cannot reach Edge/AZ-06 management APIs or the runtime socket.
      *Missing: hardware/lab certification. `LIVE_GATES` id `hil_attacker_cannot_reach_mgmt_or_socket`.*

## Lifecycle and recovery

- [x] Live execution is default-off.
      *Evidence: `tests/test_runtime.py::test_live_activation_is_disabled_by_default`; `tests/test_virtual_lab.py::test_virtual_lab_does_not_change_live_default`; `compose.py` and `runtime/posture.py` read `AZAZEL_DECEPTION_LIVE` and default to `False`.*
- [x] Termination decision expiry is enforced.
      *Evidence: `tests/test_runtime.py::test_expired_termination_decision_is_rejected`.*
- [x] Activation/termination anti-replay ledger exists.
      *Evidence: `tests/test_runtime.py::test_activation_decision_is_one_shot`, `::test_termination_decision_is_one_shot`; crash durability in `tests/test_state_durability.py::test_consume_decision_fsyncs_marker_file_and_parent_dir`.*
- [x] Runtime failure after decision consumption records explicit failure state/evidence and does not restore decision authority.
      *Evidence: `tests/test_runtime.py::test_activation_failure_consumes_decision_and_records_failure`.*
- [x] Every request and lifecycle step is recorded into a hash-linked evidence chain that verifies intact and fails closed when any record is tampered with.
      *Evidence: `tests/test_evidence.py`, `tests/test_shadow_server.py::test_every_request_is_audited_with_intact_evidence_chain`. `LIVE_GATES` id `software_evidence_chain_complete`.*
- [x] Reset preserves evidence while removing local runtime state.
      *Evidence: `tests/test_runtime.py::test_reset_clears_runtime_state_but_preserves_evidence`.*
- [x] Heartbeat freshness (`heartbeat_is_fresh`) and descriptive state reconciliation (`reconcile_with_edge` / `runtime-reconcile`) building blocks exist: a stale/absent heartbeat is fail-closed, and local-vs-Edge active-set divergence is reported (descriptive-only; acting on it still needs an Edge decision or the kill switch).
      *Evidence: `tests/test_edge_reconciliation.py` (11 tests) — `::test_stale_heartbeat_rejected`, `::test_future_heartbeat_beyond_skew_rejected`, `::test_unparsable_heartbeat_fails_closed`, `::test_reconcile_flags_local_only_active`, `::test_reconcile_flags_edge_only_active`.*
- [x] The AZ-06 side of the authenticated heartbeat/reconciliation surface is implemented and fail-closed: the shadow/replay service exposes `heartbeat` and `reconcile` actions that are descriptive-only and apply every envelope gate (authenticity, Edge allowlist, node binding, freshness, one-shot request ledger), and every request is audited into the evidence chain.
      *Evidence: `tests/test_shadow_heartbeat.py` — `::test_heartbeat_reports_identity_health_and_sequence`, `::test_reconcile_reports_divergence_with_local_state`, `::test_new_actions_require_an_authentic_envelope`, `::test_new_actions_enforce_identity_binding`, `::test_stale_heartbeat_envelope_is_rejected`, `::test_replayed_heartbeat_envelope_is_rejected`, `::test_heartbeat_and_reconcile_are_audited`.*
- [ ] A real container completes the full activation/evidence/termination/reset software lifecycle end-to-end.
      *Missing: an executed, recorded run. The Virtual Phase-1 Lab (`make virtual-lab`, `scripts/dev/virtual_phase1_lab.py`) drives exactly this against a real container with the real `GitHubAttestationPackageVerifier`, but it is a manual developer command: no workflow invokes it, and its report is written to `artifacts/lab/virtual-phase1-lab.json`, which `.gitignore` excludes, so no run is archived. `tests/test_virtual_lab.py` is by its own docstring a CI-safe unit test of the driver with the compose invocation monkeypatched — it starts no container. `tests/test_docker_integration.py::test_gated_live_lifecycle_enforces_isolation_and_preserves_evidence` does start a real container, but is opt-in behind `AZAZEL_DECEPTION_DOCKER_TESTS=1`. The `docker-lifecycle` and `virtual-lab` jobs of `.github/workflows/executed-evidence.yml` now set that variable and archive the lab report, and each job refuses a green-but-skipped result (`scripts/ci/assert_executed.py`). **This box stays `[ ]` until a green run of that workflow can be named here** — the evidence rule requires an executed, recorded run, not a job that exists. `LIVE_GATES` id `software_real_container_lifecycle_executed`.*
- [ ] Real container termination/reset after **attacker modification** is demonstrated, with the evidence chain finalized and verified.
      *Missing: an executed, recorded run. `tests/test_docker_integration.py::test_attacker_modified_state_is_destroyed_by_termination` asserts exactly this — attacker state written into the running decoy, read-only rootfs refusing persistence, termination, and a fresh activation carrying no attacker-modified state — and the same module covers container-crash recovery (`::test_container_crash_is_recovered_by_kill_switch`) and an injected teardown fault failing closed (`::test_termination_failure_fails_closed_and_kill_switch_recovers`). All eight tests in that module are opt-in behind `AZAZEL_DECEPTION_DOCKER_TESTS=1`; the `docker-lifecycle` job of `.github/workflows/executed-evidence.yml` now sets it and asserts all eight executed. **This box stays `[ ]` until a green run of that job can be named here.** `LIVE_GATES` id `software_attacker_modified_reset_executed`.*
- [ ] Runtime daemon restart / host restart / resource exhaustion / route drift failure injection passes in an appropriate Linux lab.
      *Missing: host restart and route drift are HIL and have no software path. Runtime-daemon restart (`tests/test_docker_integration.py::test_daemon_restart_preserves_state_and_recovers`) and resource exhaustion (`::test_pid_exhaustion_is_contained_by_limits`, `::test_storage_and_memory_ceilings_contain_exhaustion`) are now executed by the `docker-lifecycle` job of `.github/workflows/executed-evidence.yml`; host restart and route drift remain HIL, so this gate cannot close on that job alone. `LIVE_GATES` id `hil_host_restart_and_route_drift_injection`.*

## Portability

- [x] Canonical contracts and shared fixtures support ARM64 and AMD64 with one package identity.
      *Evidence: the `native-contract` matrix of `.github/workflows/portability.yml` (Linux amd64, Linux arm64, macOS arm64) validating the same package, green in run [`32939686192`](https://github.com/01rabbit/Azazel-Deception/actions/runs/32939686192); `tests/test_planner.py::test_amd64_is_supported`; `tests/test_fabric_golden.py`.*
- [x] Reference OCI source is built on native Linux ARM64 and native Linux AMD64 GitHub runners and combined into one immutable multi-architecture manifest.
      *Evidence: the `build-native` matrix and `publish-manifest` job of `.github/workflows/reference-image.yml`; the resulting digests are pinned in the reference package and Compose asset and recorded in [`implementation-status.md`](implementation-status.md).*
- [x] The same digest-pinned multi-architecture reference runtime is exercised on native Linux ARM64 and AMD64 CI runners.
      *Evidence: `native-compose-smoke (linux-amd64)` and `native-compose-smoke (linux-arm64)` in run [`32939686192`](https://github.com/01rabbit/Azazel-Deception/actions/runs/32939686192).*
- [x] Machine-readable portability evidence is archived for both Linux architectures.
      *Evidence: the `az06-portability-<label>` upload step of `.github/workflows/portability.yml` (`if-no-files-found: error`), produced by `scripts/dev/collect-portability-evidence.py` / `scripts/dev/reference-compose-smoke.sh`.*
- [ ] The package itself is fully signed/verified and `ImageManifest.verified=true` is justified by provenance + SBOM policy.
      *Missing: reviewed SBOM **content** policy (license/component allow-lists) in the trusted verifier. SBOM *attestation* verification is implemented and tested (`tests/test_sbom_verifier.py`); content policy is not. Tracked by `Azazel-Deception#3`. `LIVE_GATES` id `portability_package_fully_signed_verified_true_justified`.*
- [ ] Equivalent end-to-end activation/evidence/termination/reset semantics are demonstrated on both architectures.
      *Missing: the ARM64 half. The `docker-lifecycle` job of `.github/workflows/executed-evidence.yml` runs the real-container lifecycle on `ubuntu-latest` (AMD64) only; no ARM64 runner executes it, so the two architectures still have nothing to compare. `LIVE_GATES` id `portability_equivalent_e2e_on_arm64_and_amd64`.*

A physical AMD64 workstation is **not** a current software-development blocker.
Physical topology/hardware validation remains part of HIL/field certification,
not the native software portability gate.

## Operational integration

- [x] Edge shadow/replay evaluator exists and cannot enforce.
      *Evidence: `tests/test_shadow_server.py` — `::test_capabilities_and_package_and_plan_flow`, `::test_shadow_activation_and_termination_rehearsal` (zero container start, `enforcement_applied=False`), `::test_every_request_is_audited_with_intact_evidence_chain`.*
- [x] AZ-06 verifies Edge-decision authenticity before acting: `HmacDecisionAuthenticator` checks an HMAC-SHA256 signature over the canonical decision bytes, fail-closed, wired as an injected gate on both activation and termination (the key is operator-supplied, never stored in the repo). Together with the one-shot decision ledger and decision expiry this gives authenticity + anti-replay + freshness.
      *Evidence: `tests/test_decision_transport.py` — `::test_tamper_after_signing_fails`, `::test_wrong_key_fails`, `::test_unsigned_activation_rejected_when_authenticator_configured`, `::test_tampered_signed_decision_rejected`, `::test_require_authenticated_decision_wraps_authenticator_exception`; canonical-byte agreement with the Fabric release in `tests/test_canonical_bytes_anchor.py` and `tests/test_golden_decision_interop.py`.*
- [x] The decision authenticator can be made mandatory via the strict live posture (`require_authenticated_decisions=True` rejects live activation/termination when no authenticator is configured).
      *Evidence: `tests/test_strict_live_posture.py::test_strict_auth_requires_configured_authenticator`; `tests/test_reference_posture_default.py::test_reference_adapter_strict_termination_fails_closed_without_gates`.*
- [x] An operator kill switch (`DockerComposeAdapter.emergency_stop`) halts an environment without an Edge decision, is fail-safe (records intent as evidence, surfaces a stop failure as `kill_switch_failed`), and a descriptive status/health surface (`health()` / `azazel-deception runtime-status`) reports adapter config and runtime state without authorizing anything.
      *Evidence: `tests/test_operator_controls.py` — `::test_kill_switch_terminates_active_environment_without_edge_decision`, `::test_kill_switch_requires_operator_and_reason`, `::test_kill_switch_surfaces_stop_failure`, `::test_kill_switch_retry_after_failure_reattempts_stop`, `::test_health_surface_is_descriptive_only`.*
- [x] `TransitionExecutor` strict-for-live is enforced in code, not by calling convention: a live-posture executor built any other way cannot be constructed.
      *Evidence: `tests/test_transition_executor.py` — `::test_live_executor_must_be_strict`, `::test_build_reference_transition_executor_is_strict_for_live`. `LIVE_GATES` id `software_transition_executor_strict_for_live_code_enforced`.*
- [ ] **HIL** — end-to-end operator kill-switch control is proven against a live, attacker-modified container.
      *Missing: hardware/lab certification. This was previously recorded only as prose on the checked kill-switch line above; it is a mandatory gate in its own right — `LIVE_GATES` id `hil_kill_switch_against_live_attacker_modified_container`, asserted present by `tests/test_live_gate.py::test_required_gate_set_is_non_empty_and_covers_hil_kill_switch`.*
- [ ] A full networked, mutually-authenticated Edge-to-AZ-06 heartbeat and automatic state-reconciliation loop is proven end-to-end.
      *Missing: an executed, recorded run. The code on both sides exists — the AZ-06 `heartbeat`/`reconcile` actions (checked above) and the Edge-side `HeartbeatLoop` in `Azazel-Edge/py/azazel_edge/deception_shadow_client.py`, which polls on an interval, tracks consecutive failures, reconciles against the Edge active set and fires an `on_divergence` hook. The named end-to-end proof, `Azazel-Edge/tests/test_deception_shadow_heartbeat_e2e.py`, opens with `pytest.importorskip("azazel_deception")` and Edge CI (`.github/workflows/ci.yml`) installs only `requirements/runtime.txt` and `requirements/fabric.txt` — never `azazel-deception` — so that test skips in every recorded Edge run. The `cross-repo-heartbeat-e2e` job of `.github/workflows/executed-evidence.yml` now runs it here instead, checking out Azazel-Edge alongside AZ-06 and putting `edge/py` on `PYTHONPATH`, and asserts it did not `importorskip` away. It runs in this repository, not Edge's, because installing `azazel-deception` into Edge CI would invert the dependency direction — an AZ-06 regression would redden Edge's baseline, and Edge must stay fully functional with no AZ-06 present. **This box stays `[ ]` until a green run of that job can be named here.** `LIVE_GATES` id `software_networked_heartbeat_e2e_executed`.*
- [ ] Continuous key distribution/rotation for the mutually-authenticated Edge↔AZ-06 transport.
      *Missing: a deployment concern with no implementation or test in this repository. `LIVE_GATES` id `deployment_continuous_transport_key_distribution_rotation`.*
- [ ] **HIL** — combined networked Edge decision → AZ-06 activation → evidence → termination → reset is demonstrated in a lab.
      *Missing: hardware/lab certification. Two halves exist separately: the networked Edge shadow session (capabilities, package, decision-bound plan, activation/termination rehearsal, audited with an intact evidence chain and zero container start — `tests/test_shadow_server.py`), and the local live decision → activation → evidence → termination → reset lifecycle on real containers (`tests/test_docker_integration.py`, opt-in and unexecuted). The combined flow has never been run. `LIVE_GATES` id `hil_combined_networked_e2e_lifecycle`.*

## Phase-2 gate

- [ ] All Phase-1 mandatory live gates above are satisfied before enabling
      dynamic narrative artifacts, credential lures, personas, or finite-state
      transitions tracked by `Azazel-Deception#6`.
      *Missing: every `[ ]` item above. This is a meta-gate; it closes only when the rest of this file does.*
