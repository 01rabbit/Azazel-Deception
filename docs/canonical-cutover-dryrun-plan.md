# AZ-06 bootstrap→canonical cutover — dry-run plan

> **Status: PLAN ONLY. This document changes no code and no runtime behavior.**
> It is the dry-run/design artifact that the governance model requires *before*
> any live-enforcement cutover. Nothing here is authorized to execute. The
> default posture is unchanged: `live_enabled=False` → `shadow_simulated`, no
> container action. Each staged step below requires explicit human approval and
> a dry-run execution before it is applied, and the live flip additionally
> requires the mandatory items in [`live-gate-checklist.md`](live-gate-checklist.md)
> — several of which are hardware-in-the-loop (HIL) and cannot be closed in a
> cloud session.

## Purpose and scope

Retire the interim (pre-canonical) Edge-decision shape and make the canonical
Fabric `EnvironmentTransitionDecision` / `EnvironmentActivationDecision` the only
accepted decision form on the consumer path, then define how — and under what
preconditions — the live materialization gate is flipped from shadow to enforced.

Out of scope (explicitly **not** touched by this plan): `installer/`, `systemd/`,
and `security/` enforcement code. Those remain separate gated surfaces.

## Current state (grounded in merged code)

- **Producer** (Azazel-Edge `deception_transition`) and **consumer** (AZ-06
  `TransitionExecutor` / `DockerComposeAdapter`) are merged and pin
  the same exact `azazel-fabric` release tag (stated once in `pyproject.toml`,
  described in [`fabric-pin.md`](fabric-pin.md)); its canonical signing contract
  and golden vectors are released, and the cross-repo interop / signature tests execute green (no
  longer version-skipped).
There are **two distinct consumer paths**, and they are in different states —
this plan must not conflate them:

- **Activation / termination consumer** — `DockerComposeAdapter.activate_environment`
  / `.terminate_environment` validate the canonical `EnvironmentActivationDecision`
  / `EnvironmentTerminationDecision` **directly** (`src/azazel_deception/runtime/
  compose.py:338`). This path has **no interim shape and never did** — it is
  *already canonical-only*, so there is nothing to "flip" here. Its reference
  wiring (`build_reference_adapter`) is **strict by default**
  (`require_sbom_verification=True` + `require_authenticated_decisions=True`); the
  only relaxation is the explicit dev opt-out (`--dev-relaxed-posture` /
  `AZAZEL_DECEPTION_RELAXED_POSTURE=1`). The library `DockerComposeAdapter` keeps
  permissive explicit defaults for unit callers only.
- **Transition-decision consumer** — `TransitionExecutor`. **Steps 1–3 of the
  staged cutover below have since been delivered** (commits `480b51c`,
  `02c63ca`), so the description of this path as carrying an interim fallback is
  historical: the legacy interim dict shape is retired and unconditionally
  rejected (`tests/test_transition_executor.py::test_interim_dict_is_always_rejected`,
  `::test_signed_interim_dict_is_rejected_under_strict`), and strict-for-live is
  **code-enforced** — the constructor raises unless `live_enabled=True` is
  accompanied by `require_authenticated_decisions` **and**
  `require_replay_protection` **and** `require_decision_expiry` **and**
  `require_canonical_decision`. `build_reference_transition_executor()`
  (`runtime/posture.py`) is the strict-by-default reference constructor and
  forces `live_enabled=False` under a relaxed posture. `live_enabled` still
  defaults `False` → `shadow_simulated`; even `live_enabled=True` performs **no
  container action** (materialization is a runtime adapter's job).

## Target state

1. Canonical Edge decisions are the **only** accepted form on the live path; the
   interim back-compat shape is removed.
2. Live materialization is enabled **only** under the strict posture and an
   explicit deployment configuration — never a code default — and only once every
   mandatory live gate is satisfied.

## Staged cutover (each step reversible; dry-run first; approval-gated)

> The activation/termination path is already canonical-only (see Current state),
> so these steps concern the **transition-decision consumer** (`TransitionExecutor`).

Steps 1–3 are **done** (commits `480b51c`, `02c63ca`); Step 4 is the only one
still outstanding. The rows are kept as the record of what each step was and how
it was approved.

| Step | Action | Reversal | Approval |
|---|---|---|---|
| 0. Soak/observe | Keep defaults. In shadow, record whether real Edge transition decisions arrive as interim vs canonical; confirm 100% canonical over the soak window. | n/a (no change) | none (observation only) |
| 1. Code-enforce strict-for-live | Close the gap that `live_enabled=True` on `TransitionExecutor` structurally forces authentication **only**: extend the constructor guard so `live_enabled=True` also requires `require_canonical_decision` + `require_replay_protection` + `require_decision_expiry` (i.e. full `.strict()`), **or** add a `build_reference_transition_executor(...)` factory analogous to `build_reference_adapter`. Without this, "canonical-only for the transition path" is not code-enforceable — only convention. | Revert commit. | **human** |
| 2. Wire + canonical-only | Wire `TransitionExecutor` (via the strict factory from Step 1) into the live transition path with `require_canonical_decision=True`, so interim transition decisions are rejected. | Unwire / flag flip. | **human** |
| 3. Retire interim path | After a zero-interim soak, remove the interim `_authorize` branch and its back-compat tests. | Revert commit. | **human** |
| 4. Live flip | Enable live materialization via explicit deployment config (`AZAZEL_DECEPTION_LIVE` + strict posture), gated on the checklist below. | Disable the env/config gate. | **human + live-gate checklist** |

## Dry-run methodology (before Steps 2 and 4)

Run the reference adapter in **shadow** against real, signed Edge decisions in a
staging environment: assert the `would_execute` result and its bindings match the
expected transition, confirm **zero** container action and `enforcement_applied:
False`, exercise the anti-replay ledger (one-shot) and the `effective_at`/expiry
window, and diff the evidence chain against the expected. No attacker-facing
container is started at any point during the dry run.

## Preconditions that BLOCK the live flip (Step 4)

[`live-gate-checklist.md`](live-gate-checklist.md) is the authority for which
gates are open. Every gate there is now in exactly one state — checked, open, or
profile-not-applicable — with no open residual hidden in the prose of a checked
line, so the unchecked `[ ]` boxes are the whole list. Those marked **HIL**
require hardware/lab or human certification and cannot be closed from a cloud
session. Summarizing the open set at the time of writing:

- **HIL** — no route from decoy workload to the protected production network.
- **HIL** — decoy egress denied under runtime/route failure.
- **HIL** — attacker traffic cannot reach Edge/AZ-06 management APIs or the runtime socket.
- **HIL** — combined networked Edge→AZ-06 activation→evidence→termination→reset in a lab.
- **HIL** — host restart / route-drift failure injection in a Linux lab.
- **HIL** — end-to-end operator control (kill switch) proven against a **live,
  attacker-modified** container. Now its own `[ ]` box in the checklist; do not
  treat the software kill-switch as fully certified.
- **Unexecuted software proof** — the real-container lifecycle, the
  attacker-modified termination/reset, and the networked heartbeat/reconciliation
  E2E all have tests that no job runs (opt-in env gate, or a cross-repo
  `importorskip`). Until a job executes them they are open, and they have no
  `LIVE_GATES` id.
- Deployment — continuous key distribution/rotation for the mutually-authenticated transport.
- Portability — full package signing with `ImageManifest.verified=true` justified by provenance + SBOM policy; equivalent end-to-end lifecycle demonstrated on both ARM64 and AMD64.

The **software** precondition that `TransitionExecutor` strict-for-live be
code-enforced (Step 1) is **satisfied** — see Current state above. It remains in
`LIVE_GATES` as `software_transition_executor_strict_for_live_code_enforced` so a
flip must positively assert it.

The Phase-2 gate (dynamic narrative artifacts, credential lures, personas,
finite-state transitions per `Azazel-Deception#6`) stays closed until all
Phase-1 mandatory live gates above are satisfied.

## Verification / tests to add per step

- Step 1: a test asserting live construction of `TransitionExecutor` without full
  strict (canonical + replay + expiry) fails closed — analogous to the existing
  `live_enabled` → `require_authenticated_decisions` guard test.
- Step 2: a reference-wiring test asserting an interim transition decision is
  rejected under `require_canonical_decision=True`, while a canonical signed
  decision is accepted (`shadow_simulated`).
- Step 3: removal is safe only when no test still depends on the interim path;
  the canonical + strict suites must remain green.
- Step 4: a staging dry-run harness (shadow) exercised against the live Edge
  signer, plus the HIL certifications above, recorded as machine-readable evidence.

## Approval gate

This document authorizes nothing. Steps 1–4 each require explicit human sign-off,
and Step 4 additionally requires the HIL/deployment/portability items above to be
certified. `installer/`, `systemd/`, and `security/` enforcement are separate
gated surfaces not covered here.
