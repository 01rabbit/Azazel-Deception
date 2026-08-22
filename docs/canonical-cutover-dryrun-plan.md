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
  `azazel-fabric @ v0.8.0`; the canonical signing contract + golden vectors are
  released, and the cross-repo interop / signature tests execute green (no
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
- **Transition-decision consumer** — `TransitionExecutor` is the component that
  carries the interim (`_authorize`) dict fallback alongside the canonical model,
  and the `require_canonical_decision` flag that rejects the interim shape.
  **It is not yet instantiated by any live/reference entry point** — a repo-wide
  search finds it only in `transitions.py` and tests, never in
  `build_reference_adapter`, the CLI, or `virtual_phase1_lab`. Its constructor
  currently couples `live_enabled=True` to `require_authenticated_decisions`
  **only** (`transitions.py:147`) — **not** to `require_canonical_decision`,
  `require_replay_protection`, or `require_decision_expiry`. `TransitionExecutor.
  strict(...)` turns on all four gates, but it is **opt-in convention, not a code
  invariant** for `live_enabled=True`: `TransitionExecutor(catalog,
  live_enabled=True, require_authenticated_decisions=True, decision_authenticator=…)`
  is a valid construction and would emit `would_execute` for an interim,
  non-expiring, replay-unprotected (but authenticated) decision. `live_enabled`
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

From [`live-gate-checklist.md`](live-gate-checklist.md), the following mandatory
items are still open. Those marked **HIL** require hardware/lab or human
certification and cannot be closed from a cloud session. **Note:** the checklist
records some open HIL residuals inside prose on otherwise-checked lines, so this
list is *not* just the unchecked `[ ]` boxes — read the prose too.

- **HIL** — no route from decoy workload to the protected production network.
- **HIL** — decoy egress denied under runtime/route failure.
- **HIL** — attacker traffic cannot reach Edge/AZ-06 management APIs or the runtime socket.
- **HIL** — combined networked Edge→AZ-06 activation→evidence→termination→reset in a lab.
- **HIL** — host restart / route-drift failure injection in a Linux lab.
- **HIL** — end-to-end operator control (kill switch) proven against a **live,
  attacker-modified** container. (Recorded in `live-gate-checklist.md`'s prose on
  the otherwise-checked kill-switch line, not as its own `[ ]` box — do not treat
  the software kill-switch as fully certified.)
- **Software** — `TransitionExecutor` strict-for-live must be **code-enforced**
  (Step 1 above), not left to `.strict()` convention, before the transition path
  is live-enabled.
- Deployment — continuous key distribution/rotation for the mutually-authenticated transport.
- Portability — full package signing with `ImageManifest.verified=true` justified by provenance + SBOM policy; equivalent end-to-end lifecycle demonstrated on both ARM64 and AMD64.

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
