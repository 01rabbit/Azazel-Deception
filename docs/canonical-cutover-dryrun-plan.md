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
- `TransitionExecutor` accepts **both** the interim dict shape and the canonical
  Fabric model. `require_canonical_decision=True` promotes canonical-only;
  `TransitionExecutor.strict(...)` turns on all four gates (authentication,
  one-shot anti-replay, decision expiry incl. `effective_at ≤ as_of < expires_at`,
  canonical-only). `live_enabled` defaults `False` → result `shadow_simulated`;
  even `live_enabled=True` performs **no container action** (materialization is a
  runtime adapter's job).
- `DockerComposeAdapter` reference wiring (`build_reference_adapter`) is
  **strict by default** (`require_sbom_verification=True` +
  `require_authenticated_decisions=True`); the only relaxation is the explicit
  dev opt-out (`--dev-relaxed-posture` / `AZAZEL_DECEPTION_RELAXED_POSTURE=1`).
  The library `DockerComposeAdapter` keeps permissive explicit defaults for unit
  callers only.

## Target state

1. Canonical Edge decisions are the **only** accepted form on the live path; the
   interim back-compat shape is removed.
2. Live materialization is enabled **only** under the strict posture and an
   explicit deployment configuration — never a code default — and only once every
   mandatory live gate is satisfied.

## Staged cutover (each step reversible; dry-run first; approval-gated)

| Step | Action | Reversal | Approval |
|---|---|---|---|
| 0. Soak/observe | Keep defaults. In shadow, record whether real Edge decisions arrive as interim vs canonical; confirm 100% canonical over the soak window. | n/a (no change) | none (observation only) |
| 1. Canonical-only at reference | Set `require_canonical_decision=True` in reference wiring so interim decisions are rejected. | Flag flip back to `False`. | **human** |
| 2. Retire interim path | After a zero-interim soak, remove the interim `_authorize` branch and its back-compat tests. | Revert commit. | **human** |
| 3. Live flip | Enable live materialization via explicit deployment config (`AZAZEL_DECEPTION_LIVE` + strict posture), gated on the checklist below. | Disable the env/config gate. | **human + live-gate checklist** |

## Dry-run methodology (before Steps 1 and 3)

Run the reference adapter in **shadow** against real, signed Edge decisions in a
staging environment: assert the `would_execute` result and its bindings match the
expected transition, confirm **zero** container action and `enforcement_applied:
False`, exercise the anti-replay ledger (one-shot) and the `effective_at`/expiry
window, and diff the evidence chain against the expected. No attacker-facing
container is started at any point during the dry run.

## Preconditions that BLOCK the live flip (Step 3)

From [`live-gate-checklist.md`](live-gate-checklist.md), the following mandatory
items are still open. Those marked **HIL** require hardware/lab or human
certification and cannot be closed from a cloud session:

- **HIL** — no route from decoy workload to the protected production network.
- **HIL** — decoy egress denied under runtime/route failure.
- **HIL** — attacker traffic cannot reach Edge/AZ-06 management APIs or the runtime socket.
- **HIL** — combined networked Edge→AZ-06 activation→evidence→termination→reset in a lab.
- **HIL** — host restart / route-drift failure injection in a Linux lab.
- Deployment — continuous key distribution/rotation for the mutually-authenticated transport.
- Portability — full package signing with `ImageManifest.verified=true` justified by provenance + SBOM policy; equivalent end-to-end lifecycle demonstrated on both ARM64 and AMD64.

The Phase-2 gate (dynamic narrative artifacts, credential lures, personas,
finite-state transitions per `Azazel-Deception#6`) stays closed until all
Phase-1 mandatory live gates above are satisfied.

## Verification / tests to add per step

- Step 1: a reference-wiring test asserting an interim-shape decision is rejected
  under `require_canonical_decision=True`, while a canonical signed decision is
  accepted (`shadow_simulated`).
- Step 2: removal is safe only when no test still depends on the interim path;
  the canonical + strict suites must remain green.
- Step 3: a staging dry-run harness (shadow) exercised against the live Edge
  signer, plus the HIL certifications above, recorded as machine-readable evidence.

## Approval gate

This document authorizes nothing. Steps 1–3 each require explicit human sign-off,
and Step 3 additionally requires the HIL/deployment/portability items above to be
certified. `installer/`, `systemd/`, and `security/` enforcement are separate
gated surfaces not covered here.
