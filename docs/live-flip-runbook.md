# AZ-06 Live-Flip Runbook (canonical-cutover Step 4)

The live flip enables real materialization of decoy environments —
`AZAZEL_DECEPTION_LIVE` plus the strict posture actually driving
`docker compose up`, instead of the default `shadow_simulated`. It is **Step 4**
of `canonical-cutover-dryrun-plan.md`, and it is the one step this repository's
cloud/CI work **cannot** complete on its own: it needs hardware-in-the-loop
(HIL) certification and explicit human authorization.

This runbook is **non-executing documentation**. Nothing here flips the gate;
it records the procedure and the machine-checkable precondition so the flip,
when authorized, is auditable and reversible.

## Prerequisites (Steps 0–3, done)

- Fabric `v0.8.0` released; AZ-06/Edge pin it.
- Canonical-only transition consumer; the interim decision shape is retired.
- `TransitionExecutor` strict-for-live is **code-enforced** (its constructor
  refuses `live_enabled=True` without the full strict posture), and
  `build_reference_transition_executor()` is the strict-by-default reference
  constructor.
- `DockerComposeAdapter` reference wiring is strict-by-default
  (`build_reference_adapter`), with the explicit dev-only relaxed opt-out.

## Mandatory gate: machine-readable certification

Every mandatory item still open in `live-gate-checklist.md` is encoded in
`azazel_deception.runtime.live_gate.LIVE_GATES`. Before a flip, assemble a
certification bundle (one `LiveGateCertification` per gate, each with a real
`evidence_ref`) and confirm readiness:

```python
from azazel_deception.runtime.live_gate import evaluate_live_gate_readiness
readiness = evaluate_live_gate_readiness(certification_bundle)
assert readiness.ready, readiness.blocking_summary()
```

`evaluate_live_gate_readiness` is **fail-closed**: it returns `ready=True` only
when every required gate is `certified=True` with a non-empty `evidence_ref`. It
**authorizes nothing** — a `ready` result is a *necessary* precondition, never
sufficient.

The required gates (categories in parentheses):

| Gate id | Category |
|---|---|
| `hil_no_route_decoy_to_production` | HIL |
| `hil_egress_denied_under_failure` | HIL |
| `hil_attacker_cannot_reach_mgmt_or_socket` | HIL |
| `hil_host_restart_and_route_drift_injection` | HIL |
| `hil_kill_switch_against_live_attacker_modified_container` | HIL |
| `hil_combined_networked_e2e_lifecycle` | HIL |
| `portability_package_fully_signed_verified_true_justified` | portability |
| `portability_equivalent_e2e_on_arm64_and_amd64` | portability |
| `deployment_continuous_transport_key_distribution_rotation` | deployment |
| `software_transition_executor_strict_for_live_code_enforced` | software (done) |

## Flip procedure (only when authorized)

1. **Certify.** Complete each HIL/portability/deployment gate in a physical lab
   and record its evidence; produce the certification bundle.
2. **Verify readiness.** `evaluate_live_gate_readiness(bundle).ready is True`.
   If not, stop — the `blocking_summary()` names what is missing.
3. **Obtain explicit human authorization** for the target release/profile. The
   readiness check does not replace this.
4. **Wire the gate (gated code change, separate PR).** Make the live path
   consult the readiness check as an additional fail-closed precondition before
   any materialization, and construct executors via
   `build_reference_transition_executor(...)` / `build_reference_adapter(...)`
   with `live_enabled=True`. This step is itself reviewed (review → adversarial
   review) and is out of scope for the pre-work that shipped this runbook.
5. **Enable.** Set `AZAZEL_DECEPTION_LIVE=1` for the certified profile only.

## Reversal

Disable the env/config gate (`AZAZEL_DECEPTION_LIVE` unset) — the adapter and
executor fall back to `shadow_simulated` with no container action. No decision
is consumed by a refused flip.

## Out of scope

`installer/`, `systemd/`, and `security/` enforcement remain separate gated
surfaces, not covered here.
