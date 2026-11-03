# MIO objective feedback (Deception#55)

`src/azazel_deception/runtime/mio_feedback.py` lets AZ-06 return bounded,
verdict-free facts about an environment that Azazel-Edge authorized while
considering an Azazel-MIO observation objective. It adds no decision path.

## Separation of meaning

| Thing | What it is | What it can do |
|---|---|---|
| MIO objective | advice (`advisory:` refs) | nothing: starts, selects, extends and ends nothing |
| Edge decision | the only authorization | HMAC-authenticated, one-shot, time-limited; consumed by the existing `DockerComposeAdapter.activate_environment` / `terminate_environment` |
| runtime materialization, observed mechanism, interaction, outcome | facts AZ-06 observed | each under its own bundle key; none is a decision |
| tactical assessment | not made here | always `{"status": "not_assessed", "owner": "outside_az06"}` |

The module never calls `activate_environment` or `terminate_environment`.
Withdrawal happens only when the caller hands an Edge termination decision to
the existing adapter. Isolation drift is recorded as an `EffectObservation`
with `status=failed`, `termination_reason=isolation_drift_observed`; that
record withdraws nothing.

Silence is not safety: a bundle with no interactions always carries
`no_interaction_observed_is_not_evidence_of_safety`. A redirection mechanism
carries `redirection_does_not_imply_diversion`. Evidence is virtual or local
and says so (`virtual_or_local_evidence_not_hil`).

## How an objective is bound to a decision

Fabric types are unchanged. MIO references use the existing `advisory:` ref
kind: `advisory:mio-objective-<id>`, `advisory:mio-hypothesis-<id>`,
`advisory:mio-frame-<id>`. If Edge considered the objective, it lists those refs
in the signed `EnvironmentActivationDecision.evidence_refs`. The HMAC covers
the canonical decision bytes, so the listing is bound by the signature.

1. `accept_mio_objective` validates the closed advisory shape. Any key naming
   an action, environment, package, decision, budget or lifetime is rejected
   (`ObjectiveRejected`).
2. `admit_objective` is a pure check (nothing consumed). It returns
   `AdmittedObjective`, or `AdvisoryRetained(exposure="refused")` with reason
   `no_decision`, `decision_unauthenticated`, `decision_expired`,
   `decision_not_accepted` or `objective_not_in_authenticated_decision`.
3. The caller activates through the existing adapter (that is where the
   decision is consumed).
4. `bind_reference_chain` re-authenticates, checks the decision was consumed,
   the lease, the runtime state (environment, decision, package, node) and the
   activated evidence record, and accepts the Edge effect only if its
   `decision_ref` is `decision:<decision_id>`. The result is a
   `ReferenceChain`.

`BindingRefused.code` is one of: `decision_unauthenticated`,
`decision_not_consumed`, `decision_mismatch`, `lease_expired`,
`lease_not_started`, `environment_mismatch`, `package_mismatch`,
`node_mismatch`, `session_mismatch`, `session_reset`,
`effect_decision_mismatch`, `effect_rejected`, `evidence_tampered`, `stale`,
`interaction_unbound`, `telemetry_missing`.

## Lease

A lease is the decision's own window: `effective_at` to `expires_at` of the
signed activation decision. It is not extended by anything in this module, and
nothing here ends the environment when it closes. An observation recorded
outside the lease, or a bundle that claims a live environment outside it, is
refused (`lease_expired` / `lease_not_started`).

## Session and generation

`session_ref` is `session:` plus the evidence hash of the `activated` record,
and `generation` is that record's evidence sequence number. After
terminate and reset, the old chain is refused with `session_reset`; a new
activation yields a different session (`session_mismatch` for the old chain).

## Tenant

Fabric has no tenant field in the pinned effect and outcome types. `node_id`
(recorded runtime state, checked against the decision's `target_node_id`) and
`trace_id` (from the Edge effect) stand in for it. Every bundle says so with
`tenant_substituted_by_node_id_and_trace_id`. This is a substitution, not an
isolation guarantee between tenants.

## Bundle

`build_feedback_bundle` returns a plain dict with schema
`az06-mio-feedback-bundle/v0-local`. It is a local container, not a contract
and not a new wire schema. Objects inside it (`EffectObservation`,
`PresentedTerrainRef`, `OutcomeObservationEnvelope`, `InteractionObservation`)
are Fabric types, validated before being dumped. Keys: `reference_chain`,
`decision`, `execution_request`, `runtime_materialization`,
`observed_mechanism`, `interactions` (at most 256, with a truncated flag),
`outcome`, `tactical_assessment`, `freshness`, `isolation`, `limitations`,
`evidence`.

Attacker-derived text passed as `untrusted_text` to the bound observer is never
stored; only `untrusted_text_sha256` and `untrusted_text_len` reach the
evidence, the bundle, Knowledge and MIO.

`verify_feedback_bundle` re-checks the chain, the evidence hash chain, that the
bundle's head hash is in the chain, that each interaction is bound and equals
the stored record, the lease for live claims, and freshness.
`knowledge_ingest_payload` produces the existing Knowledge envelope
(`{"environment_id", "items"}`); `mio_deception_context` produces a mapping
MIO's `MioDeceptionContext.coerce` accepts, mapping anything AZ-06 cannot vouch
for (drift, stale, failed) to `unknown` rather than `active`.

## Requests to other teams

The numbering is this document's own; reconcile it with the team ledger.

- G1 (Fabric #72): a typed home for MIO objective/hypothesis/frame refs and an
  objective field on the effect/outcome envelope, replacing the local
  `MioObservationObjective`.
- G2 (Fabric): a tenant identifier on effect and outcome types.
- G3 (Edge): agreement to carry objective refs in activation decision
  `evidence_refs` (the binding used here).
- G4 (Edge): a production issuer of activation and termination decisions
  (Edge main has none; tests use synthetic decisions signed with a test key).
- G5 (Edge): a termination-decision path that consumes the
  `isolation_drift_observed` fact. AZ-06 only records it.
- G6 (MIO): produce objectives in the closed shape above and consume the
  lifecycle vocabulary of `mio_deception_context`.
- G7 (Knowledge): accept the interaction envelope idempotently on resend and
  keep the bundle limitations visible to its consumers.
- G8 (hardware): physical isolation, egress denial and restart/route-drift
  proofs.

## Not closed here

This work does not close any hardware-only gate. Evidence from the in-process
lifecycle, a container on a development host, or a virtual lab is not HIL
proof of protected-network isolation, denied decoy egress, physical NIC/VLAN
separation or host-restart behavior; those gates stay open in
`docs/implementation-status.md`.
