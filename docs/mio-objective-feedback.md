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
signed activation decision. Nothing here extends it, and nothing here ends the
environment when it closes (only an Edge termination decision does).

Outside the lease an interaction is still recorded, marked
`metadata.outside_lease = true` and counted in the limitations; it is a fact
that happened, not an authorization. A bundle built after the lease end carries
the `lease_expired` limitation. If the environment is still active then, the
effect observation is `failed` with reason `lease_expired_runtime_still_active`
-- AZ-06 never claims a live effect past the lease. A bundle that claims a live
effect is refused (`lease_expired`) when verified past the lease.

## Session and generation

`session_ref` is `session:` plus the evidence hash of the `activated` record,
and `generation` is that record's evidence sequence number. Observation ids are
`<env>-s<generation>-obs-<evidence seq>`, so two observers, a re-created
observer, or a re-activation never collide. After terminate and reset the old
chain is refused for recording (`session_reset`); a read-only bundle of the
ended session (`environment_state == "reset"`) can still be built.

## Tenant and trace

Fabric has no tenant field in the pinned effect and outcome types. `node_id`
(recorded runtime state, checked against the decision's `target_node_id`) and
`trace_id` (from the Edge effect) stand in for it. Every bundle says so with
`tenant_substituted_by_node_id_and_trace_id`. This is a substitution, not an
isolation guarantee between tenants.

`trace_id` is **not authenticated**: the decision HMAC covers the decision, not
the effect. One decision binds one effect only (recorded as an
exclusively created file under `<state root>/mio_bindings/`; the runtime state
is never written by this module); a second effect with another
trace is refused (`effect_rejected`).

## Objective content

`objective_digest` is the canonical sha256 of the objective. If the signed
decision lists `advisory:mio-objective-digest-<hex32>` next to the objective
ref, the digest must match (otherwise the objective is retained as advice) and
the chain records `objective_content_bound = true`. Without that ref only the
reference names are bound and every bundle carries the limitation
`objective_content_not_bound`.

## Bundle

`build_feedback_bundle` returns a plain dict with schema
`az06-mio-feedback-bundle/v0-local`. It is a local container, not a contract
and not a new wire schema. Objects inside it (`EffectObservation`,
`PresentedTerrainRef`, `OutcomeObservationEnvelope`, `InteractionObservation`)
are Fabric types, validated before being dumped. Keys: `reference_chain`,
`decision`, `execution_request` (with the activated evidence seq and hash),
`caller_declared`, `runtime_materialization`, `observed_mechanism`,
`interactions` (at most 256, 8 KiB each, 2.5 MB in all), `objective_coverage`,
`outcome`, `tactical_assessment`, `freshness`, `isolation`, `limitations`,
`evidence`.

`objective_coverage` gives, for each hypothesis and each desired
`(observation_class, surface)`, one of `observed` (with observation ids, at
most 8), `not_observed_with_coverage`, or
`undeterminable_telemetry_gap:<name>`, plus counts per class/surface and per
confounder. The surface-to-telemetry mapping is declared by the caller
(`coverage_basis = caller_declared`); AZ-06 cannot verify what a sensor covers.
It says what was and was not observable. It never says which hypothesis is
right: that stays MIO's.

### Interaction input limits

Metadata keys come from an allow-list; values are bool, number, or a token of
at most 64 characters from `[A-Za-z0-9._:-]`. `lure_id` must name a lure of the
package. `observed_at` must lie between the activation (minus a 5 s skew) and
now plus 5 s. `untrusted_text` is never stored: only its length and a keyed
HMAC-SHA256 (a per-session random key kept beside, not in, the evidence chain)
remain; on a `credential_lure` surface only the length remains.

### Coverage entries

Each entry carries `observed_count`, `confounded_count`, `outside_lease_count`
and a status: `observed`, `observed_confounded_only`,
`observed_outside_lease_only`, `not_observed_with_coverage`,
`undeterminable_telemetry_gap:<name>` or `undeterminable_unmapped_surface:<surface>`.
Desired observations are not hypothesis-specific, which the section states as
`desired_observations_not_hypothesis_specific`. `freshness.anchor_kind` is
`last_interaction` or `activation`.

### Verification

`verify_feedback_bundle` believes nothing the bundle says about itself. It
requires the evidence head the bundle names, rebuilds the whole bundle from the
evidence chain cut at that head plus the inputs the caller declared, and
compares every key. The bundle's head must be the chain's current head:
evidence appended later (a drift, a new contact) makes it `stale`.
`allow_historical=True` (audit only; the consumers cannot ask for it) accepts
an earlier head, never for a bundle claiming a live effect. Any rewrite of isolation, limitations, freshness,
interactions, coverage or environment state is `evidence_tampered`. The Edge
mechanism evidence must be supplied again (`mechanism=`) for a bundle that
claims an observed mechanism. The knowledge and MIO projections
(`knowledge_ingest_payload`, `mio_deception_context`, `mio_frame_inputs`) call
verify themselves and need `expected_chain`, `state`, `now`, `max_age`.

`caller_declared` (telemetry names, isolation assertion refs, surfaces, the
surface-to-telemetry map) is the build caller's declaration. It is covered by
`caller_declared_mac`, an HMAC under the per-session key, so a change after
build is detected (`evidence_tampered`); the truth of the declaration is not
guaranteed. The Edge mechanism evidence is likewise assumed to be received
from Edge over a trusted path and presented again by the caller. The session
key is not discarded on reset, because earlier digests must stay checkable;
key files must be regular, owner-only (0600) files of exactly 32 bytes in a
0700 directory, otherwise `evidence_tampered`.

`mio_frame_inputs` returns what MIO 7a35288's `MioSituationFrameBuilder.build`
accepts (`deception_context`, `explicit_unknowns`) and what
`MioSituationFrame.build` accepts (`unknowns`, `freshness_seconds`,
`evidence_refs`) plus `known_facts` (`DECEPTION_DESIRED_OBSERVED_<CLASS>_<SURFACE>`,
`DECEPTION_DESIRED_NOT_OBSERVED_WITH_COVERAGE_<CLASS>_<SURFACE>`) and unknowns such as
`DECEPTION_UNMAPPED_SURFACE_<SURFACE>`: `DECEPTION_TELEMETRY_GAP_<NAME>`, `DECEPTION_EVIDENCE_STALE`,
`DECEPTION_ISOLATION_NOT_ASSERTED`, `DECEPTION_ISOLATION_DRIFT_OBSERVED`,
`DECEPTION_NO_INTERACTION_NOT_SAFETY`, `DECEPTION_LEASE_EXPIRED`,
`DECEPTION_OBJECTIVE_CONTENT_NOT_BOUND`. Anything AZ-06 cannot vouch for maps
the lifecycle to `unknown`, never `active`.

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

## Operating notes

- **Private directories.** `mio_feedback_keys/` and `mio_bindings/` under the
  state root must be plain directories owned by the service user with mode
  0700; key and binding files must be 0600. A refusal names which of owner or
  mode is wrong (`evidence_tampered`). To migrate an existing state root:
  `chown` the directories and files to the service user and `chmod 700` the
  directories (`chmod 600` the files).
- **Keys are created only when recording or building.** Verification only reads
  an existing key; a missing key is refused as `evidence_tampered` ("session
  key missing") and nothing is created.
- **Filesystem.** Private files are created with a temporary file and
  `os.link`, so the state root must be on a filesystem with hard links. Any
  `OSError` there is reported as `evidence_tampered` with the reason.
- **Locks are per process.** The numbering lock and the evidence lock work only
  inside one process, the same limit as `state.py`. Across processes an
  observation id can repeat; the bundle is then refused, so the failure is
  safe (it can deny service, it cannot forge a bundle).
- **Build and consume together.** Because the bundle's head must be the chain's
  current head, build the bundle and hand it to its consumer straight away;
  anything appended in between makes it `stale`.
