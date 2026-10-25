# SO-08 — Isolation drift: detection, withdrawal, and the field-exercise record

> **No green CI run satisfies the SO-08 HIL gate.** SO-08 is a
> **hardware-only** objective. The namespace-based virtual lab described here
> is a CI *regression signal* for the detection half. Its records carry
> `class: "virtual-lab-regression"` and `gate: false`, can never carry
> `verdict: "pass"`, and are refused as HIL evidence by
> `azazel_deception.runtime.so08_record.validate_record`.

Program plan §8 row, owned by AZ-06 (Azazel-Deception#41, assignment in
`01rabbit/Azazel:docs/roadmaps/service-objective-assignments.md`):

> Deception isolation drift — detect within 2 seconds and withdraw
> attacker-route exposure within 5 seconds, independent of runtime cleanup

The target values (2 s, 5 s, 20 samples per kind) are the row's. They are
stated once in code, in `azazel_deception.runtime.so08_record`
(`DETECTION_BOUND_MS`, `WITHDRAWAL_BOUND_MS`, `SAMPLES_PER_KIND`), and this
repository does not change them.

## Who owns which half

| Half | Owner | Kind of act |
|---|---|---|
| Detection | AZ-06 (`runtime/isolation_drift.py`) | Observation, appended to AZ-06's evidence chain |
| Withdrawal | Azazel-Edge's authority path, measured end-to-end | Enforcement |

AZ-06 **detects and records**. It does not withdraw, block, tear down, or ask
anything to. A recorded drift is a fact for Edge to act on. Edge has not yet
declared its authoritative enforcement path (**Azazel-Edge#412**), so the
withdrawal half **cannot be measured today**: every record carries gap
`SO08-NO-EDGE-WITHDRAWAL-PATH` naming Azazel-Edge#412, the withdrawal part is
`not_measurable`, and so is the overall verdict. Nothing in this repository
stands in for Edge and withdraws a route.

This is enforced in code, not left to the record: while
`so08_record.EDGE_WITHDRAWAL_PATH_DECLARED` is `False`, the validator refuses
any record — virtual-lab or HIL — whose withdrawal part lacks that gap, whose
gap does not carry `blocks_verdict: true`, or whose gap does not reference
Azazel-Edge#412. A blocking gap forces `not_measurable`, so **no SO-08 record
can pass until a future, reviewed code change flips that constant** once Edge
declares its path (`tests/test_isolation_drift.py::test_no_hil_record_can_pass_until_edge_declares_the_withdrawal_path`).

## Declared drift kinds

Declared once, in `azazel_deception.runtime.isolation_drift.DRIFT_KINDS`. Each
is the runtime counterpart of an isolation invariant the static Compose policy
(`runtime/policy.py`) already refuses at plan time:

| Drift kind | Injected as (virtual lab) | Static-policy twin |
|---|---|---|
| `route_to_protected` | a route to the protected network appears in the decoy's routing table | `network_not_internal` |
| `published_port` | a listening socket appears on the publish (host) side | `published_ports` |
| `capability_regranted` | a process with a non-empty effective capability set appears in the decoy (the analogue of `docker exec --privileged`) | `capability_readdition_forbidden` |

The invariant is absolute — any finding of a declared kind is drift — because
the policy tolerates zero of each. A sampler that does not report a kind is a
refusal, never "no drift".

## How drift appears in exported evidence

`DockerComposeAdapter.export_evidence` (and anything else reading the raw
chain) carries each drift as an `EnvironmentEvent` with
`event_type: "failure"` and `metadata.stage: "isolation_drift"`, plus
`drift_kind`, `policy_twin`, `finding`, `authority: "descriptive_only"` and
`environment_state`. **An external reducer must not treat such a record as a
lifecycle failure**: it does not mean activation, termination or reset failed,
it does not change the environment's state, and AZ-06 does not move the
environment to `failed` because of it. Filter on `metadata.stage` first.
`export_observations` never returns it (it is not attacker interaction).

The observer's own rules, as documented on `IsolationDriftObserver`:

- **One observer per environment.** Event ids continue the environment's
  isolation-drift sequence read from the chain at construction, so a restarted
  observer never reuses an id.
- **A restart re-records persistent drift once.** The active set is not
  persisted; a new observer cannot vouch that a drift it sees is the one an
  earlier process saw, and a duplicate fact is safe where a dropped one is
  not. Deduplicate by `(drift_kind, finding)` if needed.
- **Any environment state is accepted, including terminated or absent.** The
  row is "independent of runtime cleanup": a route that outlives the decoy is
  the case that matters. `metadata.environment_state` says which case it was.
- A drift's disappearance is not recorded; it would read as a withdrawal AZ-06
  has no authority to perform.

## Measurement definition

- **Clock**: the harness host's monotonic clock (`time.monotonic_ns()`). The
  harness both injects and reads the evidence back, so one clock domain.
- **Start**: taken immediately *before* the harness issues the injection, so
  latency can only be over-stated.
- **End (detection)**: the harness reads the drift's record back out of AZ-06's
  evidence chain (`RuntimeStateStore.append_evidence` → the environment's
  `.jsonl` chain). The record is Fabric's `EnvironmentEvent` with
  `event_type: "failure"` and `metadata.stage: "isolation_drift"`; Fabric has
  no dedicated isolation-drift record, and `InteractionObservation` is not used
  because a route appearing is not attacker interaction.
- **End (withdrawal)**: the first instant an **active reachability probe** from
  the decoy side (a TCP connect to a protected-side listener) no longer
  reaches. Reachability, not teardown: the decoy may still be running.
- **Samples**: 20 injections per declared kind.
- **Pass**: *every* sample detects ≤ 2 s *and* withdraws ≤ 5 s. An unfinished
  sample (never detected / never withdrawn) is a violation. An empty sample set
  never passes.

## Virtual lab (regression signal, `gate: false`)

`make so08-virtual-lab` runs `scripts/dev/so08_drift_lab.py`. It needs Linux
and root (it creates network and PID namespaces); in a container that means
`--privileged`. It builds decoy ↔ router ↔ protected plus a front
(publish-side) namespace, runs a decoy workload as uid 65534 with every
capability dropped in its own PID namespace, and for each kind × 20: injects,
lets the real `IsolationDriftObserver` (fed by a procfs sampler polling every
50 ms) record the drift, times the read-back, runs the probe once
(descriptive: it confirms the route injection actually exposed the protected
side), and then reverts its own injection. That revert is a test fixture: it
is not timed and is not withdrawal.

Exit status — a run that did not happen is never green:

| Exit | Meaning |
|---|---|
| `0` | Executed; every detection sample ≤ 2 s. The record's verdict is still `not_measurable` and `gate` is `false`. |
| `1` | Executed; the detection half regressed. |
| `2` | Not executed (not Linux, not root, missing tool, namespaces refused, baseline not isolated, evidence chain broken) **or** the record failed validation. A record with `executed: false`, `verdict: "not_measurable"` is still written. |

A virtual-lab record's `product_configuration.commissioned_identity` is the
literal marker `virtual-lab, no commissioned identity` — never a kernel
interface name.

## HIL field-exercise record

The release form of SO-08. One JSON record per field exercise, **committed to
this repository** under `docs/field-exercises/so08/<run_id>.json` (not a
workflow artifact). It uses the same schema as the virtual-lab record and is
held to the same validator,
`azazel_deception.runtime.so08_record.validate_record`, with these
differences:

| Field | Virtual lab | HIL field exercise |
|---|---|---|
| `schema` | `azazel-deception/so08-record/v1` | same |
| `objective_id` | `SO-08` | same |
| `class` | `virtual-lab-regression` | `hil-field-exercise` |
| `gate` | `false` | `true` |
| `owner` | `{repository: "01rabbit/Azazel-Deception", commit: <40-hex>, worktree_clean}` | same |
| `product_configuration.commissioned_identity` | `virtual-lab, no commissioned identity` | the **commissioned composite identifier** `az06-commission:<site>/<node>/<segment>` (each part lower-case alphanumerics and hyphens; `so08_record.COMMISSIONED_IDENTITY_PATTERN`). A positive shape, so no kernel interface name (`eth0`, `ETH0`, `wwan0`, `cni0` …) can satisfy it |
| `product_configuration.lab_backend` | `linux-netns` | one of `so08_record.HIL_BACKENDS` (`field-segment`) |
| `product_configuration.drift_kinds` | `DRIFT_KINDS` | same |
| `field_exercise` | absent | required: `performed_at_utc`, `operator`, `site_ref`, `protected_network_ref`, `edge: {repository: "01rabbit/Azazel-Edge", commit <40-hex>, authority_path_ref: "01rabbit/Azazel-Edge#N" or "01rabbit/Azazel-Edge@<40-hex>:<path>" (ASCII, exact match)}` |
| `executed` | bool | bool |
| `parts[name=detection]` | per-sample `start_monotonic_ns`, `end_monotonic_ns`, `drift_kind`, evidence ref; `pass_rule.bound_ms: 2000.0`; `pass_rule.evaluated` | same |
| `parts[name=withdrawal]` | per-sample start, `end_monotonic_ns: null`; gap `SO08-NO-EDGE-WITHDRAWAL-PATH` (mandatory, blocking) | per-sample start, probe-stops-reaching end, and `edge_enforcement_event_ref` (`edge-enforcement:<id>`) naming the Edge enforcement event; `pass_rule.bound_ms: 5000.0`; the same gap, mandatory and blocking, until Edge#412 |
| `verdict` | `fail` or `not_measurable` — never `pass` | `pass` / `fail` / `not_measurable`, recomputed from the samples |

**The identity check is shape-only.** `COMMISSIONED_IDENTITY_PATTERN` proves
the field has the commissioned-identifier *form*; it cannot prove the
identifier was commissioned, and a segment may still be spelled like an
interface (`az06-commission:site-a/node-7/br0` is well-formed). A reviewer
accepting a HIL record must check `commissioned_identity` against the
committed commissioning record for that site and node; the validator does not
and cannot do that for them.

The validator recomputes every part's verdict from its samples and gaps (a gap
with `blocks_verdict: true` forces `not_measurable`; every gap must carry a
boolean `blocks_verdict`) and refuses a record whose stated verdict is better
than its samples support. Both parts need 20 samples of every declared kind,
with unique `sample_id`s (copies do not count) and the same injections in
both; every finished detection sample names its evidence-chain record
(`evidence_event_id`, `evidence_seq`); times are integers, never booleans.
There is no `skip` verdict.

A passing HIL record is evidence an operator may cite as the `evidence_ref` of
a `LiveGateCertification` for `hil_host_restart_and_route_drift_injection`; it
is not itself a certification and authorizes nothing. Until Azazel-Edge#412
lands, no HIL record can pass either, because the withdrawal half has no
authority path to measure.
