# Deception ↔ Knowledge Integration & Effectiveness Observation

Status: **design doctrine, pre-implementation.** This document fixes how
AZ-06 Azazel-Deception and AZ-04 Azazel-Knowledge relate, and how deception
effectiveness is observed. It is the reference for the effectiveness-observation
contract (`azazel_fabric` observation schema), the AZ-06 interaction emitter,
and the finite-state transition catalog.

Grounded in the inherited requirements recorded in
[`docs/source-traceability.md`](source-traceability.md):

- `01rabbit/Azazel#60` / `#61` — Engage-aligned, deterministic finite-state
  transitions, Edge final authority, LLM optional/preparation-oriented, evidence
  -preserving reset.
- `01rabbit/Azazel-Deception#6` (Phase 2) — emit sufficient canonical events for
  Knowledge to distinguish *observed interaction*, *observed reaction*,
  *measured outcome*, *runtime confounders*, and *unknowns*; **do not claim
  attacker belief from interaction alone.**
- `01rabbit/Azazel-Knowledge#52` — outcomes become evidence-backed **advisory**
  context; no executable directives; deterministic, replayable summaries with
  **confidence and counter-evidence**.
- `01rabbit/Azazel-Knowledge#58` — record tier/architecture/runtime
  adapter/active-omitted components/resource saturation/capability drift;
  **separate narrative effectiveness from host-capacity/runtime effects**; LLM
  availability is preparation metadata, not evidence that an LLM participated
  live.
- `01rabbit/Azazel-Edge#325` — Edge is the sole activation/transition/termination
  authority; AZ-06 is optional; Knowledge is advisory; Fabric is descriptive.

## 1. The relationship: data is bidirectionally visible, control is one-directional

The question "should Deception and Knowledge integrate?" resolves as **yes as a
data path, no as a mutual runtime coupling.** Observation flows one way;
authority stays with the human and Edge.

```text
Observation (one-way, incremental)
  Deception  ── interaction/reaction/outcome facts ──▶  Edge evidence plane
             (attacker-facing)      (untrusted framing)        │
                                                               ▼
                                                          Knowledge
                                                   (real-time analysis, attacker
                                                    assessment — advisory only)
                                                               │
                                              advisory (assessment + suggested
                                               configuration add/change)
                                                               ▼
Authority (one-way, signed)                                👤 User
  Deception  ◀── materialize approved change ──  Edge  ◀──  (decides = Engage
             (finite-state transition)      (signed decision)   intent)

FORBIDDEN: Knowledge ──▶ live Deception (direct/automatic reconfiguration).
Closing that loop lets the attacker steer and observe the decoy's adaptation
through their own behavior.
```

This matches the series doctrine exactly: *Engage expresses intent. Knowledge
advises. Fabric describes. Edge decides and enforces. Deception Host
materializes, transitions, records, and resets.*

## 2. Non-negotiable invariants

1. **Authority never crosses.** Knowledge is permanently advisory-only; it never
   selects a node, tier, placement, transition, or action. The authority to
   change a live decoy exists only with the human (intent) and Edge (decision).
2. **Determinism and signing hold.** A live decoy is never hand-edited. A change
   is either the selection of a pre-authored, frozen, signed finite-state
   transition, or an offline rebuild → freeze → sign → redeploy.
3. **The attacker is never in the loop.** No path lets attacker behavior
   automatically change the decoy. An assessment reaches the decoy only through
   a human decision.
4. **Attacker input is untrusted.** Incremental interaction logs are
   attacker-authored strings. They are framed as untrusted at the Edge evidence
   plane before Knowledge (especially any LLM analysis) consumes them, to
   contain poisoning/injection.

## 3. Granularity of "configuration change"

Even user-driven, a change is one of two tiers — never live ad-hoc editing.

| Change | How | When |
|---|---|---|
| **In-engagement small transition** (open one port, move to another narrative state) | User selects a pre-authored, frozen, signed **finite-state transition**; Edge approves | Live |
| **Structural addition / new narrative** | Offline package rebuild → freeze → sign → redeploy (terminate → evidence finalize → reset → redeploy) | Generational |

## 4. Observing deception effectiveness: the honesty ladder

Effectiveness observation fails when *interaction* is conflated with *belief* or
*effectiveness*. Observations are layered by claim strength and never mixed. The
higher the layer, the stronger the claim and the weaker the evidence.

| Layer | Observable fact | Can claim | Cannot claim |
|---|---|---|---|
| ① Interaction | attacker contacted the decoy | "was touched" | "believed it was real" |
| ② Reaction | behavior changed after contact (deeper probing, credential use, lateral attempt) | "reacted" | "was deceived" |
| ③ Outcome | measured quantities (dwell time, credentials spent, attempt count, stages reached) | "absorbed this much resource" | causal certainty |
| ④ Inference | probabilistic estimate of belief/intent | belief/intent **with confidence + counter-evidence** (advisory) | certainty |

**Layers ①–③ are facts that AZ-06 emits. Layer ④ is Knowledge's advisory
output** (with confidence and counter-evidence per Knowledge#52). AZ-06 does not
score its own effectiveness.

### Confounders that must be subtracted

Failing to separate these overstates effectiveness. The observation contract
carries explicit confounder tags and runtime context:

- **Scanner/bot noise** — indiscriminate scanning is not a "reaction".
- **Our own health checks / heartbeat** — internal traffic is not attacker reaction.
- **Host-capacity / runtime effects** — did the narrative work, or did a loaded
  host just extend dwell time? (narrative effectiveness vs host-capacity effect).
- **Architecture context** — ARM64/AMD64 runtime context is retained while
  package identity is preserved.

## 5. Who says what

| Component | Role | Authority |
|---|---|---|
| **Deception** | Emits facts (①②③ raw signals with confounder tags). Does not score itself. | emit only |
| **Knowledge** | Infers (④ assessment, confidence + counter-evidence). Decides/enforces nothing. | advisory |
| **👤 User** | Interprets; expresses the next move as Engage intent. | intent |
| **Edge** | Decides; issues signed decisions; sole activation/transition/termination authority. | decision/enforcement |

## 6. Contract surface (this doctrine, in code)

- **Effectiveness observation schema** (Fabric) — canonical, fact-only
  interaction/reaction/outcome events with confounder tags and runtime context;
  **belief/effectiveness-verdict fields fail closed** (mirrors the runtime
  -directive guard). Deception emits it; Knowledge consumes it.
- **Effectiveness advisory schema** (Fabric) — Knowledge's ④ output: assessment
  with confidence and counter-evidence, non-executable, references the
  observations it summarizes.
- **AZ-06 interaction emitter** (Deception) — records structured observations to
  the tamper-evident evidence chain; refuses verdict fields; attaches runtime
  context from placement/package.
- **Finite-state transition catalog** (Fabric) — pre-authored, frozen, signed
  set of transitions bound to a package; each declares current/target state,
  evidence-backed trigger, expected observation, resource/time/network bounds,
  rollback/termination conditions, and mandatory Edge approval. AZ-06 executes
  only catalog entries authorized by Edge.

## 7. Summary

> Observing deception effectiveness means separating interaction / reaction /
> outcome / inference as layers, subtracting confounders, leaving the ④
> effectiveness judgement to Knowledge as confidence-bearing advisory, and
> keeping AZ-06 to the incremental emission of facts. "Touched = effective" is
> structurally forbidden. Data is bidirectionally visible; control is
> one-directional and passes through the human and Edge.
