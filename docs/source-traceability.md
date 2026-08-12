# Cross-Repository Requirement Traceability

This document records the Azazel-series issues that defined AZ-06 before and during repository bootstrap. It is a design traceability map, not a substitute for the canonical contracts in Azazel-Fabric.

## Umbrella doctrine

### `01rabbit/Azazel#60` — Engage-aligned adversary engagement model

Inherited requirements:

- MITRE Engage-aligned / Engage-informed wording only
- no hack-back, autonomous retaliation, or attacker-system compromise
- bounded duration/scope/resources and explicit termination
- AI may assist/explain but never select or execute core live actions
- system-level separation of intent, advice, contracts, decision, and execution

### `01rabbit/Azazel#61` — AZ-06 Engagement Environment Plane

Inherited requirements:

- formal series identity: AZ-06 Azazel-Deception Host, codename `THEATRE`
- coherent service/banner/history/artifact/credential/persona environment
- Edge remains final authority
- deterministic finite-state transitions rather than free-form autonomous planning
- evidence-preserving reset and credential invalidation
- container-first, capability-aware, hardware-independent runtime
- Raspberry Pi 5 is a minimum reference host, not a product constraint
- ARM64/AMD64 portability and Docker Compose initial adapter
- LLM is optional and preparation-oriented

## Shared contracts

### `01rabbit/Azazel-Fabric#8` — shared engagement contracts

Inherited requirements:

- engagement objective/approach/activity/candidate/outcome vocabulary
- candidate/advisory data is non-executable
- product-local decision authority remains outside Fabric
- unsupported command-boundary schema fails closed

### `01rabbit/Azazel-Fabric#9` — deception-environment contracts

Inherited requirements:

- canonical `DeceptionPackage`, narrative/environment/artifact/persona/credential/state/lifecycle/evidence types
- `HostCapabilities`, `RuntimeRequirements`, `DeploymentTier`, `RuntimeAdapterDescriptor`, `PlacementPlan`, `ImageManifest`
- OCI digest/provenance/SBOM and signature binding
- ARM64/AMD64 golden fixtures
- tier selection cannot remove required components or weaken safety
- bootstrap local schemas in this repository are temporary until Fabric publishes canonical shapes

## Edge authority

### `01rabbit/Azazel-Edge#319` — engagement candidates in deterministic loop

Inherited requirements:

- Evidence -> NOC/SOC -> candidate -> existing Action Arbiter -> bounded action
- NOC/mission availability preempts engagement value
- selected/rejected alternatives remain audit-visible
- feature disabled by default and replay/shadow before live action

### `01rabbit/Azazel-Edge#325` — AZ-06 integration

Inherited requirements:

- Edge approves activation, target node/capability class, tier, routing, budgets, transitions, downgrade, termination
- AZ-06 performs local runtime placement; Edge is not a Docker/KVM/Kubernetes scheduler
- capability negotiation is descriptive only
- heartbeat/state reconciliation, anti-replay, kill switch, deterministic stale-state handling
- terminate -> evidence finalize -> reset -> redeploy for initial hardware migration; no live attacker-session migration

## Knowledge feedback

### `01rabbit/Azazel-Knowledge#52` — engagement-effectiveness advisory

Inherited requirements:

- outcomes become evidence-backed advisory context
- no executable Knowledge directives
- deterministic, replayable summaries with confidence and counter-evidence

### `01rabbit/Azazel-Knowledge#58` — AZ-06 narrative/runtime effectiveness

Inherited requirements:

- record selected tier, architecture, runtime adapter/version, active/omitted components, resource saturation, capability drift
- separate narrative effectiveness from host-capacity/runtime effects
- preserve package identity across ARM64/AMD64 while retaining runtime context
- do not claim that interaction proves attacker belief
- LLM availability is preparation metadata, not evidence that LLM participated live

## Gadget boundary

### `01rabbit/Azazel-Gadget#16` — Engage-lite profiles

Inherited requirement for interoperability:

- Gadget remains limited to fixed, bounded local profiles and operator-controlled modes

### `01rabbit/Azazel-Gadget#17` — AZ-06 compatibility boundary

Inherited requirements:

- Gadget may consume only a minimal static compatible subset
- `linux/arm64` is required for fixed Gadget decoy artifacts
- no dynamic narrative/persona/credential-chain/VM orchestration on Gadget
- package identity/evidence may remain comparable with AZ-06 without claiming Gadget hosts AZ-06

## Bootstrap implementation mapping

| Requirement | Current AZ-06 bootstrap location |
|---|---|
| host capability discovery | `src/azazel_deception/capabilities.py` |
| fail-closed package validation | `src/azazel_deception/package.py` |
| descriptive placement plan | `src/azazel_deception/planner.py` |
| CLI / non-executing bootstrap | `src/azazel_deception/cli.py` |
| ARM64/AMD64 reference package | `examples/packages/municipal-linux-v1/package.yaml` |
| isolated Compose reference | `runtime/compose/reference-linux.compose.yaml` |
| authority and plane separation | `docs/architecture.md`, `docs/integration.md` |
| safety invariants | `docs/safety-model.md` |
| Fabric migration boundary | `docs/contracts.md` |
| delivery sequence | `docs/roadmap.md` |

## Change rule

When a source issue changes an authority, safety, portability, or contract requirement, update this traceability document and the corresponding implementation/test before enabling broader live execution.
