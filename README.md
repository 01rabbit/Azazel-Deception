# AZ-06 Azazel-Deception - Container-First Engagement Environment Host

> **Codename:** `THEATRE`

Azazel-Deception is **AZ-06 Azazel-Deception Host**, the attacker-facing Engagement Environment Plane of the Azazel series.

It materializes bounded, coherent deception environments from versioned packages after approval by Azazel-Edge. It is a portable, capability-aware, container-first runtime: Raspberry Pi 5 is a minimum reference host, not a product constraint.

> Engage expresses intent. Knowledge advises. Fabric describes. Edge decides and enforces. Deception Host materializes, transitions, records, and resets.

## Status

**Bootstrap / Phase 0-1.** The repository exists and the AZ-06 designation is ratified, but live engagement remains disabled by default until the shared Azazel-Fabric deception-environment contracts and Edge integration gates are stable.

Initial portability target:

- OCI containers
- `linux/arm64` and `linux/amd64`
- Docker Compose reference adapter
- static Linux deception package
- deterministic package validation, lifecycle, evidence, and reset semantics
- no GPU, KVM, Kubernetes, or online LLM requirement

Current bootstrap already provides host capability discovery, fail-closed package validation, deterministic non-executing placement planning, a synthetic Linux reference package, isolated Compose assets, CI, tests, and safety/integration documentation.

## Responsibility boundary

Azazel-Deception owns:

- host capability discovery
- validation and materialization of already-approved deception packages
- isolated decoy services, files, credentials, personas, and bounded activity runtime
- execution of approved finite-state transitions
- interaction evidence export
- deterministic reset and credential invalidation

Azazel-Deception does **not** own:

- final engagement decisions or route enforcement — Azazel-Edge owns those
- shared wire-contract authority — Azazel-Fabric owns those contracts
- effectiveness scoring or posture authority — Azazel-Knowledge remains advisory-only
- unrestricted autonomous planning
- hack-back, attacker-system compromise, arbitrary code delivery, or uncontrolled decoy egress
- runtime LLM authority

## Architecture

```text
Azazel-Knowledge Advisor
        | advisory-only context
        v
Azazel-Edge Gateway
  deterministic approval / routing / budgets / termination
        | signed, versioned decision
        v
Azazel-Deception Host
  package validation / capability match / runtime adapter / evidence / reset
        | measured outcomes
        v
Azazel-Knowledge Advisor
```

Within AZ-06:

```text
DeceptionPackage
      |
      v
Package Validator ---- Host Capabilities
      |                     |
      +----------+----------+
                 v
          Placement Planner
                 |
                 v
          Runtime Adapter
          Docker Compose
                 |
                 v
       Isolated Decoy Runtime
                 |
                 v
       Evidence + Reset Result
```

## Deployment tiers

| Tier | Reference host | Intended use |
|---|---|---|
| `lite` | Raspberry Pi 5 / ARM64 SBC | one small static Linux environment |
| `standard` | N100/N305-class x86 mini PC | multiple containers and richer deterministic environments |
| `heavy` | KVM-capable x86 host | later VM-capable and multi-segment environments |
| `cluster` | multiple nodes | future work; not part of the initial implementation |

Packages declare required capabilities and explicitly optional components. Missing required capabilities fail closed; AZ-06 never silently weakens isolation or required narrative components.

## LLM policy

LLM use is optional and preparation-oriented. It may help draft narratives, synthetic documents, personas, or package content before deployment. Any AI-generated material must be validated, frozen, versioned, and signed before activation.

Approved packages remain fully executable with **no LLM available at runtime**. An LLM never selects an engagement, opens a port, changes routing, authorizes a transition, or mutates a live environment autonomously.

## Safety invariants

- no route from decoy workloads to protected production assets
- decoy egress denied by default
- no real credentials, personal data, secrets, or production artifacts in reference packages
- explicit duration, CPU, memory, storage, connection, and traffic budgets
- fail closed on unsupported schema, capability mismatch, invalid provenance, stale decision, or inconsistent narrative
- operator-visible lifecycle and manual termination
- evidence-preserving deterministic teardown and reset
- Docker socket, Edge control APIs, and host privileged interfaces are never exposed to attacker-facing workloads

See [`docs/safety-model.md`](docs/safety-model.md).

## Bootstrap CLI

The initial CLI is intentionally non-executing. It reports host capabilities, validates the bootstrap reference package, and produces a deterministic placement plan while the Fabric and Edge activation contracts stabilize.

```bash
python -m azazel_deception capabilities
python -m azazel_deception validate examples/packages/municipal-linux-v1/package.yaml
python -m azazel_deception plan examples/packages/municipal-linux-v1/package.yaml
```

The `plan` command produces a descriptive placement plan only. It does not start containers and carries no activation authority.

## Repository layout

```text
src/azazel_deception/       bootstrap control-plane code
runtime/compose/            reference Docker Compose adapter assets
examples/packages/          deterministic reference deception packages
docs/                       architecture, safety, contracts, integration, roadmap, traceability
tests/                      deterministic bootstrap tests
```

## Design traceability

The requirements inherited from the Azazel-series issues are mapped in [`docs/source-traceability.md`](docs/source-traceability.md). This records which doctrine, Fabric, Edge, Knowledge, and Gadget issues produced each AZ-06 responsibility and safety invariant.

Primary cross-repository dependencies:

- Doctrine / parent: `01rabbit/Azazel#61`
- Engage system model: `01rabbit/Azazel#60`
- Shared contracts: `01rabbit/Azazel-Fabric#9` and `#8`
- Edge authority / activation: `01rabbit/Azazel-Edge#325` and `#319`
- Effectiveness analysis: `01rabbit/Azazel-Knowledge#58` and `#52`
- Gadget fixed-profile compatibility boundary: `01rabbit/Azazel-Gadget#17` and `#16`

## Implementation trackers

| Issue | Purpose |
|---|---|
| [#1](https://github.com/01rabbit/Azazel-Deception/issues/1) | Replace bootstrap schemas with canonical Azazel-Fabric deception contracts |
| [#2](https://github.com/01rabbit/Azazel-Deception/issues/2) | Implement feature-disabled Docker Compose lifecycle adapter |
| [#3](https://github.com/01rabbit/Azazel-Deception/issues/3) | Prove one signed reference package on ARM64 and AMD64 |
| [#4](https://github.com/01rabbit/Azazel-Deception/issues/4) | Build isolation, evidence, termination, and deterministic reset test harness |
| [#5](https://github.com/01rabbit/Azazel-Deception/issues/5) | Implement AZ-01 Edge shadow/replay integration before live activation |
| [#6](https://github.com/01rabbit/Azazel-Deception/issues/6) | Phase 2 coherent narrative, honey artifacts, credentials, personas, and finite-state transitions |

The intended implementation order is **#1 → #2/#3/#4 → #5 → live Phase 1 gate → #6**. Live exposure must not be enabled merely because a runtime adapter can start containers.

## Phase order

1. Phase 0 — canonical contracts, threat model, isolation, provenance, golden fixtures, dry-run only.
2. Phase 1 — one static coherent Linux environment on ARM64 and AMD64, behind explicit Edge authorization and feature gates.
3. Phase 2 — coherent honey artifacts, decoy-only credentials, deterministic personas, and Edge-approved finite-state transitions.
4. Phase 3 — Knowledge effectiveness loop, advisory-only.
5. Phase 4 — additional Linux/Windows/OT/IoT environment classes after isolation and reset are proven.

## Claims

Use `MITRE Engage-aligned` or `Engage-informed`. This project does not claim MITRE certification or guaranteed attacker belief. Measure and report **observed interaction**, **observed reaction**, and **measured outcomes**.

## License

MIT. See [`LICENSE`](LICENSE).
