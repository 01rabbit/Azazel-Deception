# Safety Model

AZ-06 hosts attacker-facing workloads. Its security boundary therefore assumes decoy workloads can become hostile.

## Invariants

- No route from a decoy workload to protected production assets.
- Decoy egress is denied by default.
- No Docker/Podman socket is mounted into attacker-facing workloads.
- No Edge control API, Fabric authority surface, or host privileged interface is exposed to a decoy.
- `privileged` and host networking are prohibited for bootstrap profiles.
- Real production credentials, personal data, operational secrets, and real customer documents are prohibited in reference packages.
- Every live environment must have explicit duration and resource budgets.
- Every credential lure must be decoy-only, scoped, identifiable, and expiring once the canonical contract exists.
- Unsupported schema, architecture, runtime, capability, signature/digest, stale decision, or narrative contradiction fails closed.
- Reset and credential invalidation must be acknowledged before a host returns to ready state.

## Authority failures

Knowledge is advisory-only. Fabric is descriptive-only. A package is declarative-only. Capabilities are descriptive-only. None can activate or expand an environment.

Live activation requires a valid, expiring, one-shot Edge decision. This is enforced today, not pending: the canonical Fabric contracts of `Azazel-Fabric#9` are landed and pinned, and `DockerComposeAdapter.activate_environment` / `.terminate_environment` reject an absent, expired, not-yet-effective, mis-bound, or already-consumed decision before any runtime action. What is still open is the *networked* Edge→AZ-06 flow tracked in `Azazel-Edge#325` — see [`live-gate-checklist.md`](live-gate-checklist.md).

## LLM boundary

LLM use is preparation-only by default. Generated material must be reviewed/validated, frozen, versioned, and signed before deployment. Runtime inference cannot select actions, expose services, change routes, authorize transitions, or mutate the live narrative.

## Defensive State is not AZ-06's to hold

> **Deception materializes an approved engagement; it does not decide the
> producer's Defensive State.** (Deception#28)

Two vocabularies, two namespaces, and no path between them.

| | Owner | Values |
| --- | --- | --- |
| Defensive State | Azazel-Edge / Gadget, canonically Azazel-Fabric (Fabric#14) | `OBSERVE` `NOTIFY` `THROTTLE` `REDIRECT` `ISOLATE` |
| AZ-06 lifecycle | this repository | `active` `terminated` `reset` `failed` `stale` |

A `REDIRECT` decision may result in traffic reaching an AZ-06 environment.
`REDIRECT` is still not an AZ-06 lifecycle state, and the runtime refuses it as
one.

**AZ-06 never learns the producer's words.** The canonical vocabulary appears
nowhere in this package's code — a copy here would be a second place that
defines it, and the first thing a consumer would do with the copy is compare an
AZ-06 value to an Edge one, which is exactly the merge this boundary prevents.
`tests/test_defensive_state_boundary.py` parses every module and fails if one
of the five values appears as a string literal outside a docstring.

**A reported producer state is not an input.** The issue asks what happens when
the producer's state leaves `REDIRECT` while an environment is active. The
answer is *nothing, by itself*: the runtime acts on signed, one-shot Edge
decisions and on the lease it was given, and there is no parameter anywhere for
a reported state to arrive through. That is also why a stale, replayed, or
malformed producer state cannot activate or prolong an environment — not
because it is filtered, but because there is nothing to filter. The test
asserts this structurally over every public runtime entry point, so adding such
a parameter fails there rather than in a review nobody runs.

**Correlation without merging.** `PresentedTerrainSnapshotV0` carries
`producer_decision_ref` and `lifecycle_state` as separate fields, and neither
is derived from the other. An auditor can line up "which Edge decision" with
"what AZ-06 did" without the two becoming one state machine.

**Status: AC-7 open.** Adopting the Fabric#14 contract for status/audit
correlation waits on a Fabric release that carries it. This repository pins
`v0.8.0`; `DefensiveState` has shipped to no tag. A test fails the moment a pin
carrying the vocabulary lands, which is when that work becomes actionable.

## Deployment guidance

Co-location with Edge is acceptable only for bounded development/demo profiles. Field deployment should use a separate host or a strong isolated virtualization boundary on a dedicated decoy segment.
