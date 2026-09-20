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

**A producer's reported state is recorded, never spoken.** Since AC-7 the
snapshot carries what the producer said about itself, beside AZ-06's own
lifecycle state:

| Field | Meaning |
| --- | --- |
| `producer_defensive_state` | verbatim, exactly as the producer said it, or absent |
| `producer_defensive_state_is_canonical` | whether the pinned Fabric knows that word |
| `lifecycle_state` | AZ-06's own namespace, unchanged |

Three properties make this correlation rather than adoption.

*The field names its owner.* An unqualified `defensive_state` on an AZ-06 model
would be ambiguous about whose state it is, and that ambiguity is how two
namespaces merge. This one is unmistakably the producer's; the boundary test
refuses an unqualified spelling.

*The flag is computed, never accepted.* Both the evidence model and the
snapshot recompute it — the snapshot is the artifact an auditor reads and can
be built directly, so inheriting the claim would let anything that writes a
snapshot mark any word canonical by asserting it.

*The coercion fallback is discarded.* Fabric lands an unrecognized state on the
weakest one so a consumer *deciding what to do* fails safe. AZ-06 is not that
consumer: it is recording what a producer said. Substituting would turn "the
producer said something we do not know" into "the producer said `OBSERVE`" —
AZ-06 asserting another product's posture, which is the one thing this boundary
exists to prevent. An unrecognized word is kept verbatim with the flag `false`.

Adoption is a *validator* import (`coerce_defensive_state`), not a copy of the
vocabulary: the five values still appear in no AZ-06 string literal, and
recording a reported state still gives it no path to activation. Both
properties are re-asserted after adoption, because an adoption commit is
exactly what would erode them. This repository pins Fabric `v0.9.0rc2`; a test
fails if the pin stops being an exact tag or stops carrying the contract.

## Deployment guidance

Co-location with Edge is acceptable only for bounded development/demo profiles. Field deployment should use a separate host or a strong isolated virtualization boundary on a dedicated decoy segment.
