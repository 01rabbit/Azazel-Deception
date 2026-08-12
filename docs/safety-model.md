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

Live activation requires a valid, expiring Edge decision once Edge#325 and Fabric#9 are implemented.

## LLM boundary

LLM use is preparation-only by default. Generated material must be reviewed/validated, frozen, versioned, and signed before deployment. Runtime inference cannot select actions, expose services, change routes, authorize transitions, or mutate the live narrative.

## Deployment guidance

Co-location with Edge is acceptable only for bounded development/demo profiles. Field deployment should use a separate host or a strong isolated virtualization boundary on a dedicated decoy segment.
