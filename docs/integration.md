# Series Integration

## Azazel-Edge

Edge is the sole activation/transition authority for the initial architecture. Integration is tracked in `01rabbit/Azazel-Edge#325`, extending the Engage candidate work in `#319`.

Target flow:

```text
Evidence -> NOC/SOC -> Engagement Candidate -> Action Arbiter
        -> signed activation/transition decision -> AZ-06
        -> environment event/outcome -> audit + Knowledge ingest
```

Edge approves profile/capability class and budgets, not low-level Docker/KVM placement. AZ-06 must remain optional; Edge baseline operation cannot depend on AZ-06 availability.

## Azazel-Fabric

Fabric defines versioned wire contracts and invariants. AZ-06 consumes them; it does not redefine them.

## Azazel-Knowledge

Knowledge consumes measured outcomes and returns advisory-only effectiveness context. It never selects a node, deployment tier, runtime adapter, placement, transition, or action.

## Azazel-Gadget

Gadget remains outside the full AZ-06 runtime. It may consume a minimal static compatible package subset for `scapegoat`, but it does not host dynamic narratives, personas, multi-step credential paths, or long-running state machines.
