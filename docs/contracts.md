# Contract Integration

Canonical shared contracts belong in **Azazel-Fabric**, not this repository.

Tracked dependency: `01rabbit/Azazel-Fabric#9` (built on engagement contracts in `#8`). These contracts are **published and consumed**: AZ-06 pins an exact Fabric release tag (see [`fabric-pin.md`](fabric-pin.md)) and `Azazel-Deception#1`, the migration tracker, is closed.

Canonical concepts (those AZ-06 consumes today are listed in the "Canonical contracts" section of [`implementation-status.md`](implementation-status.md); the rest are declared by Fabric and not yet consumed here):

- `DeceptionPackage`
- `NarrativeManifest`
- `EnvironmentProfile`
- `ArtifactManifest`
- `PersonaProfile`
- `CredentialLure`
- `DecoySurface`
- `EnvironmentState`
- `EnvironmentTransitionCandidate`
- `EnvironmentTransitionDecision`
- `EnvironmentActivationDecision`
- `EnvironmentTerminationDecision`
- `EnvironmentEvent`
- `EnvironmentOutcome`
- `NarrativeConsistencyReport`
- `HostCapabilities`
- `RuntimeRequirements`
- `DeploymentTier`
- `RuntimeAdapterDescriptor`
- `PlacementPlan`
- `ImageManifest`

## Bootstrap rule

The local `deception-package/bootstrap-v0.1` and `host-capabilities/bootstrap-v0.1` shapes exist only to make Phase 0 development testable. They are not public Azazel wire contracts. Now that Fabric has published the canonical shapes, the bootstrap shape survives **as compatibility input only**: it is normalized into the canonical Fabric model immediately on load, and it is usable only after an explicit seal (`tests/test_package_integrity.py::test_bootstrap_is_usable_only_after_explicit_seal`).

No shared contract may carry a directive that bypasses Edge authority.
