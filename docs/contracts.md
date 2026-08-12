# Contract Integration

Canonical shared contracts belong in **Azazel-Fabric**, not this repository.

Tracked dependency: `01rabbit/Azazel-Fabric#9` (built on engagement contracts in `#8`).

Expected canonical concepts:

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

The local `deception-package/bootstrap-v0.1` and `host-capabilities/bootstrap-v0.1` shapes exist only to make Phase 0 development testable. They are not public Azazel wire contracts and must be replaced or adapted behind a compatibility layer when Fabric publishes the canonical version.

No shared contract may carry a directive that bypasses Edge authority.
