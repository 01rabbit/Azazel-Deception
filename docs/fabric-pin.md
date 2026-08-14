# Azazel-Fabric Pin

AZ-06 pins the stable Azazel-Fabric release tag:

`v0.5.0`

This release contains the canonical AZ-06 deception contract baseline
(`azazel_fabric.deception_contracts`, `azazel_fabric.deception_integrity`,
and the shared `azazel_fabric.testing.deception` golden factories) and
supersedes the earlier reviewed development-commit pin.

Pin policy: consumers pin an exact `vX.Y.Z` tag, never `main` and never a
development commit. Moving to a newer Fabric release is an explicit,
reviewed pin bump.
