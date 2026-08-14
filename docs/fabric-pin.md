# Azazel-Fabric Pin

AZ-06 pins the stable Azazel-Fabric release tag:

`v0.5.0`

This release contains the canonical AZ-06 deception contract baseline
(`azazel_fabric.deception_contracts`, `azazel_fabric.deception_integrity`,
and the shared `azazel_fabric.testing.deception` golden factories) and
supersedes the earlier reviewed development-commit pin.

`v0.5.0` is formally released: the git tag exists, the GitHub Release is
published (not draft/prerelease, marked Latest), and the tag-driven Fabric
`release.yml` workflow ran green (it enforces that the tag matches
`azazel_fabric.__version__` and that the test suite passes before cutting the
release).

Pin policy: consumers pin an exact `vX.Y.Z` tag, never `main` and never a
development commit. Moving to a newer Fabric release is an explicit,
reviewed pin bump.
