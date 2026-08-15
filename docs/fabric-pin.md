# Azazel-Fabric Pin

AZ-06 pins the stable Azazel-Fabric release tag:

`v0.6.0`

This release adds the AZ-06 effectiveness-observation contracts
(`InteractionObservation`, `EffectivenessAdvisory`, the
`assert_no_effectiveness_verdict` honesty guard) and the finite-state
transition catalog (`FiniteStateTransition`, `TransitionCatalog`,
`select_transition`, `catalog_content_digest`), on top of the `v0.5.0`
canonical deception contract baseline (`azazel_fabric.deception_contracts`,
`azazel_fabric.deception_integrity`, shared golden factories). Additive and
non-breaking over `v0.5.0`.

`v0.6.0` is cut through the tag-driven Fabric `release.yml` workflow (it
enforces that the tag matches `azazel_fabric.__version__` and that the test
suite passes before cutting the release).

Pin policy: consumers pin an exact `vX.Y.Z` tag, never `main` and never a
development commit. Moving to a newer Fabric release is an explicit,
reviewed pin bump.
