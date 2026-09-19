# Azazel-Fabric Pin

> **Single source of truth.** The authoritative, machine-readable pin is the
> `azazel-fabric` requirement in `pyproject.toml`. This document describes that
> pin and nothing else restates the version number: every other document in this
> repository links here (or to `pyproject.toml`) instead of repeating a version,
> so a pin bump can never leave a stale copy behind. A bump changes exactly two
> places — `pyproject.toml` and this file — plus a CHANGELOG entry.

AZ-06 pins the stable Azazel-Fabric release tag:

`v0.8.0`

## What this release provides

`v0.8.0` adds `azazel_fabric.deception_contracts.decision_signing` — the single
authoritative definition of the HMAC-SHA256 transport signature over an Edge
decision envelope (`canonical_decision_bytes`, `compute_decision_signature`,
`sign_decision`, `verify_decision_signature`) — and publishes cross-repo golden
decision vectors through `azazel_fabric.testing` (`load_golden_decision`,
`golden_decision_names`, `GOLDEN_DECISION_SIGNATURE_KEY`). Its canonicalization
is byte-identical to AZ-06's `azazel_deception.runtime.transport`, so an
Edge-side producer and the AZ-06 consumer sign and verify the same bytes.
Fabric describes the wire format only: a signature proves origin and integrity,
never authority.

`v0.8.0` is additive and non-breaking over the earlier baselines it carries:

- `v0.5.0` — the canonical deception contract baseline
  (`azazel_fabric.deception_contracts`, `azazel_fabric.deception_integrity`,
  shared golden factories);
- `v0.6.0` — the AZ-06 effectiveness-observation contracts
  (`InteractionObservation`, `EffectivenessAdvisory`, the
  `assert_no_effectiveness_verdict` honesty guard) and the finite-state
  transition catalog (`FiniteStateTransition`, `TransitionCatalog`,
  `select_transition`, `catalog_content_digest`);
- the `0.7.0` MITRE Engage-aligned `engagement_contracts` family, which shipped
  inside the `v0.8.0` tag — Fabric cut **no `v0.7.0` tag**, so `v0.6.0` →
  `v0.8.0` is the only upgrade path and a document citing `v0.7.0` as a pinnable
  release is wrong.

## Release status

The `v0.8.0` tag exists on `01rabbit/Azazel-Fabric` and its GitHub Release is
published (not draft, not prerelease, published 2026-08-22). Fabric cuts tags
through its tag-driven `release.yml` workflow, which enforces that the tag
matches `azazel_fabric.__version__` and that the test suite passes before the
release is cut.

In series status vocabulary
(`Azazel/docs/roadmaps/third-party-development-handoff.md` §7) the pin is
**verified** for AZ-06's software suite: `pytest` is green against the installed
`azazel_fabric 0.8.0` on `main`, on Linux amd64, Linux arm64 and macOS arm64 CI
runners. It is not a claim about field or HIL properties.

## Pin policy

Consumers pin an exact `vX.Y.Z` tag, never `main` and never a development
commit. Moving to a newer Fabric release is an explicit, reviewed pin bump that
updates `pyproject.toml`, this document, and the CHANGELOG together.

## Pin history

| AZ-06 change | Pin |
|---|---|
| `dba1400` (2026-08-14) | reviewed development commit → `v0.5.0` |
| `c3154de` (2026-08-15) | `v0.5.0` → `v0.6.0` |
| `77ad0cd` (2026-08-22) | `v0.6.0` → `v0.8.0` (current) |
