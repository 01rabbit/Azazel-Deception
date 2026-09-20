# Versions and the Azazel-Fabric Pin

> **Single source of truth.** The authoritative, machine-readable values are in
> `pyproject.toml`: `[project].version` for the product version and the
> `azazel-fabric` requirement for the Fabric pin. This document describes them
> and nothing else restates a version number: every other document in this
> repository links here (or to `pyproject.toml`) instead of repeating one, so a
> bump can never leave a stale copy behind. A bump changes exactly two places —
> `pyproject.toml` and this file — plus a CHANGELOG entry.

## Product version

AZ-06 currently declares:

`0.2.0.dev0`

This is a pre-release development version. No stable version has been released
and the repository carries no release tag; work in progress is recorded under
`[Unreleased]` in [`CHANGELOG.md`](../CHANGELOG.md), which describes it as
development toward `0.2.0`.

`azazel_deception.__version__` reports the same value because it is **derived**,
not written down a second time: `src/azazel_deception/__init__.py` reads it from
the installed distribution metadata. It previously carried its own literal and
drifted to `0.1.0.dev0` while `pyproject.toml` said `0.2.0.dev0`
(`Azazel-Deception#38` item 1); removing the second copy makes that class of
drift structurally impossible rather than merely noticed.

## Fabric pin

AZ-06 pins the Azazel-Fabric release tag:

`v0.9.0rc2`

### Why a release candidate

This is a deliberate, narrow deviation from the "exact stable tag" policy
below, recorded here rather than left to be discovered in `pyproject.toml`.

`v0.9.0rc2` is the first tag carrying `azazel_fabric.schema.defensive_state` —
the canonical Defensive State vocabulary (`OBSERVE` `NOTIFY` `THROTTLE`
`REDIRECT` `ISOLATE`) and `coerce_defensive_state`. AZ-06 needs it as a
*validator* to classify a producer-reported state without copying the
vocabulary into this package (Deception#28 AC-7, see
[`safety-model.md`](safety-model.md)). Waiting for `v0.9.0` would mean either
holding AC-7 or copying the five values here, and the copy is precisely what
the boundary forbids.

The risk is bounded by what AZ-06 uses it for: one function, on a field that no
runtime path reads. A candidate promises no stability, so this pin is revisited
when `v0.9.0` is cut — `git+...@v0.9.0` and nothing else changes.

## What this release provides

`v0.9.0rc2` adds `azazel_fabric.schema.defensive_state`: the canonical
Defensive State vocabulary, owned in exactly one place, and
`coerce_defensive_state`, which reports both a fail-safe value and whether the
input was recognised. AZ-06 uses only the recognition flag; see
[`safety-model.md`](safety-model.md) for why the fail-safe value is discarded
here.

`v0.9.0rc2` also carries `azazel_fabric.outcome_contracts`, which AZ-06 both
consumes and produces:

- `runtime/producer_evidence.py` **consumes** `MechanismObservationV0` — the
  already-observed REDIRECTION mechanism fact that Presented Terrain linkage
  is built on;
- `runtime/outcome_export.py` **produces** `OutcomeObservationV0` — the
  Presented Terrain lifecycle observation that joins that producer's evidence
  chain.

Both used to agree with the contract by coincidence of maintenance rather than
by construction: the consumer restated the contract's field list, banned-key
set and bound constants, and the producer assembled the wire shape by hand.
That copy had already drifted — Fabric had added `effectiveness` and
`initiative_score` to its tactical-claim refusals and AZ-06 had not. Both
sides now go through Fabric's models, with AZ-06's own narrowing kept on top
(stricter, never looser); `tests/test_outcome_contracts_adoption.py` holds the
direction.

It carries everything in `v0.8.0` below, additively.

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

The `v0.9.0rc2` tag exists on `01rabbit/Azazel-Fabric` and its GitHub Release is
published as a **prerelease** (2026-09-20) — Fabric's `release.yml` classifies
anything that is not exactly `vMAJOR.MINOR.PATCH` as a prerelease, so a
candidate cannot appear where a consumer looks for the latest stable release.

The superseded `v0.8.0` tag exists and its GitHub Release is
published (not draft, not prerelease, published 2026-08-22). Fabric cuts tags
through its tag-driven `release.yml` workflow, which enforces that the tag
matches `azazel_fabric.__version__` and that the test suite passes before the
release is cut.

In series status vocabulary
(`Azazel/docs/roadmaps/third-party-development-handoff.md` §7) the pin is
**verified** for AZ-06's software suite: `pytest` is green against the installed
`azazel_fabric 0.9.0rc2` on `main`, on Linux amd64, Linux arm64 and macOS arm64
CI runners. It is not a claim about field or HIL properties.

## Pin policy

Consumers pin an exact tag, never `main` and never a development commit. A
stable `vX.Y.Z` is the default; a candidate is pinned only with a recorded
reason and a stated condition for leaving it, as above. Moving to a newer Fabric release is an explicit, reviewed pin bump that
updates `pyproject.toml`, this document, and the CHANGELOG together.

## Pin history

| AZ-06 change | Pin |
|---|---|
| `dba1400` (2026-08-14) | reviewed development commit → `v0.5.0` |
| `c3154de` (2026-08-15) | `v0.5.0` → `v0.6.0` |
| `77ad0cd` (2026-08-22) | `v0.6.0` → `v0.8.0` |
| Deception#28 AC-7 (2026-09-20) | `v0.8.0` → `v0.9.0rc2` (current) |
