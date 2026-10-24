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

`v0.9.0rc5`

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

`v0.9.0rc3` is the pin now, and the move was **not** optional for this
repository. It widens the `effect_contracts` reference grammar so that a typed
reference's body may contain further colons. Under `rc2` it could not, which
meant every hierarchical reference AZ-06 mints — `surface:http:8080`,
`artifact:honey:invoice-2026` — was refused by every slot requiring a typed
ref, and `runtime/effect_projection.py` had to refuse them rather than flatten
them. Rewriting a producer's identifier is not an option: `surface:http-8080`
is a well-formed reference to a surface that does not exist.

`v0.9.0rc4` narrows `EffectObservation` to the two
authority classes an observation can have observed — `observed_fact` and
`active_materialized` (Azazel-Fabric#52) — and refuses the four others that
`rc3` accepted. **It is the first non-additive candidate in the series**, and
the reason this repository moves to it is not that the grammar changed
somewhere: AZ-06 is a *producer* of `EffectObservation`, so this is the
contract it emits under.

The move costs nothing here because `runtime/effect_projection.py` already
derives the class from the observation's status and can emit only those two —
`observe_effect` has no parameter for it. What changes is that this became a
guarantee of the contract instead of a habit of one function. A future edit
introducing a third class would now be refused at the boundary rather than
accepted and carried downstream.

The pin was verified before the move rather than after: the `v0.9.0rc4` tag's
own checkout reproduces `release/v0.9.0rc4.digest.json`, whose signature
verifies under the release owner's key, and this repository's full suite runs
green against it. **What is signed is that digest; the git tag itself is
unsigned** and is not a trust boundary (Azazel-Fabric#56).

That refusal was recorded as a test designed to fail when the pin moved, and it
did. The stand-in values are gone from
`tests/test_effect_contracts_producer.py`; AZ-06's own references now go into
`PresentedTerrainRef` unchanged.

`v0.9.0rc5` is the pin now (Azazel-Deception#50). It is **additive** over
`rc4` (Azazel-Fabric#51): `PresentedTerrainRef` gains `trace_id`,
`synthetic_identity_refs`, `synthetic_credential_refs` and `source_effect_ref`,
`activation_decision_ref` becomes optional, and a terrain may bind to its
effect by effect and trace instead of by decision. Every `rc4` payload stays
valid and chains as before. The pin was held at `rc4` until AZ-06 adopted the
change, because moving it without carrying the values would gain nothing; the
move and the adoption land together.

What AZ-06 adopts:

- **`trace_id`** is carried. Once a terrain carries it, the chain check
  compares it, so a terrain cannot be chained to an effect of another
  incident.
- **`synthetic_identity_refs` / `synthetic_credential_refs`** are carried
  unchanged when they are already typed `identity:` / `credential:` references,
  and refused otherwise. They are never given a prefix: an identifier that was
  rewritten no longer points at what it pointed at (the same reason as
  `surface:http-8080` above). Recognizable secret material is refused by the
  projector before any Fabric record is constructed, in addition to Fabric's
  own check -- in every reference field it emits, not only the credential
  slot: evidence and isolation references are published too.
- **Binding a shadow run.** AZ-06's default mode is `planned_shadow`, and under
  `rc4` its terrain could not be chained to its effect at all.
  `project_presented_terrain(..., source_effect=...)` now binds one through
  `source_effect_ref` + `trace_id`, names no decision and claims
  `planned_shadow`. Only a `stale` presentation without active surfaces may be
  bound this way: `active`, `terminated` and `reset` say an environment ran,
  `failed` says a run was attempted, and live surfaces under a shadow label
  would be a materialization. Binding is not
  accepting: `accept_defensive_effect_ref` still declines to materialize a
  shadow run.
- **Trailing newlines.** The pinned grammar accepts `kind:body\n` as a typed
  reference (Azazel-Fabric#65). AZ-06 does not rely on that: the projector
  refuses whitespace and control characters in every reference it emits --
  typed or untyped, from the snapshot (including the activation decision,
  evidence and isolation references), from the caller (`isolation_result_ref`)
  and from a bound effect (`effect_id`, `decision_ref`, `trace_id`). The
  producer evidence and the snapshot also refuse them where they enter, since
  their trace and decision references were checked only for length.

The pin was verified before the move, against the same four criteria as
`rc4`:

- **Signature.** The `v0.9.0rc5` tag's own checkout (`450d950`) reproduces
  `release/v0.9.0rc5.digest.json`
  (`sha256:c183eb92dfd706cc2bcf69bad37641588f440c488b0264564c7a8e044647cc9d`)
  with `tools/rc_digest.py --check`, and `tools/rc_signature.py --check`
  verifies its signature under `release-owner` — both with the tag's own key
  file and with the key file as it stood at `v0.9.0rc4`, so the trust root is
  not one the new tag supplied. As with `rc4`, what is signed is the digest;
  the tag is unsigned. The signing-key incident (Azazel-Fabric#61) suspends new
  signatures by that key; `rc5` was signed and published before it.
- **Version.** The installed distribution equals the pin
  (`tests/test_fabric_pin_documentation.py` checks it on every run).
- **Compatibility.** This repository's full suite is green against it.
- **Degradation.** `azazel-fabric` is a required dependency. There is no
  degraded path in which AZ-06 runs without Fabric, so there is none to
  verify.

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

`v0.9.0rc2` further carries `azazel_fabric.effect_contracts` (Fabric#15), the
cross-series effect / outcome / presented-terrain family. AZ-06 is its **first
producer anywhere in the series**: `runtime/effect_projection.py` renders the
local `PresentedTerrainSnapshotV0` as `PresentedTerrainRef`.

The projection refuses rather than fills gaps. Fabric's record requires facts
AZ-06 does not always hold — a declared expiry above all — and each plausible
default would make the contract look adopted while reporting something AZ-06
never observed. A refusal names the missing fact; an invented bound would have
told a consumer that AZ-06 time-boxed a presentation it did not.

Every projection also returns the list of local fields that reach no Fabric
slot, because a lossy projection that reports nothing is how a consumer comes
to read the Fabric record as the whole of what AZ-06 observed. Until
`v0.9.0rc5` three entries were worth naming there: `trace_id`, and
`synthetic_identity_refs` / `synthetic_credential_refs`, which Fabric#15's own
field list named and the shipped model did not carry. `rc5` gave all three a
slot, and they are now carried (see above).

AZ-06 is also this family's **first consumer**. `runtime/effect_projection.py`
accepts a `DefensiveEffectRef` produced by Azazel-Edge and emits an
`EffectObservation` against it, which closes a gap this document previously
recorded as open: the observation is keyed on an `effect:`-typed id that
nothing in the series minted, so it had no possible producer anywhere.
Azazel-Edge#419 mints it.

What AZ-06 refuses is doctrine rather than taste. It materializes an
Edge-approved environment, so it declines an effect carrying
`advisory_inference` or `planned_shadow` — advised or considered is not
approved, and materializing one would make AZ-06 the step that turns a
suggestion into an environment. It also declines any effect class other than
`redirect_to_presented_terrain`, because Presented Terrain has no meaning
behind isolation or a notification, and any effect naming AZ-06 itself as
producer.

`OutcomeObservationEnvelope` remains unproduced here. It correlates
`outcome_contracts` records across a window, which is a different job from
observing one materialization, and AZ-06 has no window to speak for.

At `v0.9.0rc2` the hierarchical references AZ-06 actually mints
(`surface:http:8080` and the like) were refused by every slot requiring a typed
ref, because that grammar split on a colon and then forbade the body from
containing one. That measurement is what produced
[Azazel-Fabric#48](https://github.com/01rabbit/Azazel-Fabric/pull/48) and,
through it, `v0.9.0rc3`.

`tests/test_effect_contracts_producer.py` recorded the refusal in a form
designed to **turn red when the pin moved**, and it did. The stand-in values
are gone; AZ-06's references reach the record unchanged. What the file records
now is the distinction that survived: `deception:surface:http-8080` is still
untyped, because Fabric has no `deception` kind. Widening the body did not stop
the grammar discriminating — a value is untyped when Fabric does not know its
kind, never because of how it was punctuated.

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
| Deception#28 AC-7 (2026-09-20) | `v0.8.0` → `v0.9.0rc2` |
| `effect_contracts` producer (2026-09-20) | `v0.9.0rc2` → `v0.9.0rc3` — the reference grammar; see above |
| `EffectObservation` authority narrowing (2026-09-20) | `v0.9.0rc3` → `v0.9.0rc4` — AZ-06 emits this record, so it moves with the contract it emits under; see above |
| Deception#50 (2026-10-24) | `v0.9.0rc4` → `v0.9.0rc5` (current) — carries `trace_id` and the synthetic identity / credential references, and binds a shadow run to its effect; see above |
