# Bounded Lite profiles: `nexus-embedded-lite` and `boot-emergency-lite`

Status: **implemented** (`src/azazel_deception/overlay.py`), software-proven.
Deception#35 AC-3 and AC-4. Nothing here has been observed on hardware, and
neither profile has been signed or released.

Related: [contracts](contracts.md) · [safety model](safety-model.md) ·
[live gate checklist](live-gate-checklist.md) · [fabric pin](fabric-pin.md)

## 1. What a profile is

A Lite profile is a **reduction of one signed package**, not a package of its
own and not a patch applied to one. It removes components, surfaces and
credentials, and it lowers resource ceilings. It can do nothing else.

AZ-06 materializes what Edge already approved. A profile selects nothing,
approves nothing, and widens nothing; rendering one grants no authority that
the signed base did not already carry, which is none.

## 2. Why widening is unrepresentable, not merely rejected

`ProfileOverlay` has no free-form field. Every field is either

- a set of identifiers that must already resolve inside the signed base
  (`keep_components`, `keep_surfaces`, `keep_credentials`), or
- a numeric ceiling combined with the base's by taking the **minimum**.

There is nowhere to write an image, a port, a route, a DNS name, a mount, a
command or a credential the base does not already carry. An overlay naming
something absent is refused at render time rather than silently ignored, and a
ceiling above the base's is clamped rather than honoured.

That is the first layer. The second is `assert_is_reduction`, which checks a
rendered manifest **independently of how it was produced** — so a rendering
made by hand, by a later tool, or by a compromised builder is held to the same
rule.

## 3. The four dimensions the schema does not model

Deception#35 names ten dimensions. Six have fields in
`deception-package/v0.1`: services, images, ports, capabilities, credentials,
resources. **Routes, DNS, mounts and commands do not exist in the schema at
all.**

Rather than invent schema for them, the check proves something stronger and
schema-independent: **every string in the rendered manifest already appears in
the signed package.** A route, a DNS name, a mount path or a command has to
arrive as a string that was not there before, so none can be introduced —
whether or not the schema ever learns to model them.

The `package_digest` is the single exemption, because it is recomputed over the
reduced payload by design.

This guard is not a substitute for the per-dimension checks and does not make
them redundant. A tamper that reuses material already in the package — swapping
one component's image for another's, or moving an existing surface to a
different port number — introduces no new string and is caught only by the
dedicated check. Both layers are exercised by tests that defeat the other one.

## 4. What the profile artifact declares

A rendering carries its own `selection`, so the manifest can be checked against
the profile's claim and not only against the base.

Without it, re-adding a component the profile excluded reads as a reduction of
the base — which it is — while being a widening of the profile, which is what a
consumer actually installed.

**What this catches:** an edit to the manifest alone. **What it does not
catch:** a consistent edit to both the selection and the manifest, which
produces a different profile that is still a valid reduction of the same base.
Deciding *which* profiles are authorized is a policy question for whatever
verifies this artifact, not for this module.

## 5. The two profiles, and one thing they do not do

Both are authored against `examples/packages/municipal-linux-v1`. A deployment
authors its own against whatever package it actually signed.

| | `nexus-embedded-lite` | `boot-emergency-lite` |
| --- | --- | --- |
| components | `intranet-web` | `intranet-web` |
| memory ceiling | 2048 MiB | 1024 MiB |
| storage ceiling | 4096 MiB | 2048 MiB |
| bandwidth ceiling | 2000 kbps | 512 kbps |
| max connections | 100 | 100 |
| evidence events | 50 000 | 5 000 |
| evidence bytes | 32 MiB | 4 MiB |
| evidence retention | 7 days | 12 hours |

**Boot Lite's compute ceiling equals this package's declared floor, and does
not go below it.** The package states its `lite` tier needs 100 connections,
1024 MiB and 2048 MiB of storage. A profile cannot promise a workload less than
the workload declared, so lowering a ceiling past a declared minimum is a
misconfiguration rather than a reduction, and the renderer refuses it.

That constraint was **found by the guard, not assumed**: the first authored
Boot ceiling asked for 25 connections and was refused. Against this base
package, Boot Lite therefore differs from Nexus Lite in bandwidth and in
evidence budget, not in compute. A package authored for emergency use with a
smaller declared minimum would reduce further. This one does not, and saying so
is better than inventing headroom it never had.

## 6. Finite evidence budgets

Every profile must declare `max_observation_events`, `max_observation_bytes`
and `max_retention_seconds`, all positive. A profile that declines to state one
is refused at construction.

An unbounded evidence budget is how hostile telemetry consumes Core reserves,
so "bounded profile" and "finite evidence budget" are the same requirement
stated twice.

Boot's budget is an order of magnitude tighter on every axis. Boot runs on
borrowed hardware: the host is not ours, the session is short, and evidence
that outlives the incident is a liability rather than an asset.

## 7. What this does not establish

- That either profile has been **signed**. Neither has; a rendering binds to a
  signed base by digest and is itself a derived artifact.
- That either profile has been **deployed or measured**. No Nexus and no Boot
  host has been measured; the ceilings are conservative choices and config, not
  a hardware claim.
- That decoy reachability is zero (AC-6), that drift withdraws exposure within
  an SLO (AC-7), or that pressure cannot consume Core reserves (AC-8). All
  three are HIL evidence and none of it exists.
- That Boot Lite stays disabled when current-host isolation cannot be proven
  (AC-11). That is Boot's gate, not this module's.
