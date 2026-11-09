# Package-scoped local canary preparation and evidence

Tracking: #74; static integration remains #31, MIO feedback #55. Status: bounded
in-process preparation/matching and existing evidence-emitter projection. No
HTTP listener, route, package activation, production-page injection or external
callback is installed or enabled by this change.

`credentials.canaries.CanaryRegistry` reuses `mint_lure` / `LureRegistry` for
synthetic lure validity and invalidation. It adds a separate CSPRNG token, exact
package-digest/environment/boot/session/surface binding, presentation evidence,
replay/expiry checks and quotas. The old deterministic credential-lure contract
is preserved; its public identifier is not the new secret token.

## Usage boundary

Construct a validated `CanaryScope` from admitted package/lifecycle facts owned
by the product adapter. Construction itself grants nothing. Call `issue` with an
explicit aware timestamp and TTL. The returned `IssuedCanary` exposes its token
only for planting a reviewed synthetic local path/document; repr and
`public_reference()` omit it. `synthetic_openapi()` emits a fixed fake API
schema containing that relative path and no server/external address. Do not log
or export this document or its local path as audit evidence: it contains the
planted token. The registry stores only a token digest and safe opaque IDs.

After a real bounded presentation is observed, `present` binds an immutable
presentation evidence reference and timestamp. Without it, a matched request
is `touch_without_presentation`; it is not promoted to a presentation chain.
`touch` requires matching scope, event/evidence refs and explicit observation
time. Expired, unknown, reset, copied-across-session/boot/surface tokens fail
closed. Duplicate event IDs are refused; a distinct request is a distinct fact,
not a new independent proof of AI use. A copied token within the same session
can still be touched: the observation cannot establish who or what followed it.

`record_canary_touch` uses the existing `InteractionObserver` and Fabric
InteractionObservation: class `interaction`, surface `config_breadcrumb`, no
reaction verdict. Opaque target/package/boot/session/event refs and limitations
remain scalar metadata. It checks the emitter's environment/package binding.
The existing tamper-evident chain receives no token secret. Reported presentation
and interaction refs remain unverified source claims, not independently verified
runtime activity or causal effectiveness. No new Fabric schema is introduced.

Evidence write/validation failure returns `evidence_unavailable` and increments
`audit_failures`. The event ID stays consumed; no automatic retry or activation
follows. This deliberate bounded drop cannot be interpreted as zero activity.
The caller must project unavailable/coverage counters through its owning adapter.

## Reset, limits and safety

`reset` reuses `invalidate_all`, permanently closes this registry and returns
local invalidation bookkeeping. It cannot predate known canary observations.
A replacement registry accepts no prior token. This is not proof that a running
service/artifact was terminated, removed or reset: #31 and the existing runtime
lifecycle retain those independent checks. No secrets/checkpoint persistence is
added; on restart token validation is unavailable/fail-closed until a separately
admitted new presentation, rather than silently restoring old capabilities.

Default software caps are 128 tokens, 2,048 accepted event IDs and 600-second TTL;
constructor maxima are 4,096 tokens / 8,192 events / 3,600-second TTL. These are
bounded prototype limits, not measured hardware budgets. Invalid tokens allocate
no per-request registry state. Entries are not evicted or reactivated at capacity;
reset does not clear IDs to reopen replay. All time comes from callers, never
the wall clock. Token entropy comes from `secrets.token_urlsafe(32)` only at issue.

The example `examples/canaries/local-web-v1.json` is a reviewable preparation
profile and is not consumed by the live Compose adapter. Actual planting,
HTTP event intake, authenticated Edge decision/exposure, isolation readback and
teardown wiring remain under #31/#325/#358 in their owning repositories. No
instruction-following payload, real credential, command, model output or arbitrary
runtime template is supported. Scanner, prefetch, health-check, replay and copied
links remain alternative explanations. No AI identity, intent, belief, successful
DIVERT or permission to escalate follows from a touch.

## Verification

```sh
PYTHONPATH=src python -m pytest -q tests/test_local_canaries.py tests/test_credential_lures.py tests/test_interaction_observation.py
```

Tests cover scope/clock/expiry, copied/guessed tokens, immutable presentation,
duplicate/event/token caps, reset/restart refusal, no token echo, evidence-chain
projection, failed storage and no process/network calls. Container/CI/portability
results remain software evidence; physical isolation/engagement efficacy and
static fingerprint comparisons remain open.
