#!/usr/bin/env python3
"""AZ-06 dev/relay helper: push exported interaction observations somewhere.

This is deliberately **not** part of the shippable ``azazel_deception``
package. In production, Azazel-Edge is the mediator between AZ-06 and
Azazel-Knowledge: Edge reads (or is pushed) AZ-06's evidence-chain facts and
relays them onward under its own authority. AZ-06 itself never talks to
Knowledge and never decides deception effectiveness.

For the *virtual, localhost* Deception -> Edge -> Knowledge dev loop,
though, something has to physically move the exported observation dicts
across a socket so the harness can exercise the wire without a real Edge
deployed. That "something" is this script: a dumb HTTP POST of already
-canonical observation dicts (as produced by
``azazel_deception.runtime.observation_export.export_observations`` /
``observations_since``) to a Knowledge-style ingest URL, using only the
stdlib (``urllib``) so it adds no dependency to the package or the lab.

``push_observations`` is intentionally minimal:

* it does not add, remove, or reinterpret any field -- the dicts it sends
  are exactly what the caller passed in;
* it never adds a belief/effectiveness field (nothing here even has the
  vocabulary for one -- callers pass Fabric-shaped ``InteractionObservation``
  dicts, and this function does not touch their contents at all);
* it is a no-op (returns ``None``, makes no network call) when given an
  empty observation list, so an idle poll of the incremental cursor never
  produces a spurious empty request.

Being a script under ``scripts/dev/`` (like ``virtual_phase1_lab.py``) rather
than a module under ``src/azazel_deception/`` keeps this v0.6.0's stance that
AZ-06 exports facts but does not itself perform network relay -- the same
reasoning that keeps ``_simulated_verifier`` out of the shippable
``azazel_deception.runtime.verifier`` module. If a future wave decides AZ-06
should ship a real relay client, that is a deliberate package-level decision
for the orchestrator to make, not a side effect of adding dev tooling here.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def push_observations(
    observations: list[dict[str, Any]],
    url: str,
    *,
    token: str | None = None,
    timeout: float = 10.0,
) -> int | None:
    """POST a batch of observation dicts to a Knowledge-style ingest URL.

    Sends the exact list of dicts given, JSON-encoded as
    ``{"observations": [...]}``, in one POST. A dumb transport only: it does
    not validate, filter, reorder, or annotate the payload, and it does not
    interpret attacker content -- that is the caller's job (typically
    ``export_observations``/``observations_since``, which already produced
    canonical, Fabric-validated dicts).

    Returns the HTTP status code, or ``None`` (no request made) if
    ``observations`` is empty. Raises ``urllib.error.URLError`` /
    ``urllib.error.HTTPError`` on transport failure -- callers decide
    whether/how to retry; this helper does not swallow failures.
    """

    if not observations:
        return None

    payload = json.dumps({"observations": observations}).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = urllib.request.Request(
        url, data=payload, headers=headers, method="POST"
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return int(response.status)


def main(argv: list[str] | None = None) -> int:
    from azazel_deception.runtime.compose import DockerComposeAdapter

    parser = argparse.ArgumentParser(
        prog="push-observations",
        description=(
            "DEV ONLY: export one environment's recorded interaction "
            "observations and POST them to a Knowledge-style ingest URL. "
            "In production, Azazel-Edge mediates this relay; this script "
            "exists for the virtual localhost Deception->Edge->Knowledge "
            "dev loop only."
        ),
    )
    parser.add_argument("--compose", required=True, help="compose file the adapter is bound to")
    parser.add_argument("--state-root", required=True, help="runtime state root")
    parser.add_argument("--environment-id", required=True)
    parser.add_argument("--url", required=True, help="Knowledge-style ingest URL")
    parser.add_argument("--token", default=None, help="optional bearer token")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument(
        "--since",
        default=None,
        help="only push observations after this observation_id (incremental cursor)",
    )
    args = parser.parse_args(argv)

    adapter = DockerComposeAdapter(args.compose, args.state_root, live_enabled=False)
    if args.since:
        from azazel_deception.runtime.observation_export import observations_since

        observations = observations_since(adapter.state, args.environment_id, args.since)
    else:
        observations = adapter.export_observations(args.environment_id)

    if not observations:
        print("[az06] no observations to push", file=sys.stderr)
        return 0

    try:
        status = push_observations(
            observations, args.url, token=args.token, timeout=args.timeout
        )
    except urllib.error.URLError as exc:
        sys.stderr.write(f"[az06] push failed: {exc}\n")
        return 1

    print(f"[az06] pushed {len(observations)} observation(s), status={status}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
