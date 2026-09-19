"""Fail a Virtual Phase-1 Lab job whose report does not show a finished run.

The lab is not a pytest run, so ``assert_executed.py`` cannot vouch for it; the
job would otherwise be green on the strength of an exit code alone. The same
rule applies here as everywhere else in this workflow: a `[x]` needs evidence
that the thing happened, and the report is that evidence. This script reads it
and refuses a run that did not complete the lifecycle it claims to prove.

It checks the report, not the container. Physical/HIL isolation is out of scope
here exactly as it is for the lab itself.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# The lab's own contract: activation, termination and reset all reached the
# evidence chain. `azazel_deception.runtime.compose` is where these names come
# from; a rename there must fail here rather than silently weaken the check.
REQUIRED_EVENTS = ("activated", "terminated", "reset_completed")


def check(report: dict) -> list[str]:
    problems: list[str] = []

    events = report.get("evidence_event_types")
    if not isinstance(events, list) or not events:
        problems.append("evidence_event_types is missing or empty")
    else:
        missing = [name for name in REQUIRED_EVENTS if name not in events]
        if missing:
            problems.append(f"evidence chain is missing {missing} (got {events})")

    if report.get("evidence_chain_intact") is not True:
        problems.append("evidence_chain_intact is not True")

    consumed = report.get("decision_consumed")
    if not isinstance(consumed, dict) or not consumed:
        problems.append("decision_consumed is missing or empty")
    else:
        unconsumed = sorted(k for k, v in consumed.items() if v is not True)
        if unconsumed:
            problems.append(f"Edge decisions not marked one-shot consumed: {unconsumed}")

    lifecycle = report.get("lifecycle")
    if not isinstance(lifecycle, dict):
        problems.append("lifecycle is missing")
    else:
        for stage in ("activate", "status", "terminate", "reset"):
            if not lifecycle.get(stage):
                problems.append(f"lifecycle.{stage} is missing or empty")

    if not report.get("environment_id"):
        problems.append("environment_id is missing — no environment was materialized")

    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("report", type=Path, help="the lab's JSON evidence report")
    args = parser.parse_args(argv)

    if not args.report.is_file():
        print(f"{args.report}: no report — the lab did not write one", file=sys.stderr)
        return 1
    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"{args.report}: unreadable ({exc})", file=sys.stderr)
        return 1
    if not isinstance(report, dict):
        print(f"{args.report}: not a report object", file=sys.stderr)
        return 1

    problems = check(report)
    if problems:
        print(f"{args.report}: " + "; ".join(problems), file=sys.stderr)
        return 1

    print(
        f"{args.report}: lifecycle completed for {report['environment_id']} "
        f"({', '.join(report['evidence_event_types'])})"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
