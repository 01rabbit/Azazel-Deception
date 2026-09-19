"""Fail a CI job whose tests did not actually run.

A gate in ``docs/live-gate-checklist.md`` may be `[x]` only when a named green
workflow run *executed* its evidence. A pytest run that skipped everything also
exits 0, so "the job is green" does not by itself mean "the evidence ran" —
that gap is precisely what Azazel-Deception#38 found behind three `[x]` boxes
(an opt-in suite no workflow enabled, and a cross-repository test that
``importorskip``ed away in every recorded run).

This script closes the gap by reading the JUnit XML a job produced and refusing
a result that is green for the wrong reason: no tests, or any skip, or any
error. It makes no claim about what the tests assert — only that they ran.
"""

from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def _totals(report: Path) -> dict[str, int]:
    root = ET.parse(report).getroot()
    # pytest writes <testsuites><testsuite .../></testsuites>; older/other
    # writers emit a bare <testsuite>. Accept both rather than guessing.
    suites = root.findall("testsuite") if root.tag == "testsuites" else [root]
    if not suites:
        raise SystemExit(f"{report}: no <testsuite> element — the run produced no report")
    totals = {"tests": 0, "skipped": 0, "failures": 0, "errors": 0}
    for suite in suites:
        for key in totals:
            totals[key] += int(suite.get(key, 0))
    return totals


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("report", type=Path, help="JUnit XML written by pytest --junitxml")
    parser.add_argument(
        "--min-tests",
        type=int,
        default=1,
        help="fail when fewer than this many tests ran (default: 1)",
    )
    parser.add_argument(
        "--allow-skips",
        action="store_true",
        help="permit skipped tests; only use where a skip is a real, stated condition",
    )
    args = parser.parse_args(argv)

    if not args.report.is_file():
        print(f"{args.report}: no report — pytest did not run", file=sys.stderr)
        return 1

    totals = _totals(args.report)
    problems: list[str] = []
    if totals["tests"] < args.min_tests:
        problems.append(f"ran {totals['tests']} tests, expected at least {args.min_tests}")
    if totals["skipped"] and not args.allow_skips:
        problems.append(
            f"{totals['skipped']} skipped — a skipped test is not executed evidence"
        )
    if totals["failures"] or totals["errors"]:
        problems.append(f"{totals['failures']} failures, {totals['errors']} errors")

    if problems:
        print(f"{args.report}: " + "; ".join(problems), file=sys.stderr)
        return 1

    print(
        f"{args.report}: {totals['tests']} tests executed, "
        f"{totals['skipped']} skipped, {totals['failures']} failed"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
