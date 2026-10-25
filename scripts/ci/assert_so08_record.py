"""Fail an SO-08 virtual-lab job whose record does not show an executed run.

The harness's exit status already refuses green for a run it could not do;
this reads the record it wrote, independently, the way
``assert_lab_report.py`` reads the Phase-1 lab report. It accepts only a
``virtual-lab-regression`` record that executed, validates, carries
``gate: false``, and whose detection half held on every sample. It never
accepts ``verdict: "pass"`` — a virtual-lab record cannot pass SO-08, and the
validator refuses one that claims to.

This is a regression signal. It is not, and cannot become, HIL evidence.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from azazel_deception.runtime.so08_record import (  # noqa: E402
    CLASS_VIRTUAL_LAB,
    validate_record,
)


def check(record: dict) -> list[str]:
    problems = list(validate_record(record))
    if record.get("class") != CLASS_VIRTUAL_LAB:
        problems.append(f"class is {record.get('class')!r}, expected {CLASS_VIRTUAL_LAB!r}")
    if record.get("executed") is not True:
        problems.append(f"run did not execute: {record.get('not_executed_reason')!r}")
    parts = {p.get("name"): p for p in record.get("parts") or [] if isinstance(p, dict)}
    if (parts.get("detection") or {}).get("verdict") != "pass":
        problems.append("detection half did not hold on every sample")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("record", type=Path)
    args = parser.parse_args(argv)
    try:
        record = json.loads(args.record.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"FAIL: cannot read {args.record}: {exc}", file=sys.stderr)
        return 1
    problems = check(record)
    if problems:
        for problem in problems:
            print(f"FAIL: {problem}", file=sys.stderr)
        return 1
    print("OK: SO-08 virtual-lab detection half held (verdict "
          f"{record['verdict']!r}, gate false — not HIL evidence)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
