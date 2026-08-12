from __future__ import annotations

import argparse
import json
import sys

from .capabilities import detect_host_capabilities
from .package import PackageValidationError, load_package, validate_package
from .planner import build_placement_plan


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="azazel-deception")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("capabilities", help="print descriptive host capabilities")
    validate = sub.add_parser("validate", help="validate a bootstrap deception package")
    validate.add_argument("package")
    plan = sub.add_parser("plan", help="create a deterministic dry-run placement plan")
    plan.add_argument("package")
    plan.add_argument("--tier", choices=["lite", "standard", "heavy", "cluster"])
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "capabilities":
        print(json.dumps(detect_host_capabilities(), indent=2, sort_keys=True))
        return 0

    package = load_package(args.package)
    if args.command == "validate":
        errors = validate_package(package)
        print(json.dumps({"valid": not errors, "errors": errors}, indent=2, sort_keys=True))
        return 0 if not errors else 2

    try:
        plan = build_placement_plan(package, detect_host_capabilities(), args.tier)
    except PackageValidationError as exc:
        print(json.dumps({"planned": False, "error": str(exc)}, indent=2), file=sys.stderr)
        return 2
    print(json.dumps(plan, indent=2, sort_keys=True))
    return 0
