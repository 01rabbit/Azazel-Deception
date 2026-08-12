from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .capabilities import detect_host_capabilities
from .package import (
    PackageValidationError,
    calculate_package_digest,
    load_package,
    package_signing_bytes,
    validate_package,
)
from .planner import build_placement_plan


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="azazel-deception")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("capabilities", help="print descriptive host capabilities")

    validate = sub.add_parser("validate", help="validate a canonical or bootstrap deception package")
    validate.add_argument("package")

    digest = sub.add_parser("package-digest", help="calculate the canonical semantic package digest")
    digest.add_argument("package")

    signing = sub.add_parser(
        "package-signing-payload",
        help="emit the detached canonical bytes covered by package attestation",
    )
    signing.add_argument("package")
    signing.add_argument("--output", required=True)

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

    if args.command == "package-digest":
        try:
            digest = calculate_package_digest(package)
        except PackageValidationError as exc:
            print(json.dumps({"calculated": False, "error": str(exc)}, indent=2), file=sys.stderr)
            return 2
        print(digest)
        return 0

    if args.command == "package-signing-payload":
        try:
            content = package_signing_bytes(package)
        except PackageValidationError as exc:
            print(json.dumps({"created": False, "error": str(exc)}, indent=2), file=sys.stderr)
            return 2
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(content)
        print(str(output))
        return 0

    try:
        plan = build_placement_plan(package, detect_host_capabilities(), args.tier)
    except PackageValidationError as exc:
        print(json.dumps({"planned": False, "error": str(exc)}, indent=2), file=sys.stderr)
        return 2
    print(json.dumps(plan, indent=2, sort_keys=True))
    return 0
