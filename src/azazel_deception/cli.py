from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from .capabilities import detect_host_capabilities
from .package import (
    PackageValidationError,
    calculate_package_digest,
    canonical_package_payload,
    canonical_package_payload_bytes,
    load_package,
    seal_package_digest,
    validate_package,
)
from .planner import build_placement_plan


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="azazel-deception")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("capabilities", help="print descriptive host capabilities")

    validate = sub.add_parser("validate", help="validate a canonical or bootstrap deception package")
    validate.add_argument("package")

    # Canonical semantic content digest (always computed from the normalized model).
    for name in ("digest", "package-digest"):
        digest = sub.add_parser(name, help="calculate the canonical semantic package digest")
        digest.add_argument("package")

    # Canonical semantic payload covered by package_digest (digest + signature_ref excluded).
    canonical = sub.add_parser(
        "canonical-payload",
        help="emit the canonical semantic payload bound by package_digest",
    )
    canonical.add_argument("package")
    canonical.add_argument(
        "--output",
        help="write canonical detached bytes here instead of pretty JSON on stdout",
    )

    # Authoring-time seal: stamp the canonical digest. Never rewrites the source in place.
    seal = sub.add_parser(
        "seal",
        help="compute and stamp the canonical package_digest (emits a sealed package)",
    )
    seal.add_argument("package")
    seal.add_argument(
        "--output",
        help="write the sealed package here (default: stdout); source is never modified in place",
    )

    for name in ("canonical-payload-bytes", "package-signing-payload"):
        signing = sub.add_parser(
            name,
            help="emit the detached canonical bytes covered by package attestation",
        )
        signing.add_argument("package")
        signing.add_argument("--output", required=True)

    plan = sub.add_parser("plan", help="create a deterministic dry-run placement plan")
    plan.add_argument("package")
    plan.add_argument("--tier", choices=["lite", "standard", "heavy", "cluster"])

    status = sub.add_parser(
        "runtime-status",
        help="print the descriptive operator status/health surface (read-only)",
    )
    status.add_argument("--state-root", required=True)
    status.add_argument(
        "--compose",
        default="runtime/compose/reference-linux.compose.yaml",
    )

    reconcile = sub.add_parser(
        "runtime-reconcile",
        help="report divergence between local state and Edge's active set (read-only)",
    )
    reconcile.add_argument("--state-root", required=True)
    reconcile.add_argument(
        "--edge-active",
        default="",
        help="comma-separated environment IDs Edge considers active",
    )
    reconcile.add_argument(
        "--compose",
        default="runtime/compose/reference-linux.compose.yaml",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "capabilities":
        print(json.dumps(detect_host_capabilities(), indent=2, sort_keys=True))
        return 0

    if args.command == "runtime-status":
        # Imported lazily so package-only CLI use does not require the runtime.
        from .runtime.compose import DockerComposeAdapter

        adapter = DockerComposeAdapter(args.compose, args.state_root, live_enabled=False)
        print(json.dumps(adapter.health(), indent=2, sort_keys=True))
        return 0

    if args.command == "runtime-reconcile":
        from .runtime.compose import DockerComposeAdapter

        adapter = DockerComposeAdapter(args.compose, args.state_root, live_enabled=False)
        edge_active = [item for item in args.edge_active.split(",") if item.strip()]
        print(json.dumps(adapter.reconcile_with_edge(edge_active), indent=2, sort_keys=True))
        return 0

    package = load_package(args.package)
    if args.command == "validate":
        errors = validate_package(package)
        print(json.dumps({"valid": not errors, "errors": errors}, indent=2, sort_keys=True))
        return 0 if not errors else 2

    if args.command in {"digest", "package-digest"}:
        try:
            digest = calculate_package_digest(package)
        except PackageValidationError as exc:
            print(json.dumps({"calculated": False, "error": str(exc)}, indent=2), file=sys.stderr)
            return 2
        print(digest)
        return 0

    if args.command == "canonical-payload":
        try:
            if args.output:
                content = canonical_package_payload_bytes(package)
            else:
                payload = canonical_package_payload(package)
        except PackageValidationError as exc:
            print(json.dumps({"created": False, "error": str(exc)}, indent=2), file=sys.stderr)
            return 2
        if args.output:
            output = Path(args.output)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(content)
            print(str(output))
        else:
            print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))
        return 0

    if args.command == "seal":
        try:
            sealed = seal_package_digest(package)
        except PackageValidationError as exc:
            print(json.dumps({"sealed": False, "error": str(exc)}, indent=2), file=sys.stderr)
            return 2
        rendered = yaml.safe_dump(sealed, sort_keys=False, allow_unicode=True)
        if args.output:
            output = Path(args.output)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(rendered, encoding="utf-8")
            print(str(output))
        else:
            sys.stdout.write(rendered)
        return 0

    if args.command in {"canonical-payload-bytes", "package-signing-payload"}:
        try:
            content = canonical_package_payload_bytes(package)
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
