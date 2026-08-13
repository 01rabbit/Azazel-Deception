#!/usr/bin/env python3
"""AZ-06 Virtual Phase-1 Lab: a controlled software-lifecycle simulation.

This driver exercises the full AZ-06 *software* lifecycle against a real
container runtime::

    package -> placement -> runtime preflight -> controlled activation
            -> status/evidence -> termination -> reset

It is a development/verification tool, NOT a physical isolation proof and NOT an
attacker-facing deployment. It deliberately does the following:

* passes ``live_enabled=True`` explicitly here — it never changes any default;
  ``AZAZEL_DECEPTION_LIVE`` and ``DockerComposeAdapter`` defaults stay OFF.
* uses the real :class:`GitHubAttestationPackageVerifier` by default, so package
  authenticity is genuinely verified. It fails closed if ``gh``/network/the
  attestation is unavailable rather than pretending success.
* synthesizes Edge activation/termination decisions locally. These are clearly
  synthetic and carry no real Edge authority.
* the ``--simulated-verification`` escape hatch (an in-lab accept function) lives
  ONLY in this dev script and is never importable by the shippable package, so
  test-only behavior cannot leak into a production code path. It prints a loud
  warning and must be requested explicitly.

What this proves: the deterministic software lifecycle, gate ordering, evidence
emission, one-shot decision consumption, and deterministic reset on a real
container using the digest-pinned reference image on an internal-only network
with no published host ports.

What this does NOT prove: physical NIC/VLAN isolation, protected-network route
denial, host firewall behavior, or any real-hardware property. Those remain HIL
gates.
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from azazel_deception.capabilities import detect_host_capabilities  # noqa: E402
from azazel_deception.package import load_package, parse_package  # noqa: E402
from azazel_deception.planner import build_placement_plan  # noqa: E402
from azazel_deception.runtime.compose import (  # noqa: E402
    DockerComposeAdapter,
    RuntimeGateError,
)
from azazel_deception.runtime.transport import (  # noqa: E402
    HmacDecisionAuthenticator,
    sign_decision,
)
from azazel_deception.runtime.verifier import (  # noqa: E402
    GitHubAttestationPackageVerifier,
    OciAttachedSbomVerifier,
)

DEFAULT_PACKAGE = ROOT / "examples/packages/municipal-linux-v1/package.yaml"
DEFAULT_COMPOSE = ROOT / "runtime/compose/reference-linux.compose.yaml"

ACTIVATION_DECISION_ID = "az06-lab-activation"
TERMINATION_DECISION_ID = "az06-lab-termination"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _simulated_verifier(_package) -> bool:
    """Dev-only accept function. NEVER a default; NEVER exported to the package."""

    return True


def build_activation_decision(
    raw_package: dict[str, Any],
    placement: dict[str, Any],
    *,
    decision_id: str = ACTIVATION_DECISION_ID,
) -> dict[str, Any]:
    now = _now()
    return {
        "schema_version": "environment-activation-decision/v0.1",
        "decision_id": decision_id,
        "decision_authority": "azazel-edge",
        "status": "accepted",
        "package_id": raw_package["package_id"],
        "package_digest": raw_package["package_digest"],
        "target_node_id": placement["node_id"],
        "selected_tier": placement["selected_tier"],
        "budget": {
            "cpu_cores": 2,
            "memory_mb": 1024,
            "storage_mb": 2048,
            "max_connections": 100,
            "max_duration_seconds": 300,
            "bandwidth_kbps": 5000,
        },
        "safety": {
            "outbound_allowed": False,
            "production_access": False,
            "privileged_containers": False,
            "host_network": False,
            "runtime_socket_exposed_to_decoys": False,
            "edge_control_access_from_decoys": False,
        },
        "effective_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=5)).isoformat(),
        "evidence_refs": [],
        "reason_codes": ["virtual-phase1-lab"],
    }


def build_termination_decision(
    environment_id: str,
    *,
    decision_id: str = TERMINATION_DECISION_ID,
) -> dict[str, Any]:
    now = _now()
    return {
        "schema_version": "environment-termination-decision/v0.1",
        "decision_id": decision_id,
        "decision_authority": "azazel-edge",
        "environment_id": environment_id,
        "reason": "virtual-phase1-lab-teardown",
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=5)).isoformat(),
        "evidence_refs": [],
    }


def run_virtual_lab(
    adapter: DockerComposeAdapter,
    raw_package: dict[str, Any],
    host_capabilities: dict[str, Any],
    *,
    run_id: str = "fixed",
    tier: str = "lite",
    decision_key: str | None = None,
) -> dict[str, Any]:
    """Drive the full software lifecycle and return a structured evidence report.

    ``run_id`` makes each run independent: it suffixes the environment and Edge
    decision IDs, so the one-shot decision ledger stays honest per run while the
    lab remains re-runnable against a persistent state root.

    When ``decision_key`` is set, the synthetic Edge decisions are HMAC-signed so
    the adapter's decision authenticator (which must share the key) exercises the
    authenticated-transport gate.

    Raises ``RuntimeGateError`` (fail-closed) if any authority/isolation/supply
    -chain gate rejects the run.
    """

    environment_id = f"az06-lab-env-{run_id}"
    activation_id = f"{ACTIVATION_DECISION_ID}-{run_id}"
    termination_id = f"{TERMINATION_DECISION_ID}-{run_id}"

    def _maybe_sign(decision: dict[str, Any]) -> dict[str, Any]:
        return sign_decision(decision, decision_key) if decision_key else decision

    package = parse_package(raw_package)
    placement = build_placement_plan(
        raw_package,
        host_capabilities,
        requested_tier=tier,
        edge_decision_id=activation_id,
    )

    activation = _maybe_sign(
        build_activation_decision(raw_package, placement, decision_id=activation_id)
    )
    activate_result = adapter.activate_environment(
        environment_id, raw_package, placement, activation
    )
    if activate_result.get("status") != "active":
        raise RuntimeGateError(
            f"activation did not reach active state: {activate_result}"
        )

    status = adapter.collect_status(environment_id)

    termination = _maybe_sign(
        build_termination_decision(environment_id, decision_id=termination_id)
    )
    terminate_result = adapter.terminate_environment(environment_id, termination)
    reset_result = adapter.reset_environment(environment_id)
    evidence = adapter.export_evidence(environment_id)

    event_types = [event.get("event_type") for event in evidence]
    for required in ("activated", "terminated", "reset_completed"):
        if required not in event_types:
            raise RuntimeGateError(
                f"expected lifecycle event missing from evidence: {required} "
                f"(got {event_types})"
            )

    return {
        "environment_id": environment_id,
        "package_id": package.package_id,
        "package_digest": package.package_digest,
        "node_id": placement["node_id"],
        "architecture": placement["architecture"],
        "selected_tier": placement["selected_tier"],
        "component_ids": placement["component_ids"],
        "lifecycle": {
            "activate": activate_result,
            "status": status,
            "terminate": terminate_result,
            "reset": reset_result,
        },
        "evidence_event_types": event_types,
        "decision_consumed": {
            activation_id: adapter.state.decision_consumed(activation_id),
            termination_id: adapter.state.decision_consumed(termination_id),
        },
        "isolation_note": (
            "software lifecycle on internal-only network with no published host "
            "ports; NOT a physical isolation proof"
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="virtual-phase1-lab",
        description="Controlled AZ-06 Phase-1 software lifecycle simulation.",
    )
    parser.add_argument("--package", default=str(DEFAULT_PACKAGE))
    parser.add_argument("--compose", default=str(DEFAULT_COMPOSE))
    parser.add_argument("--state-root", default=str(ROOT / "runtime/state/lab"))
    parser.add_argument(
        "--run-id",
        default=uuid.uuid4().hex[:12],
        help="unique run token; keeps the one-shot decision ledger honest per run",
    )
    parser.add_argument("--tier", default="lite")
    parser.add_argument("--output", help="write the evidence report JSON here")
    parser.add_argument(
        "--simulated-verification",
        action="store_true",
        help=(
            "DEV ONLY: skip real GitHub attestation verification with an in-lab "
            "accept function. Never use outside offline development."
        ),
    )
    parser.add_argument(
        "--sbom-verify",
        action="store_true",
        help="also verify the OCI-attached SPDX SBOM of every verified image",
    )
    parser.add_argument(
        "--authenticate",
        action="store_true",
        help=(
            "exercise the authenticated Edge-transport gate: HMAC-sign the "
            "synthetic decisions with a per-run key the adapter shares"
        ),
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help=(
            "strict live posture: require the SBOM verifier and decision "
            "authenticator to be configured (combine with --sbom-verify and "
            "--authenticate, or the run fails closed)"
        ),
    )
    args = parser.parse_args(argv)

    raw_package = load_package(args.package)
    host = detect_host_capabilities()

    if args.simulated_verification:
        sys.stderr.write(
            "[az06][WARNING] --simulated-verification: package authenticity is "
            "NOT verified. Dev/offline use only.\n"
        )
        verifier = _simulated_verifier
    else:
        verifier = GitHubAttestationPackageVerifier()

    decision_key = uuid.uuid4().hex if args.authenticate else None
    adapter = DockerComposeAdapter(
        args.compose,
        args.state_root,
        live_enabled=True,  # explicit, lab-scoped; no default is changed
        package_verifier=verifier,
        sbom_verifier=OciAttachedSbomVerifier() if args.sbom_verify else None,
        decision_authenticator=(
            HmacDecisionAuthenticator(decision_key) if decision_key else None
        ),
        require_sbom_verification=args.strict,
        require_authenticated_decisions=args.strict,
    )

    environment_id = f"az06-lab-env-{args.run_id}"
    try:
        report = run_virtual_lab(
            adapter,
            raw_package,
            host,
            run_id=args.run_id,
            tier=args.tier,
            decision_key=decision_key,
        )
    except RuntimeGateError as exc:
        # Fail-closed: a rejected gate is the correct, expected outcome to report.
        sys.stderr.write(f"[az06] virtual lab fail-closed: {exc}\n")
        # Best-effort cleanup so a rejected run leaves no lingering container.
        try:
            cleanup = build_termination_decision(
                environment_id, decision_id=f"{TERMINATION_DECISION_ID}-cleanup-{args.run_id}"
            )
            if decision_key:
                cleanup = sign_decision(cleanup, decision_key)
            adapter.terminate_environment(environment_id, cleanup)
            adapter.reset_environment(environment_id)
        except Exception:
            pass
        return 2

    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(rendered + "\n", encoding="utf-8")
        print(str(out))
    else:
        print(rendered)
    print("[az06] virtual Phase-1 software lifecycle completed and reset", file=sys.stderr)
    print(
        "[az06] note: this proves software lifecycle only, not physical/HIL isolation",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
