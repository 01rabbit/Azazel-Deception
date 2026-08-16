#!/usr/bin/env python3
"""Standalone launcher for the AZ-06 shadow/replay server (dev only).

Serves ``azazel_deception.runtime.shadow_server.ShadowReplayService`` over HTTP
on localhost so another system (e.g. Azazel-Edge) can drive the strictly
non-executing shadow/replay + heartbeat/reconcile path against a real AZ-06
node. This starts NO container and enforces NOTHING — the service pins
``live_enabled=False``.

Example:

    python scripts/dev/serve_shadow.py \\
        --host 127.0.0.1 --port 8071 \\
        --key dev-shared-key --edge-id edge-1 --node-id az06-1

The shared ``--key`` (HMAC transport secret) and the allow-listed ``--edge-id``
must match what the Edge client uses. Prints the base URL and blocks until
Ctrl-C.
"""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

from azazel_deception.runtime.shadow_server import (
    ShadowReplayHTTPServer,
    ShadowReplayService,
)

REPO = Path(__file__).resolve().parents[2]
DEFAULT_PACKAGE = REPO / "examples/packages/municipal-linux-v1/package.yaml"
DEFAULT_COMPOSE = REPO / "runtime/compose/reference-linux.compose.yaml"

# A deterministic, docker-capable capability snapshot so the descriptive plan
# builds identically regardless of the dev host (matches the test fixtures).
_SYNTHETIC_CAPS = {
    "node_id": "az06-shadow-dev",
    "architecture": "amd64",
    "cpu_cores": 4,
    "memory_mb": 8192,
    "storage_free_mb": 65536,
    "runtime_adapters": {"docker_compose": True},
    "kvm_available": False,
    "gpu_available": False,
}


def _synthetic_capabilities() -> dict:
    from azazel_fabric.deception_contracts import HostCapabilities

    return HostCapabilities.model_validate(_SYNTHETIC_CAPS).model_dump(mode="json")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Serve the AZ-06 shadow/replay API (dev)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8071)
    parser.add_argument("--key", required=True, help="shared HMAC transport key")
    parser.add_argument("--edge-id", required=True, help="allow-listed Edge node id")
    parser.add_argument("--node-id", default="az06-shadow-dev", help="this AZ-06 node id")
    parser.add_argument("--package", type=Path, default=DEFAULT_PACKAGE)
    parser.add_argument("--compose", type=Path, default=DEFAULT_COMPOSE)
    parser.add_argument("--state-root", type=Path, default=None)
    parser.add_argument(
        "--real-capabilities",
        action="store_true",
        help="detect host capabilities instead of the synthetic docker-capable snapshot",
    )
    args = parser.parse_args(argv)

    state_root = args.state_root or Path(tempfile.mkdtemp(prefix="az06-shadow-"))
    service = ShadowReplayService(
        node_id=args.node_id,
        transport_key=args.key,
        allowed_edge_ids=[args.edge_id],
        package_path=args.package,
        state_root=state_root,
        compose_file=args.compose,
        capability_provider=None if args.real_capabilities else _synthetic_capabilities,
    )
    server = ShadowReplayHTTPServer(service, host=args.host, port=args.port)
    server.start()
    host, port = server.address
    print(f"[az06-shadow] serving on http://{host}:{port}  node_id={args.node_id} "
          f"edge_allowlist=[{args.edge_id}] state_root={state_root}", flush=True)
    print("[az06-shadow] live_execution=disabled (shadow/replay only). Ctrl-C to stop.", flush=True)
    try:
        import time
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\n[az06-shadow] stopping", flush=True)
    finally:
        server.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
