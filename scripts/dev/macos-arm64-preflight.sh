#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This preflight is intended for macOS." >&2
  exit 2
fi

case "$(uname -m)" in
  arm64) ;;
  *) echo "Apple Silicon arm64 is required; detected $(uname -m)" >&2; exit 2 ;;
esac

command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 2; }
command -v docker >/dev/null 2>&1 || {
  echo "Docker CLI is required. Start Docker Desktop/compatible runtime, then retry." >&2
  exit 2
}

docker info >/dev/null || {
  echo "Docker daemon is not reachable. Start Docker Desktop/compatible runtime." >&2
  exit 2
}
docker compose version >/dev/null

python3 - <<'PY'
import sys
if sys.version_info < (3, 10):
    raise SystemExit(f"Python >=3.10 required; found {sys.version.split()[0]}")
PY

if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi

. .venv/bin/activate
python -m pip install --upgrade pip
pip install -e '.[dev]'

pytest

capabilities_json="$(python -m azazel_deception capabilities)"
printf '%s\n' "$capabilities_json"
CAPABILITIES_JSON="$capabilities_json" python - <<'PY'
import json
import os
payload = json.loads(os.environ["CAPABILITIES_JSON"])
assert payload["architecture"] == "arm64", payload
assert payload["memory_mb"] > 1024, payload
assert payload["runtime_adapters"]["docker_compose"] is True, payload
assert payload["kvm_available"] is False, payload
print("[az06] macOS ARM64 capability validation passed")
PY

python -m azazel_deception validate examples/packages/municipal-linux-v1/package.yaml
python -m azazel_deception plan examples/packages/municipal-linux-v1/package.yaml --tier lite >/dev/null

export AZ06_EVIDENCE_OUT="artifacts/portability/macos-arm64-local.json"
bash scripts/dev/reference-compose-smoke.sh

echo "[az06] Apple Silicon development preflight passed"
echo "[az06] evidence: $AZ06_EVIDENCE_OUT"
echo "[az06] note: this proves local ARM64 development/runtime semantics, not Linux HIL isolation certification"
