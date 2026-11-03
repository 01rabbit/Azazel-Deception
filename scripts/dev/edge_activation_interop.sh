#!/usr/bin/env bash
# Run the #55 Edge activation/termination interop test (tests/test_edge_activation_interop.py).
#
# Verifies the pinned Azazel-Edge commit exists in a local EDGE_REPO, extracts only its
# py/ tree into a fresh temp dir, prepares Deception's pinned dependencies and pytest in
# a temp venv, and runs ONLY that test with the extracted Edge source on the path.
# Nothing in this repository is modified: no editable install, no caches, no bytecode.
#
# Test-only: compose is mocked and the signing key is a fixed test string. No production
# caller or live authorization is involved.
#
# Usage: scripts/dev/edge_activation_interop.sh [WORKDIR]
# Env:   EDGE_REPO (required; local Azazel-Edge checkout containing EDGE_COMMIT)
#        EDGE_COMMIT (default: 4fb67850bfc134ffa25ee44693e6eb3f15ee6dff; full 40-char hex)
#        PYTHON (default python3.12)
# WORKDIR defaults to a new mktemp directory; it is kept so the log can be inspected.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PYTHON="${PYTHON:-python3.12}"
EDGE_COMMIT="${EDGE_COMMIT:-4fb67850bfc134ffa25ee44693e6eb3f15ee6dff}"

if [[ -z "${EDGE_REPO:-}" ]]; then
  echo "EDGE_REPO must be set to a local Azazel-Edge checkout containing $EDGE_COMMIT" >&2
  exit 2
fi
if [[ ! "$EDGE_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
  echo "EDGE_COMMIT must be a full 40-character lowercase commit ID" >&2
  exit 2
fi
if ! git -C "$EDGE_REPO" cat-file -e "$EDGE_COMMIT^{commit}" 2>/dev/null; then
  echo "EDGE_REPO does not contain commit $EDGE_COMMIT" >&2
  exit 2
fi

if [ "${1:-}" != "" ]; then
  mkdir -p "$1"
  work="$(cd "$1" && pwd)"
else
  work="$(mktemp -d "${TMPDIR:-/tmp}/deception55-edge-interop.XXXXXX")"
fi
log="$work/edge-activation-interop.log"
: >"$log"

# Extract only the pinned Edge py/ tree from the exact commit (never from the working tree).
mkdir -p "$work/edge"
git -C "$EDGE_REPO" archive "$EDGE_COMMIT" py | tar -x -C "$work/edge"
if [ ! -f "$work/edge/py/azazel_edge/deception_activation.py" ]; then
  echo "pinned commit does not contain py/azazel_edge/deception_activation.py" >&2
  exit 2
fi

# Deception's existing pinned dependencies (read from pyproject, not hard-coded) plus pytest.
"$PYTHON" -I -c '
import sys, tomllib
with open(sys.argv[1], "rb") as fh:
    data = tomllib.load(fh)
deps = list(data["project"]["dependencies"]) + list(data["project"]["optional-dependencies"]["dev"])
print("\n".join(deps))
' "$here/pyproject.toml" >"$work/requirements.txt"

venv="$work/venv"
uv venv --python "$PYTHON" "$venv" -q >>"$log" 2>&1
uv pip install -q --python "$venv/bin/python" -r "$work/requirements.txt" >>"$log" 2>&1

report="$work/edge-activation-junit.xml"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$here/src"
export AZAZEL_DECEPTION_EDGE_ACTIVATION_INTEROP=1
export AZAZEL_DECEPTION_EDGE_SRC="$work/edge/py"
cd "$here"
set +e
"$venv/bin/python" -B -m pytest tests/test_edge_activation_interop.py -p no:cacheprovider \
  --junitxml "$report" -rs >>"$log" 2>&1
status=$?
set -e
if [ "$status" -ne 0 ]; then
  echo "edge activation interop failed (rc=$status); log: $log" >&2
  exit "$status"
fi
# A skip is not a pass: the report must contain executed tests only.
"$venv/bin/python" -I "$here/scripts/ci/assert_executed.py" "$report" --min-tests 1 >>"$log" 2>&1
echo "edge activation interop passed: commit=$EDGE_COMMIT report=$report log=$log"
