#!/usr/bin/env bash
# Run the #55 real-consumer interop suite (tests/test_mio_feedback_interop.py).
#
# Prepares, in a work directory, a venv with Azazel-MIO (pinned commit) plus this
# repository, and a separate venv with Azazel-Knowledge[api] (pinned commit; its own
# Fabric pin is left as-is). The test process starts and stops Knowledge's uvicorn
# on a free 127.0.0.1 port itself. Then asserts the JUnit report has no skip.
#
# Usage: scripts/dev/mio_feedback_interop.sh [WORKDIR]
# Env:   MIO_REPO KNOWLEDGE_REPO (default: sibling of this checkout, else one level up)
#        MIO_COMMIT (full public pin)  KNOWLEDGE_COMMIT (required, local full commit)
#        PYTHON (python3.12)  AZAZEL_DECEPTION_MIO_OBJECTIVE_INTEROP (default 1; 0 skips it)
# Provide the exact Knowledge commit locally; its full ID and run output stay in WORKDIR/interop.log, never stdout.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work="${1:-$here/../interop}"
mkdir -p "$work"; work="$(cd "$work" && pwd)"
find_repo() { # name: sibling of this checkout first, then one level further up
  for candidate in "$here/../$1" "$here/../../$1"; do
    if [ -d "$candidate/.git" ] || [ -f "$candidate/.git" ]; then (cd "$candidate" && pwd); return; fi
  done
  echo "cannot find $1 next to this checkout; set ${2}" >&2; exit 2
}
MIO_REPO="${MIO_REPO:-$(find_repo Azazel-MIO MIO_REPO)}"
KNOWLEDGE_REPO="${KNOWLEDGE_REPO:-$(find_repo Azazel-Knowledge KNOWLEDGE_REPO)}"
MIO_COMMIT="${MIO_COMMIT:-4d92b4451a3bf1ec44eb7215ebadb0fd05879c1d}"
if [[ -z "${KNOWLEDGE_COMMIT:-}" ]]; then
  echo "KNOWLEDGE_COMMIT must be set to a full local commit ID" >&2
  exit 2
fi
for commit in "$MIO_COMMIT" "$KNOWLEDGE_COMMIT"; do
  if [[ ! "$commit" =~ ^[0-9a-f]{40}$ ]]; then
    echo "MIO_COMMIT and KNOWLEDGE_COMMIT must be full 40-character commit IDs" >&2
    exit 2
  fi
done
PYTHON="${PYTHON:-python3.12}"
check_commit() {
  name="$1"; repo="$2"; commit="$3"
  if ! git -C "$repo" cat-file -e "$commit^{commit}" 2>/dev/null; then
    echo "$name must contain the requested commit object" >&2
    exit 2
  fi
}
check_commit MIO_COMMIT "$MIO_REPO" "$MIO_COMMIT"
check_commit KNOWLEDGE_COMMIT "$KNOWLEDGE_REPO" "$KNOWLEDGE_COMMIT"
log="$work/interop.log"
python_identity="$($PYTHON -c 'import sys; print(sys.version + " | " + sys.executable)')"
venv_key="$($PYTHON -c 'import hashlib,sys; print(hashlib.sha256("\0".join(sys.argv[1:]).encode()).hexdigest())' "$MIO_COMMIT" "$KNOWLEDGE_COMMIT" "$python_identity")"
mio_venv="$work/venv-mio-$venv_key"
knowledge_venv="$work/venv-knowledge-$venv_key"
run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
{
  printf '\nrun_id=%s\n' "$run_id"
  printf 'deception_head=%s\n' "$(git -C "$here" rev-parse HEAD)"
  printf 'deception_tree=%s\n' "$(git -C "$here" rev-parse 'HEAD^{tree}')"
  printf 'mio_commit=%s\n' "$MIO_COMMIT"
  printf 'knowledge_commit=%s\n' "$KNOWLEDGE_COMMIT"
  printf 'python_identity=%s\n' "$python_identity"
} >>"$log"

extract() { # repo commit dest
  if [ ! -e "$3/.extracted-$2" ]; then
    rm -rf "$3"; mkdir -p "$3"
    git -C "$1" archive "$2" | tar -x -C "$3"
    touch "$3/.extracted-$2"
  fi
}
extract "$MIO_REPO" "$MIO_COMMIT" "$work/mio"
extract "$KNOWLEDGE_REPO" "$KNOWLEDGE_COMMIT" "$work/knowledge"

if [ ! -x "$mio_venv/bin/python" ]; then
  uv venv --python "$PYTHON" "$mio_venv" -q
  uv pip install -q --python "$mio_venv/bin/python" -e "$work/mio" -e "$here" pytest
fi
if [ ! -x "$knowledge_venv/bin/python" ]; then
  uv venv --python "$PYTHON" "$knowledge_venv" -q
  uv pip install -q --python "$knowledge_venv/bin/python" -e "$work/knowledge[api]" >>"$log" 2>&1
fi

cleanup() { # no stray uvicorn from this work dir may outlive the run
  pkill -f "$knowledge_venv/bin/python -m uvicorn" 2>/dev/null || true
}
trap cleanup EXIT

report="$work/interop-junit.xml"
rm -f "$report"
cd "$here"
export AZAZEL_DECEPTION_MIO_INTEROP=1
export AZAZEL_DECEPTION_KNOWLEDGE_PYTHON="$knowledge_venv/bin/python"
export AZAZEL_DECEPTION_KNOWLEDGE_SRC="$work/knowledge"
pytest_args=(tests/test_mio_feedback_interop.py -p no:cacheprovider)
# The runner runs the MIO objective producer conformance test by default. The
# ordinary pytest suite (run without this runner) still skips it unless opted in.
export AZAZEL_DECEPTION_MIO_OBJECTIVE_INTEROP="${AZAZEL_DECEPTION_MIO_OBJECTIVE_INTEROP:-1}"
case "$AZAZEL_DECEPTION_MIO_OBJECTIVE_INTEROP" in
  1) expected_tests=15 ;;
  0) expected_tests=14; pytest_args+=(-k 'not test_mio_pinned_objective_producer') ;;
  *) echo "AZAZEL_DECEPTION_MIO_OBJECTIVE_INTEROP must be 0 or 1, got '$AZAZEL_DECEPTION_MIO_OBJECTIVE_INTEROP'" >&2; exit 2 ;;
esac
if "$mio_venv/bin/python" -m pytest "${pytest_args[@]}" \
  --junitxml "$report" -rs >>"$log" 2>&1; then
  status=0
else
  status=$?
fi
[ "$status" -eq 0 ] || { echo "interop pytest failed (rc=$status); log: $log" >&2; exit "$status"; }
if "$mio_venv/bin/python" scripts/ci/assert_executed.py "$report" --min-tests "$expected_tests" >>"$log" 2>&1; then
  :
else
  status=$?
  echo "interop: skip/error check failed (rc=$status); log: $log" >&2
  exit "$status"
fi
# assert_executed.py only enforces a minimum; the runner requires the exact count.
if ran="$($mio_venv/bin/python -I -c '
import sys, xml.etree.ElementTree as ET
root = ET.parse(sys.argv[1]).getroot()
suites = root.findall("testsuite") if root.tag == "testsuites" else [root]
ran = sum(int(s.get("tests", 0)) for s in suites)
want = int(sys.argv[2])
if ran != want:
    sys.exit(f"interop: expected exactly {want} executed tests, report has {ran}")
print(ran)
' "$report" "$expected_tests")"; then
  :
else
  status=$?
  echo "interop: exact-count check failed (rc=$status); log: $log" >&2
  exit "$status"
fi
printf 'executed_tests=%s\n' "$ran" >>"$log"
printf 'interop: %s tests executed, 0 skipped, 0 failed; local log: %s\n' "$ran" "$log"
