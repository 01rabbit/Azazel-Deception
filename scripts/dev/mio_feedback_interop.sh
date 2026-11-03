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
#        MIO_COMMIT (7a35288)  KNOWLEDGE_COMMIT (6b590f3)  PYTHON (python3.12)
# Knowledge is private: its output goes to the log file in WORKDIR, never to stdout.
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
MIO_COMMIT="${MIO_COMMIT:-7a35288}"
KNOWLEDGE_COMMIT="${KNOWLEDGE_COMMIT:-6b590f3}"
PYTHON="${PYTHON:-python3.12}"
log="$work/interop.log"

extract() { # repo commit dest
  if [ ! -e "$3/.extracted-$2" ]; then
    rm -rf "$3"; mkdir -p "$3"
    git -C "$1" archive "$2" | tar -x -C "$3"
    touch "$3/.extracted-$2"
  fi
}
extract "$MIO_REPO" "$MIO_COMMIT" "$work/mio"
extract "$KNOWLEDGE_REPO" "$KNOWLEDGE_COMMIT" "$work/knowledge"

if [ ! -x "$work/venv-mio/bin/python" ]; then
  uv venv --python "$PYTHON" "$work/venv-mio" -q
  uv pip install -q --python "$work/venv-mio/bin/python" -e "$work/mio" -e "$here" pytest
fi
if [ ! -x "$work/venv-knowledge/bin/python" ]; then
  uv venv --python "$PYTHON" "$work/venv-knowledge" -q
  uv pip install -q --python "$work/venv-knowledge/bin/python" -e "$work/knowledge[api]" >>"$log" 2>&1
fi

cleanup() { # no stray uvicorn from this work dir may outlive the run
  pkill -f "$work/venv-knowledge/bin/python -m uvicorn" 2>/dev/null || true
}
trap cleanup EXIT

report="$work/interop-junit.xml"
rm -f "$report"
cd "$here"
export AZAZEL_DECEPTION_MIO_INTEROP=1
export AZAZEL_DECEPTION_KNOWLEDGE_PYTHON="$work/venv-knowledge/bin/python"
export AZAZEL_DECEPTION_KNOWLEDGE_SRC="$work/knowledge"
set +e
"$work/venv-mio/bin/python" -m pytest tests/test_mio_feedback_interop.py -p no:cacheprovider \
  --junitxml "$report" -rs 2>&1 | tee -a "$log"
status=${PIPESTATUS[0]}
set -e
[ "$status" -eq 0 ] || { echo "interop pytest failed (rc=$status); log: $log" >&2; exit "$status"; }
"$work/venv-mio/bin/python" scripts/ci/assert_executed.py "$report" --min-tests 13
