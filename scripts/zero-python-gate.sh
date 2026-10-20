#!/bin/sh
# Zero-Python gate: fails (with --strict) if first-party Python or active
# Python runtime/build/test dependencies remain. Report mode (default) prints
# counts and exits 0 so CI stays informative mid-migration; the release job
# runs --strict and must pass before cutover is declared.
# Usage: zero-python-gate.sh [--strict] [--root DIR]
set -eu
STRICT=0
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
for a in "$@"; do
  case "$a" in
    --strict) STRICT=1 ;;
    --root) shift; ROOT="$1" ;;
    --root=*) ROOT="${a#--root=}" ;;
  esac
done
cd "$ROOT"
FAIL=0
PY_TRACKED="$(git ls-files '*.py' 2>/dev/null | wc -l | tr -d ' ')"
echo "tracked .py files: ${PY_TRACKED:-0}"
if [ "${PY_TRACKED:-0}" != "0" ]; then
  echo "pending: first-party .py files remain (see docs/native-migration/INVENTORY.md)"
  FAIL=1
fi
# Python manifests / packaging that must disappear at cutover.
for f in pyproject.toml requirements.txt constraints-dev.txt conftest.py MANIFEST.in; do
  if [ -e "$f" ]; then echo "pending: $f still present"; FAIL=1; fi
done
# Active Python references in runtime/install/CI paths (docs/history excluded).
if grep -rInE --exclude-dir=.git --exclude-dir=docs --exclude-dir=webui --exclude='*.md' \
  -e '\bpython3?\b' -e '\bpip\b' -e 'pytest' -e 'uvicorn' -e 'requirements\.txt' \
  Dockerfile.native Makefile install.sh install.ps1 install.bat START.bat \
  .github/workflows go.mod 2>/dev/null | grep -v 'zero-python-gate' | head -30; then
  echo "pending: Python references above in runtime/install/CI paths"
  FAIL=1
else
  echo "no Python references in runtime/install/CI paths"
fi
# Subprocess-launched Python from native code (gate's own scanner excluded).
if grep -rInE --include='*.go' --include='*.rs' -e '"python3?"' internal rust/crates cmd 2>/dev/null | grep -v 'internal/zeropython' | head -20; then
  echo "pending: native code invokes Python"
  FAIL=1
else
  echo "native code does not invoke Python"
fi
if [ "$STRICT" = "1" ] && [ "$FAIL" = "1" ]; then
  echo "ZERO-PYTHON GATE: FAIL"
  exit 1
fi
echo "ZERO-PYTHON GATE: ${FAIL:+report done (pending items above)}"
