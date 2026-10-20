#!/usr/bin/env bash
# Lightweight Linux/macOS setup for the native Go + Rust BreachPilot engine.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

for tool in go cargo; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "[!] Required native tool '$tool' not found in PATH." >&2
    exit 1
  fi
done

echo "==> Building Rust execution sidecar"
cargo build --manifest-path rust/Cargo.toml --workspace --release

echo "==> Building Go control plane (bp)"
go build -o bp ./cmd/bp

if command -v npm >/dev/null 2>&1 && [[ -f "webui/package.json" ]]; then
  echo "==> Building WebUI"
  (cd webui && npm ci --no-audit --no-fund && npm run build)
fi

echo "==> Running ./bp --doctor"
./bp --doctor
