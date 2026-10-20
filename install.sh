#!/usr/bin/env bash
# BreachPilot native Go + Rust installer for Linux and macOS.
# Builds the Go control plane (bp + MCP servers), Rust execution sidecar
# (bp-sidecar), and TypeScript WebUI bundle, installs ~/.local/bin launchers,
# and runs `bp --doctor`.

set -euo pipefail

MODE="install"
YES=0
MINIMAL=0
ADD_TO_PATH="${ADD_TO_PATH:-1}"
INSTALL_BIN_DIR="${HOME}/.local/bin"

usage() {
  cat <<'EOF'
Usage: ./install.sh [options]

Options:
  --yes, -y       Non-interactive install.
  --check         Read-only environment check; changes nothing.
  --doctor        Run `bp --doctor` against the checkout and exit.
  --minimal       Build core Go + Rust binaries only (skip WebUI npm build).
  --uninstall     Remove ~/.local/bin/bp and ~/.local/bin/breachpilot launchers.
  --help, -h      Show this help message.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes|-y) YES=1; shift ;;
    --check) MODE="check"; shift ;;
    --doctor) MODE="doctor"; shift ;;
    --minimal) MINIMAL=1; shift ;;
    --uninstall) MODE="uninstall"; shift ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

if [[ "$MODE" == "uninstall" ]]; then
  rm -f "$INSTALL_BIN_DIR/bp" "$INSTALL_BIN_DIR/breachpilot" "$INSTALL_BIN_DIR/bp-sidecar"
  echo "[OK] Removed BreachPilot launchers from $INSTALL_BIN_DIR"
  exit 0
fi

check_tool() {
  local cmd="$1"
  local label="$2"
  if command -v "$cmd" >/dev/null 2>&1; then
    echo "  [OK] $label: $(command -v "$cmd")"
    return 0
  else
    echo "  [!!] $label missing ($cmd not found in PATH)"
    return 1
  fi
}

echo "==> Checking BreachPilot native toolchain"
MISSING=0
check_tool go "Go toolchain (1.24+)" || MISSING=1
check_tool cargo "Rust cargo toolchain" || MISSING=1
if [[ "$MINIMAL" -eq 0 ]]; then
  check_tool npm "Node.js npm (WebUI)" || MISSING=1
fi
check_tool nmap "Nmap scanner (optional for native scan, recommended)" || true

if [[ "$MODE" == "check" ]]; then
  exit "$MISSING"
fi

if [[ "$MISSING" -ne 0 ]]; then
  echo "[FAIL] Missing required native build toolchains above." >&2
  exit 1
fi

if [[ "$MODE" == "doctor" ]]; then
  go run ./cmd/bp --doctor
  exit $?
fi

echo "==> Building Rust execution sidecar (bp-sidecar)"
cargo build --manifest-path rust/Cargo.toml --workspace --release

echo "==> Building Go control plane and MCP servers"
go build -trimpath -o bp ./cmd/bp
go build -trimpath -o bp-mcp-defensive ./cmd/bp-mcp-defensive
go build -trimpath -o bp-mcp-assess ./cmd/bp-mcp-assess
go build -trimpath -o bp-mcp-engine ./cmd/bp-mcp-engine
go build -trimpath -o bp-codegen ./cmd/bp-codegen

if [[ "$MINIMAL" -eq 0 ]] && [[ -f "webui/package.json" ]]; then
  echo "==> Building React/TypeScript WebUI"
  (cd webui && npm ci --no-audit --no-fund && npm run build)
fi

if [[ "$ADD_TO_PATH" == "1" ]]; then
  mkdir -p "$INSTALL_BIN_DIR"
  ln -sf "$REPO_ROOT/bp" "$INSTALL_BIN_DIR/bp"
  ln -sf "$REPO_ROOT/bp" "$INSTALL_BIN_DIR/breachpilot"
  if [[ -f "$REPO_ROOT/rust/target/release/bp-sidecar" ]]; then
    ln -sf "$REPO_ROOT/rust/target/release/bp-sidecar" "$INSTALL_BIN_DIR/bp-sidecar"
  fi
  echo "==> Installed launchers in $INSTALL_BIN_DIR (bp, breachpilot, bp-sidecar)"
fi

echo "==> Running native environment doctor"
./bp --doctor
echo "[OK] BreachPilot native installation complete."
