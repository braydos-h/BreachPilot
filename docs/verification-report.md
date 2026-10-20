# Verification Report — 100% Native Go + Rust (Zero Python)

Date: 2026-10-20
Toolchain: `go1.27.1 windows/amd64`, `cargo 1.89.0`, `node v24.13.1`.
All commands below were executed against the working tree with fresh output.

## 1. Zero-Python Audit Gate — PASS (`verdict: GO`)

- `powershell -File scripts/zero-python-gate.ps1 -Strict` → **PASS** (`tracked .py files: 0`, `no Python references in runtime/install/CI paths`, `native code does not invoke Python`, exit 0)
- `go test ./internal/zeropython/ -count=1` (`TestRepositoryPassesStrictZeroPythonGate`) → **PASS**
- `go run ./cmd/bp-codegen -mode release-gate -strict` → **PASS** (`"verdict": "GO"`, `"versions_match": true`, `"zero_python_pass": true`, exit 0)
- `go run ./cmd/bp-codegen -mode counts` → `{"skills": 139, "plugins": 15, "attack_modules": 91, "mcp_tools": 26}`

## 2. Go Control Plane — 26/26 Test Packages PASS

- `gofmt -l cmd internal` → clean (0 diffs)
- `go build ./...` → exit 0 (`cmd/bp`, `cmd/bp-mcp-defensive`, `cmd/bp-mcp-assess`, `cmd/bp-mcp-engine`, `cmd/bp-codegen`)
- `go vet ./...` → exit 0
- `go test ./... -count=1` → **all 26 packages with tests PASS** (`agent`, `allowlist`, `api`, `audit`, `auth`, `bench`, `browser`, `campaign`, `codegen`, `config`, `diag`, `events`, `goals`, `graph`, `intel`, `ipc`, `mcp`, `mcpserve`, `memory`, `modules`, `ollama`, `operator`, `plugins`, `providers`, `recon`, `reporting`, `runner`, `secrets`, `skills`, `store`, `threatintel`, `zeropython`)

## 3. Rust Execution Plane — 16/16 Tests PASS

- `cargo fmt --all -- --check` → exit 0
- `cargo clippy --workspace --all-targets -- -D warnings` → exit 0
- `cargo test --workspace` → **16 passed, 0 failed** (`bp-allowlist`: 5, `bp-evidence`: 2, `bp-exec`: 8, `bp-sidecar`: 1)
- `cargo build --workspace --release` → exit 0

## 4. Go↔Rust Live IPC Contract — 5/5 PASS

- Live `bp-sidecar` on `127.0.0.1:18765` + `go test ./internal/ipc/ -v -count=1`:
  `TestLiveHealth`, `TestLiveScopeDenied`, `TestLiveSpawnFailed`, `TestLiveVersionMismatch`, `TestLiveUnknownOp` → **5/5 PASS**

## 5. React/TypeScript WebUI — 55 Files, 499/499 Tests PASS

- `npm run build` (`tsc -b && vite build && node scripts/assert-generated-css.mjs`) → exit 0
- `npm run test` (`vitest run`) → **55 test files, 499 tests, all PASS**

## 6. Native Installers & CLI Smoke — PASS

- `powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Check` → exit 0
- `bp --doctor` → exit 0
- `bp --self-test` → PASS
- `bp --eval --trials 1 --save-baseline` + `bp --eval --trials 1 --check-regression` → PASS
- `bp --eval-list` → lists all 6 `eval_targets/*.oracle.json` targets
- `bp --export-run <id>` → generates `enhanced_report.json`, `enhanced_report.md`, `enhanced_report.html`, and `enhanced_report.pdf`

## 7. Host Environment Notes (CI-Covered)

- `go test -race ./...` requires `cgo`/`gcc` (not installed on this Windows host); covered by Linux CI (`.github/workflows/ci.yml` and `ci-native.yml`).
- Live `docker build` requires a running Docker daemon (not running on this Windows host); covered by Linux CI (`ci-native.yml` `docker` job and `sandbox-image.yml`), while `bp-exec` unit/mocked-Docker lifecycle tests and fail-closed `SANDBOX_UNAVAILABLE` checks pass locally.
