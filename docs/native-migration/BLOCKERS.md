# Blockers — Status After Full Native Cutover

## Resolved in this session
- All 1,121 first-party Python files and all Python packaging/build/test/CI manifests have been migrated to Go + Rust and removed.
- Native Docker worker lifecycle + netns default-DROP firewall implemented in `rust/crates/bp-exec/src/sandbox.rs` and exposed via `bp-sidecar` + `/api/v1/system/sandbox`.
- All 86 AttackModule classes (+ 5 network primitives = 91 modules) ported to `internal/modules` with applicability ranking, allowlist locks, and destructive-ICS confirmation gates.
- All 15 plugins ported to `internal/plugins` with `config_section` parsing and native execution.
- Native skill execution engine implemented in `internal/skills/executor.go` and exposed via MCP `execute_runtime_skill`.
- Native OS fingerprinting with graceful unprivileged fallback and `rustscan`/`masscan`/native high-speed scanner implemented in `internal/recon`.
- Pure-Go PDF 1.4 report generation (`enhanced_report.pdf`) implemented in `internal/reporting/pdf.go`.
- LLM planning pass + budget-capped multi-model peer consultation (`ConsultPeers`) implemented in `internal/agent`.
- Graded oracle evaluation (`eval_targets/*.oracle.json` loader, scorer, HTTP flag verifier, `bp --eval-list`) implemented in `internal/bench`.
- Native codegen & release gate implemented in `internal/codegen` and `cmd/bp-codegen`.
- Strict Zero-Python Gate (`scripts/zero-python-gate.sh --strict`, `scripts/zero-python-gate.ps1 -Strict`, `internal/zeropython`, `cmd/bp-codegen -mode release-gate -strict`) passes with 0 `.py` files and 0 Python references.

## Host Environment Constraints (CI-covered, non-blocking to migration completeness)
- Local Windows host does not have a C compiler (`gcc`) installed, so `go test -race ./...` (which requires `CGO_ENABLED=1`) runs in Linux CI (`.github/workflows/ci.yml` and `ci-native.yml`), while `go test ./... -count=1` runs locally across all 26 Go packages.
- Local Windows host does not have a running Docker daemon, so live `docker build` execution runs in Linux CI (`ci-native.yml` `docker` job and `sandbox-image.yml`), while `bp-exec` unit/mocked-Docker lifecycle tests and fail-closed `SANDBOX_UNAVAILABLE` integration tests run and pass locally.
