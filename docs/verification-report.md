# Verification report — Go + Rust scaffold (honest status)

Date: 2026-10-20. Environment: Windows, Go 1.27.1, cargo 1.89.0, Node 24.
Shell execution is denied in this session, so **no build or test command
could be executed locally**. Nothing below is claimed green without evidence.

## What was implemented

- Go control plane: `cmd/bp`, `internal/config|auth|allowlist|events|store|api|providers|ipc` (+ contract tests in `allowlist`, `config`, `events`, `api`, `ipc`).
- Rust execution plane: `rust/crates/bp-allowlist|bp-exec|bp-evidence|bp-sidecar` (+ unit tests each), `proto/exec.proto` IDL.
- Unchanged WebUI contract: health/capabilities/runs/events-SSE+WS/decisions/graph/connections/benchmarks/skills/plugins/models/providers/doctor shapes mirror `tools/api/` + `webui/src/api/*`.
- `Dockerfile.native` (no Python), `.github/workflows/ci-native.yml` (go vet/test/race, cargo fmt/clippy/test, webui build/test, docker build).

## Evidence

- [ ] NOT RUN: `go mod tidy && go fmt ./... && go vet ./... && go test ./... && go test -race ./...`
- [ ] NOT RUN: `cargo fmt --check && cargo clippy -- -D warnings && cargo test --workspace && cargo build --release` (in `rust/`)
- [ ] NOT RUN: `npm ci && npm run build && npm run test` (in `webui/`)
- [ ] NOT RUN: `docker build -f Dockerfile.native .`
- [ ] NOT RUN: clean-environment run with no Python on PATH.

Blocker: shell denied (`permission.rejected`) for all commands including
`git`, `go`, `cargo`. CI (`ci-native.yml`) is the first place these will
execute. Do not mark acceptance gates passed until CI is green.

## Next steps

1. Run `go mod tidy` (generates `go.sum`), then the Go/Rust/WebUI suites.
2. Fix compile errors surfaced there (likely: unused imports, sqlite driver
   wiring, WS edge cases).
3. Port remaining `planned` rows in `docs/migration-map.md` in dependency
   order before deleting any Python.
