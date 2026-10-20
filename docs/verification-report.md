# Verification report — native Go + Rust (evidence, 2026-10-20)

Toolchain: go 1.27.1 windows/amd64, cargo 1.89.0, node v24.13.1.
All commands below ran in this session against the working tree. No claim
without output. Where execution was impossible, the blocker is named.

## Go — all green

- `go build ./...` → exit 0
- `go vet ./...` → exit 0 (incl. fixed: non-constant format string, tls.Conn assertion, unused imports)
- `gofmt -l cmd internal` → clean (after `go fmt`)
- `go test ./internal/... -count=1` → **all packages ok**, incl. new:
  `agent`, `allowlist` (+ApprovalEntries self-auth test), `api` (goals/secrets/
  skills/plugins/models/ollama/providers/decisions/run-e2e/tool-calls/decide/
  benchmarks-smoke), `audit` (chain + tamper), `bench`, `browser`, `config`
  (validate-before-write), `diag`, `modules`, `store` (goals/decisions),
  `runner` (recon e2e, fail-closed scope), `recon`, `secrets`, `skills`,
  `ollama` (faithful refresh port), `events`, `ipc`
- `go test -race` → **blocked**: no cgo/gcc on this Windows box
  (`-race requires cgo`). Covered by Linux CI (`ci-native.yml`).
- `go mod tidy` → clean, `go.sum` committed.

## Rust — all green (workdir `rust/`)

- `cargo test --workspace` → **10 passed, 0 failed**
  (allowlist 5, evidence 2, exec 3)
- `cargo clippy --workspace --all-targets -- -D warnings` → clean
  (fixed: non-exhaustive match, `manual_clamp`)
- `cargo fmt --all -- --check` → clean

## IPC contract — live 5/5

Real `bp-sidecar` on 127.0.0.1:18765 + `go test ./internal/ipc/ -v`:
`TestLiveHealth`, `TestLiveScopeDenied`, `TestLiveSpaFailed`,
`TestLiveVersionMismatch`, `TestLiveUnknownOp` → **all PASS**, then sidecar
terminated. (Protocol: `docs/ipc-protocol.md`, IDL `proto/exec.proto`.)

## WebUI — untouched, green

- `npm run build` (tsc + vite + css assert) → exit 0
- `npm run test` (vitest) → **55 files, 499 tests, all pass**
- No `webui/` source file modified by this migration (build output only).

## End-to-end daemon run (real binary, real network)

- `go build -o bp-e2e.exe ./cmd/bp` → ok
- `GET /api/v1/health` (no auth) → 200 `{"ready":true,"version":"v1"}`
- `GET /` (no auth) → 200 SPA index (public by design)
- `GET /api/v1/capabilities` (no auth) → 401
- `POST /runs {127.0.0.1, recon, yes:true}` → 201 → polled to **completed**
- Event replay: run_created → state → recon_completed
  (`open_ports:[135,445,3389]` — genuine Windows host surface) → run_completed
- Artifacts on disk: `recon_assessment.json`, `goal_suggestions.json`,
  `run.json`, `session_summary.md`, `activity.jsonl`, `session_state.json`
- Working tree after run: `git status` clean (reports/db/token are gitignored)
- Daemon + sidecar processes terminated; test binary removed.

## Doctor / self-test (real checks)

- `bp --doctor` → ok loopback-bind, ok sqlite-store, ok allowlist-gate,
  skip ollama-tags (provider opencode_go), WARN sidecar unreachable (true —
  no sidecar was running). Exit 0.
- `bp --self-test` → PASS loopback resolve + scan + allowlist + store.

## Not verified locally (CI-owned)

- `docker build -f Dockerfile.native` → **no Docker daemon on this box**.
  Dockerfile reviewed by hand (stage paths, `go mod download` fail-fast,
  config path, port). CI `docker` job builds it.
- `go test -race` → see above; CI runs it on Linux.
- Windows installer paths (`install.ps1`/`install.bat`) untouched — native
  installer work is pending.

## Bugs found and fixed this session (root causes)

1. `bp-exec` non-exhaustive match (test) → explicit arm.
2. clippy `manual_clamp` ×2 → `clamp()`.
3. **Vacuous allowlist**: runner appended the target itself to the gate set,
   authorizing everything → new `ApprovalEntries` (config + explicit env
   only; TARGET/DOMAIN/DISCOVERED never self-authorize) + regression test.
4. `PatchFile`/`DeleteMapKey` wrote invalid configs to disk → validate-before-write.
5. `familyOf` split at `:` broke version families → faithful `parse_model_spec` port.
6. `audit.Append` silently dropped rows when run dir was missing → MkdirAll.
7. Dropped `runSelfTest`/`eventsSub` header during edits → restored, verified by build.
8. `tls.Dialer` returns `net.Conn` → type assertion to `*tls.Conn`.
9. Non-constant `fmt.Errorf` format → `errors.New`.
10. Benchmark readiness required an open port → readiness = resolvable + allowlisted.

## Bottom line

The native backend is real and exercised end to end, but the migration is
**not complete**: pending rows in `docs/migration-map.md` still need native
ports, zero Python files were deleted (correctly), and Docker/race still
need CI. Do not declare completion.
