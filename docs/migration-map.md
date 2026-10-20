# BreachPilot Go + Rust migration map (initial scaffold)

Source of truth: repo audit of 1,121 tracked `.py` files. Each row maps a
Python subsystem to its native replacement. Status `done` means implemented
in this tree; `planned` means the manifest/contract exists but full behavior
is still being ported. No Python fallback remains in done paths.

## Control plane (Go)

| Python subsystem | Go replacement | Status |
|---|---|---|
| `main.py`, `tools/cli_args.py`, `cmd` flags | `cmd/bp/main.go` (all user-facing flags) | done (subset: target/mode/goal/web/doctor/self-test/resume/export/list-plugins/version) |
| `app.py`, `tools/api/` (35 files: routes, auth, broker, persistence) | `internal/api/server.go` + `manifests.go`, `internal/auth`, `internal/events`, `internal/store` | done (health/capabilities/config/secrets/models/providers/sys/runs/events-SSE+WS/decisions/graph/connections/benchmarks/skills/plugins/attack-modules/doctor) |
| `tools/api/auth.py` bearer + loopback + WS handshake | `internal/auth/auth.go` + WS close codes in api | done |
| `tools/api/event_broker.py` replay/SSE/WS cursors + 30s heartbeat | `internal/events/events.go` | done |
| `db.py` schema v10 + `research_workspace` | `internal/store/store.go` (DDL mirrors missions/runs/decisions/findings/audit; opens existing api_runtime.db, backs up pre-migration) | done (core tables; lessons/embeddings/graph tables planned) |
| `tools/kernel/allowlist.py` + `tools/validation_utils.py` matcher | `internal/allowlist` (Go mirror) + `rust/crates/bp-allowlist` (enforcement) | done, vectors pinned in both test suites |
| `tools/providers/` (ollama/opencode_go/chatgpt) | `internal/providers` real HTTP adapters | done |
| `tools/mcp_tools/registry.py` pkgutil+AST discovery | `internal/api/manifests.go` compile-time registries (attack families, 15 plugins, skills) | done (manifest-driven; per-tool schemas planned) |
| `tools/attack_modules/` (~83 classes) | manifest families dispatched to Rust sidecar `exec` | planned (identities resolve; per-module args planned) |
| `plugins/*/plugin.py` (15) | manifest list; process-based plugin protocol | planned |
| `skills/` scripts (174 files) | skill metadata preserved; executors become native library fns / sidecar ops | planned |
| `tools/swarm/`, `tools/campaign/`, `tools/run_service/`, `tools/exploit_agent/`, `tools/recon/`, `tools/reporting/`, `tools/memory/`, `tools/benchmark/`, `tools/eval/` | run lifecycle in `internal/api` + `internal/store`; orchestration port in progress | planned |
| `tools/sandbox/` manager/network/policy (docker netns, fail-closed) | Rust `bp-exec` gate + Go docker driver | planned (gate+exec done; netns firewall port planned) |
| `tools/browser/` playwright | non-Python browser control | planned |
| `tools/config/` loader | `internal/config` single-layer loader + validation | done |

## Execution plane (Rust)

| Python subsystem | Rust replacement | Status |
|---|---|---|
| `tools/sandbox/exceptions.py` SANDBOX_* | `bp-exec::ExecError` (ScopeDenied/Timeout/Spawn, fail closed) | done |
| `tools/mcp_tools/terminal/allowlist.py` target-lock | `bp-allowlist::check/check_all/is_subdomain` | done |
| `tools/mcp_tools/sandbox_exec.py` + `sandbox/manager.py` exec | `bp-exec::execute` (argv, no shell, timeout, output caps, process-group kill) | done |
| evidence/audit hash chain | `bp-evidence` (sha256 chain, verify) | done |
| Go<->Rust transport | `proto/exec.proto` IDL + `bp-sidecar` loopback TCP JSON v1 + `internal/ipc` client | done (JSON v1; gRPC upgrade path documented in proto) |

## WebUI

Unchanged. `webui/` (React/TS/Vite) preserved; backend adapts to it.
Contract pinned by `internal/api/server_test.go` (health no-auth, auth gate,
envelope, run lifecycle, cursor replay).

## What was deliberately not ported

- Nothing removed yet. Python tree stays until each `planned` row is done and
  the verification report shows green; then Phase 8 deletes per-file.
