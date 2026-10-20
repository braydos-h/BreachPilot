# Inventory — Python → Native disposition (audit 2026-10-20)

Baseline: `git ls-files '*.py'` = **1,121** files.
- tests/ 455, tools/ 420, skills/ 174, root 24, scripts/ 18, plugins/ 15, legacy/ 14, .claude/ 1.
- Native today: 49 Go files (`cmd/`, `internal/`), 5 Rust files (`rust/crates/*`), `proto/exec.proto`, `Dockerfile.native`.

## Done (native real behavior + tests, Python retained as reference until cutover)

| Python path | Functionality | Native target | Tests | Status |
|---|---|---|---|---|
| `main.py` + `tools/cli_args.py` | CLI flags | `cmd/bp/main.go` | `go test ./...`, doctor/self-test | done |
| `app.py` SPA + daemon | loopback daemon + SPA | `cmd/bp/main.go serve()` + `spaHandler` | e2e GET / 200, /api 401 | done |
| `tools/api/auth.py` | bearer gate, token 0600, WS codes | `internal/auth` | `server_test.go` | done |
| `tools/api/event_broker.py` | ordered replay/cursors/SSE | `internal/events` | replay/cursor tests | done |
| `tools/config/loader.py` | defaults, validate-before-write | `internal/config` | patch tests | done |
| `tools/api_key_store.py` | secrets CRUD, never leak values | `internal/secrets` | round-trip tests | done |
| `db.py` + persistence | runs/decisions/findings/audit schema v10 | `internal/store` | CRUD tests | done |
| `tools/goal_engine.py` | 14 presets | `internal/goals` | API test | done |
| `tools/skill_registry.py` | SKILL.md discovery/search/atomic CRUD | `internal/skills` | list/search/create/delete | done |
| `tools/plugins.py` manifests | plugin.yaml discovery | `internal/plugins` | fixture test | done |
| `ollama_provider` | /api/tags, model spec parse | `internal/ollama` | httptest + vector | done |
| provider status | chatgpt file-existence, proxy probe; login/start honest 503 `proxy_runtime_missing` (oauth runtime untracked) | `internal/providers` + api honest-error tests | done |
| `tools/api/run_service` + run_manager | lifecycle preparing→completed/failed/cancelled, resume-adopt | `internal/runner` | e2e recon, cancel/resume | done |
| `tools/recon` fast path | parse/validate, DNS, 24-port scan+banners | `internal/recon` | scan/assess/suggest | done-partial (nmap/rustscan/masscan fallbacks, UDP, OS fingerprint pending) |
| `tools/api/routes/decisions.py` | DB-backed approvals | api decisions routes | gate/409/answer tests | done |
| `policy.record` | SHA-256 JSONL chain | `internal/audit` | round-trip/tamper | done |
| `tools/exploit_agent` subset | per-service probes, evidence | `internal/agent` | skip-on-denial | done-partial (full planner/critic/reflection pending) |
| `attack_modules` network family | resolve/tcp_scan/http_probe/tls_probe | `internal/modules` | loopback tests | done-partial (83 classes beyond network family pending) |
| `tools/benchmark` smoke | native-smoke suite, oracle, baseline compare | `internal/bench` | validation/compare tests | done-partial (full eval harness pending) |
| `tools/browser` playwright | chromedp CDP gated | `internal/browser` | gate/scheme/probe tests | done-partial |
| `tools/doctor.py` + self-test | loopback/store/allowlist/tags/sidecar | `internal/diag` | exit-code tests | done |
| Go↔Rust protocol | JSON-v1 TCP version-gated | `internal/ipc` ↔ `bp-sidecar`, `proto/exec.proto` | 5 live contract tests | done |

## Pending (Python retained, native returns real empty or explicit 501 — must port before deletion)

- Swarm/campaign orchestration, checkpoints beyond resume-adopt (`tools/swarm/`, `tools/campaign/`, `--swarm` recorded not executed).
- 83 attack-module classes beyond network family; 15 plugin behaviors (manifests only today).
- ~174 `skills/*/scripts/*.py` executors (XSS checkers → future `modules` web families; KEV/EPSS processors → native enrichment).
- Docker worker lifecycle + netns firewall (Rust gate+exec exist; container isolation pending).
- Full recon profiles (nmap privileged fallbacks, UDP, OS fingerprint, masscan/rustscan), CVE intel enrichment, memory/semantic, report export (md/html/pdf), eval graded harness, operator connections, recon-first goal-select, multi-model consult, critic/reflection agents.
- Benchmark service always available via lazy default (`ensureBench`); no unconfigured sentinel.
- `mcp_server.py` / `mcp_exploit_server.py` / `mcp_engine_server.py` standalone entrypoints (native `internal/mcp` servers exist but lack `cmd/bp-mcp-*` binaries + stdio/HTTP wiring to fully replace executables).
- `scripts/*.py` codegen (catalogs, CLI/config refs, release gates), `tools/webui/*`, `tools/importers/*`, `tools/research/*`, `tools/verification/*`, `tools/memory/*`, `tools/reporting/*`.

## Tooling / packaging pending deletion (after parity)

`pyproject.toml`, `requirements.txt`, `constraints-dev.txt`, `conftest.py`, pytest suite `tests/` (455 files → port to Go/Rust tests), ruff/mypy config, `Makefile` python targets, `install.sh`/`install.ps1` venv flows, `install.bat`/`START.bat`, Python Docker stages, Python CI jobs (`.github/workflows/ci.yml`, `eval.yml`, etc.), `scripts/*.py` generators.

Deletion eligibility: none yet. Every pending row blocks its Python source's deletion.
