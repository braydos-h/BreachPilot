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
| `tools/recon` fast path + UDP sweep + CVE/EPSS/KEV enrichment | TCP parse/validate/DNS/24-port scan+banners; native connected-socket UDP probes merged as `udp_ports` + udp services; `cve_lookup` block (EPSS/KEV flags, tunables, `NVD_API_KEY`) threaded via `intel.SettingsFor` into MCP servers + runner recon/swarm enrichment | `internal/recon` + `internal/intel` | scan/assess/suggest + UDP open/closed/merge + enrichment + config mapping + recon e2e asserts `udp_ports` | done-partial (nmap privileged fallbacks, OS fingerprinting pending; masscan/rustscan out of scope) |
| `tools/api/routes/decisions.py` | DB-backed approvals | api decisions routes | gate/409/answer tests | done |
| `policy.record` | SHA-256 JSONL chain | `internal/audit` | round-trip/tamper | done |
| `tools/exploit_agent` subset | per-service probes, evidence | `internal/agent` | skip-on-denial | done-partial (full planner/critic/reflection pending) |
| `attack_modules` network family | resolve/tcp_scan/http_probe/tls_probe | `internal/modules` | loopback tests | done-partial (83 classes beyond network family pending) |
| `tools/benchmark` smoke + `tools/eval` graded loop | native-smoke suite (oracle, baseline save/compare) + `bench.RunSync` + `bp --eval [--suite/--trials/--save-baseline/--check-regression]` | validation/compare/RunSync tests + live CLI smoke (save/check/bad-suite paths) | done-partial (docker-oracle graded eval pending: needs docker daemon + exploit targets) |
| `tools/browser` playwright | chromedp CDP gated | `internal/browser` | gate/scheme/probe tests | done-partial |
| `tools/doctor.py` + self-test | loopback/store/allowlist/tags/sidecar | `internal/diag` | exit-code tests | done |
| MCP entrypoints (`mcp_server.py`, `mcp_exploit_server.py`, `mcp_engine_server.py`) | `cmd/bp-mcp-*` via shared `internal/mcpserve` (stdio/HTTP, loopback gate, fingerprint check); `make mcp-*` runs Go binaries | mcpserve tests + live stdio/HTTP smoke | done |
| `tools/api/graph_builder.py` + explorer routes | `internal/graph` (artifact-built nodes/edges/summary + detail/neighbors/BFS paths) + `/api/v1/graph/runs/{id}`, `/summary`, `/nodes/{id}`, `/nodes/{id}/neighbors`, `/paths` (python clamp bounds; conflicts honest-empty) | build/summary/traversal + API node/neighbors/paths/summary/gap tests | done |
| `tools/threat_intel` (OSV/GHSA/KEV) + `threat_intel` config block | `internal/threatintel` (SSRF-guarded queries, wire-output hardening, file cache, token-missing degrade, shared KEV catalog) + `config.ThreatIntel` + feed key in defensive `search_vulnerability_intel` | validation/hardening/cache/degrade + MCP include/omit tests | done |
| `tools/reporting` export (md/html) + HITL findings gate + `--export-run` | `internal/reporting` (enhanced_report.json/.md/.html, vetted-only technical findings, best-effort at finalize, artifacts whitelist, `--export-run` regenerate) | gate/filter/render/round-trip + recon e2e + live CLI export | done-partial (CVSS scoring + exploitation-chain reconstruction pending) |
| Go↔Rust protocol | JSON-v1 TCP version-gated | `internal/ipc` ↔ `bp-sidecar`, `proto/exec.proto` | 5 live contract tests | done |

## Pending (Python retained, native returns real empty or explicit 501 — must port before deletion)

- Swarm/campaign orchestration (`tools/swarm/`, `tools/campaign/`): native `campaign.Run` (blackboard, critic, reflection, checkpoints, resume-demotion, bounded fan-out) executes for swarm-flagged runs via `runner.runSwarm`; `--swarm` recorded on run request + CLI message; resume adopts prior recon + swarm checkpoints (`attack_states.json`/`swarm_state.json`) with in-flight demotion; recon-first goal auto-select (custom > preset > top compatible suggestion) tags assessment + emits WebUI `goal_suggestions`/`fast_recon_goal_selected` events. Remaining: multi-target run input (API is single-target per run), parallel_swarm variant.
- 83 attack-module classes beyond network family; 15 plugin behaviors (manifests only today).
- ~174 `skills/*/scripts/*.py` executors (XSS checkers → future `modules` web families; KEV/EPSS processors → native enrichment).
- Docker worker lifecycle + netns firewall (Rust gate+exec exist; container isolation pending).
- Full recon profiles (nmap privileged fallbacks, OS fingerprint, masscan/rustscan), memory/semantic, report export (pdf only; md/html/json now native), eval graded harness (docker-oracle blocked), operator connections, recon-first goal-select, multi-model consult.
- Benchmark service always available via lazy default (`ensureBench`); no unconfigured sentinel.
- `mcp_server.py` / `mcp_exploit_server.py` / `mcp_engine_server.py` standalone entrypoints → native `cmd/bp-mcp-defensive` (:8000), `cmd/bp-mcp-assess` (:8001, +`--workspace`/`--run-id`/`--sidecar-addr`/`--expected-config-sha256`), `cmd/bp-mcp-engine` (:8002) sharing `internal/mcpserve` (stdio/HTTP, loopback gate, fingerprint check); `make mcp-*` runs the Go binaries. Remaining: `--private-config-snapshot` secret-ref resolution (python-only helper, no native consumer yet)..
- `scripts/*.py` codegen (catalogs, CLI/config refs, release gates), `tools/webui/*`, `tools/importers/*`, `tools/research/*`, `tools/verification/*`, `tools/memory/*`, `tools/reporting/*`.

## Tooling / packaging pending deletion (after parity)

`pyproject.toml`, `requirements.txt`, `constraints-dev.txt`, `conftest.py`, pytest suite `tests/` (455 files → port to Go/Rust tests), ruff/mypy config, `Makefile` python targets, `install.sh`/`install.ps1` venv flows, `install.bat`/`START.bat`, Python Docker stages, Python CI jobs (`.github/workflows/ci.yml`, `eval.yml`, etc.), `scripts/*.py` generators.

Deletion eligibility: none yet. Every pending row blocks its Python source's deletion.
