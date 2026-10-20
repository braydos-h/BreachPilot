# BreachPilot Go + Rust Migration Map (COMPLETE — 100% Go + Rust, Zero Python)

Audit baseline: 1,121 tracked `.py` files at migration start → **0 `.py` files remaining**.
Every subsystem below is implemented in Go (`cmd/`, `internal/`) or Rust (`rust/crates/*`) with passing native tests. The React/TypeScript WebUI (`webui/`) is preserved unchanged.

## Control plane (Go) — done

| Original Python subsystem | Native Go replacement | Evidence |
|---|---|---|
| `main.py` + `tools/cli_args.py` flags | `cmd/bp/main.go` (`--target`, `--mode`, `--goal`, `--custom-goal`, `--web`, `--daemon`, `--menu`, `--doctor`, `--self-test`, `--eval`, `--eval-list`, `--save-baseline`, `--check-regression`, `--swarm`, `--multi-model`, `--resume`, `--export-run`, `--list-plugins`, `--version`) | `go build ./...`, CLI smoke tests |
| `app.py` daemon + SPA hosting | `cmd/bp/main.go serve()` loopback daemon + `spaHandler` | e2e: `GET /` 200, `/api/*` 401 w/o token |
| `tools/api/auth.py` | `internal/auth` (bearer gate, 0o600 token file, WS 4400/4401/4403/4404) | `auth_test.go` + `server_test.go` |
| `tools/api/event_broker.py` | `internal/events` (ordered replay, cursors, SSE `: heartbeat`, WS replay+live) | `events_test.go` |
| `tools/config/loader.py` | `internal/config` (`api`, `exploit`, `models`, `ollama`, `sandbox`, `cve_lookup`, `threat_intel`, `browser`, `multi_model`, `providers`, atomic `PatchFile`/`DeleteMapKey`) | `config_test.go`, `patch_test.go`, `intel_test.go`, `threatintel_test.go` |
| `tools/api_key_store.py` + `/secrets` | `internal/secrets` (`secr.json` v1, 0600, atomic, values never returned) | `secrets_test.go` |
| `db.py` + `api/persistence.py` | `internal/store` (schema v10 `runs`/`decisions`/`findings`/`audit` + `custom_goals` NOCASE unique) | `goals_test.go` |
| `tools/goal_engine.py` presets | `internal/goals` (14 presets, safe/gated/high + `standard_authorized` compat) | `goals_test.go` |
| `tools/skill_registry.py` + skill executors | `internal/skills` (`SKILL.md` discovery/search/create/delete + native `Store.Execute` across all skill archetypes) | `skills_test.go`, `executor_test.go` |
| `tools/plugins.py` + 15 plugins | `internal/plugins` (`plugin.yaml` + `config_section` discovery + native `Execute` for all 15 plugins) | `plugins_test.go`, `executors_test.go` |
| `ollama_provider` + `tools/providers/*` | `internal/ollama` + `internal/providers` (`ollama`, `opencode_go`, `chatgpt` adapters + model refresh) | `ollama_test.go`, `providers_test.go` |
| `tools/api/run_service` + `run_manager` | `internal/runner` (lifecycle, cancellation, resume-adopt, recon-first goal auto-select, swarm campaign dispatch, CVE enrichment, artifact & report generation) | `runner_test.go`, `swarm_test.go`, `swarm_resume_test.go`, `goal_select_test.go`, `intel_test.go` |
| `tools/swarm/*` + `tools/campaign/*` | `internal/campaign` (Blackboard, milestones, Recon/Vuln/Validation/Critic/Reflection specialists, RetryEngine, `swarm_state.json` + `attack_states.json` checkpoints, resume demotion) | `campaign_test.go` |
| `tools/recon/*` (TCP, UDP, OS fingerprint, fast scanner) | `internal/recon` (TCP scan+banners, connected-socket UDP scan, `FingerprintOS` with unprivileged fallback, `RunFastScanner` rustscan/masscan/native Go worker pool, Nmap privilege downgrade, CVE enrichment) | `recon_test.go`, `udp_test.go`, `fingerprint_scanner_test.go` |
| `tools/cve_lookup.py` + `tools/threat_intel.py` | `internal/intel` (NVD v2, EPSS, CISA KEV, circuit breaker, LRU cache) + `internal/threatintel` (OSV, GHSA, KEV, SSRF guard, wire hardening) | `intel_test.go`, `threatintel_test.go` |
| `tools/memory/*` | `internal/memory` (SQLite episodic memory, lessons, Jaccard relevance, `/api/v1/system/memory`) | `memory_test.go`, `slice18_routes_test.go` |
| `tools/reporting/*` (JSON, MD, HTML, PDF) | `internal/reporting` (HITL-gated `enhanced_report.json`/`.md`/`.html`/`.pdf` pure-Go PDF 1.4 generator + `bp --export-run`) | `reporting_test.go`, `pdf_test.go` |
| `tools/exploit_agent/*` + peer consult | `internal/agent` (allowlist-gated service probes, LLM planning pass, budget-capped multi-model `ConsultPeers`) | `agent_test.go`, `llm_consult_test.go` |
| `tools/attack_modules/*` (all 86 classes + 5 network tools) | `internal/modules` (91 registered tools across all families, `FindApplicable` ranking, allowlist lock, destructive-ICS confirmation gate) | `modules_test.go`, `dns_test.go`, `catalog_test.go` |
| `tools/benchmark/*` + `tools/eval/*` | `internal/bench` (`native-smoke` suite, `RunSync`, baseline save/compare, `LoadOracles`, `ScoreAgainstOracle`, `VerifyOracleFlags`, `bp --eval`, `bp --eval-list`) | `bench_test.go`, `eval_test.go`, `oracle_eval_test.go` |
| `tools/browser/*` | `internal/browser` (chromedp CDP: create/navigate/text/screenshot/close, allowlist gate, Chrome probe) | `browser_test.go` |
| `tools/operator_connection/*` | `internal/operator` (`operator_connections.json` + per-target shards, CRUD, beacon/check/remove, `/api/v1/connections/*`) | `operator_test.go`, `connections_test.go` |
| `tools/intelligence/graph/*` + `/api/v1/graph/*` | `internal/graph` (scoped `run:{id}` artifact-built graph, summary, node detail, bounded multi-hop neighbors, BFS shortest paths) | `graph_test.go`, `traverse_test.go`, `graph_api_test.go` |
| `mcp_server.py`, `mcp_exploit_server.py`, `mcp_engine_server.py` | `internal/mcp` + `internal/mcpserve` + `cmd/bp-mcp-defensive` (:8000), `cmd/bp-mcp-assess` (:8001), `cmd/bp-mcp-engine` (:8002) | `mcp_test.go`, `vulnintel_test.go`, `mcpserve_test.go` |
| `scripts/*.py` codegen & release gates | `internal/codegen` + `internal/zeropython` + `cmd/bp-codegen` (`counts`, `skill-catalog`, `mcp-catalog`, `release-gate -strict`) | `codegen_test.go`, `zeropython_test.go` |
| `tools/doctor.py` + `--self-test` | `internal/diag` | `diag_test.go` |

## Execution plane (Rust) — done

| Original Python subsystem | Native Rust replacement | Evidence |
|---|---|---|
| `tools/sandbox/exceptions.py` (`SANDBOX_*`) | `bp-exec::ExecError` (`Unavailable`, `PolicyFailed`, `ScopeDenied`, `WorkspaceFailed`, `Unsupported`, `Timeout`, `Spawn` — fail-closed) | `bp-exec` unit tests |
| `tools/mcp_tools/terminal/allowlist.py` | `bp-allowlist` (IP/CIDR/domain/`*.` dot-boundary, empty fails closed, no self-auth) | `bp-allowlist` 5 unit tests |
| `tools/sandbox/{models,docker_backend,network,policy,manager}.py` | `bp-exec::sandbox` (`SandboxManager`, hardened `build_create_args`, `build_network_policy`, IPv4/IPv6 `NAI-OUTPUT` netns firewall via `NET_ADMIN` sidecar, `cleanup_stale`, `destroy`, `cancel`, workspace confinement) | `bp-exec` 8 unit & lifecycle tests |
| `tools/exploit_agent/policy.py` audit chain | `bp-evidence` (SHA-256 hash chain, tamper verification) | `bp-evidence` 2 unit tests |
| Sidecar IPC server | `bp-sidecar` (`health`, `exec`, `sandbox_status`, `sandbox_rules`, `sandbox_cleanup` over JSON-v1 TCP) | `bp-sidecar` unit test + 5 live Go↔Rust `internal/ipc` contract tests |
