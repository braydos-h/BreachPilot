# Inventory — Python → Native Disposition (COMPLETE — 100% Migrated)

Baseline at start: `git ls-files '*.py'` = **1,121** files.
Final count: **0** `.py` files remaining; **0** Python manifests remaining.

## Complete Disposition Matrix

| Original Python Path | Functionality | Native Go / Rust Target | Native Tests | Status | Deletion Eligibility |
|---|---|---|---|---|---|
| `main.py`, `cli.py`, `tools/cli_*.py` | CLI entrypoint, flags, doctor, self-test, eval, export | `cmd/bp/main.go`, `internal/diag` | `diag_test.go`, CLI smoke | done | deleted |
| `app.py`, `tools/api/*` | Loopback HTTP REST API, SSE/WS event streaming, auth, config, secrets, goals, decisions, artifacts, logs, workspace, loot, credentials, witness, system routes | `internal/api`, `internal/auth`, `internal/events`, `internal/config`, `internal/secrets`, `internal/goals` | `server_test.go`, `real_test.go`, `notported_test.go`, `graph_api_test.go`, `connections_test.go`, `slice18_routes_test.go`, `auth_test.go`, `goals_test.go` | done | deleted |
| `db.py`, `mission.py`, `legacy/*`, root shims | Persistence schema v10, runs, decisions, findings, audit | `internal/store`, `internal/audit` | `store/goals_test.go`, `audit_test.go` | done | deleted |
| `mcp_server.py`, `mcp_exploit_server.py`, `mcp_engine_server.py`, `tools/mcp_*` | Engine, Defensive, and Assessment MCP servers (stdio + loopback HTTP) | `internal/mcp`, `internal/mcpserve`, `cmd/bp-mcp-engine`, `cmd/bp-mcp-defensive`, `cmd/bp-mcp-assess` | `mcp_test.go`, `vulnintel_test.go`, `mcpserve_test.go` | done | deleted |
| `tools/swarm/*`, `tools/campaign/*`, `tools/autonomous_orchestrator.py` | Multi-agent swarm & autonomous campaign orchestration, Blackboard, milestones, Critic/Reflection, RetryEngine, checkpoints, resume recovery | `internal/campaign`, `internal/runner` | `campaign_test.go`, `swarm_test.go`, `swarm_resume_test.go` | done | deleted |
| `tools/exploit_agent/*` | Post-recon assessment agent loop, LLM planning pass, budget-capped multi-model peer consultation | `internal/agent` | `agent_test.go`, `llm_consult_test.go` | done | deleted |
| `tools/attack_modules/*` (86 classes) | Web, SMB, AD, Auth/Creds, SSH, Services, Crypto/JWT, Deserialize, Privesc/Cloud/K8s, Persistence, ICS/OT/IoT, Supply Chain, Synthesis, Detection, Orchestrator phases + applicability ranking | `internal/modules` (`catalog.go`, `modules.go`, `dns.go`) | `modules_test.go`, `dns_test.go`, `catalog_test.go` | done | deleted |
| `tools/recon/*` | TCP connect scan, banner/version extraction, connected-socket UDP sweep, multi-signal OS fingerprinting with unprivileged fallback, rustscan/masscan/native fast scanner, goal suggestions | `internal/recon` | `recon_test.go`, `udp_test.go`, `fingerprint_scanner_test.go` | done | deleted |
| `tools/cve_lookup.py`, `tools/threat_intel.py`, `tools/intelligence/*` | NVD v2, EPSS, CISA KEV, OSV, GHSA, attack graph construction & BFS/neighbor traversal | `internal/intel`, `internal/threatintel`, `internal/graph` | `intel_test.go`, `intel_config_test.go`, `threatintel_test.go`, `graph_test.go`, `traverse_test.go` | done | deleted |
| `tools/memory/*` | Episodic memory, experience lessons, Jaccard relevance retrieval | `internal/memory` | `memory_test.go` | done | deleted |
| `tools/reporting/*`, `report_generator.py` | HITL-gated JSON, Markdown, HTML, and pure-Go PDF 1.4 report generation | `internal/reporting` | `reporting_test.go`, `pdf_test.go` | done | deleted |
| `tools/benchmark/*`, `tools/eval/*` | Benchmark suites, synchronous eval loop, baseline regression gates, `eval_targets/*.oracle.json` loader, oracle scorer, live HTTP flag verifier | `internal/bench` | `bench_test.go`, `eval_test.go`, `oracle_eval_test.go` | done | deleted |
| `tools/browser/*` | Allowlist-gated headless browser automation via Chrome DevTools Protocol (`chromedp`) | `internal/browser` | `browser_test.go` | done | deleted |
| `tools/operator_connection/*` | Persisted operator-connection registry + per-target shards | `internal/operator` | `operator_test.go` | done | deleted |
| `tools/providers/*` | Canonical `Client` interface + `ollama`, `opencode_go`, `chatgpt` HTTP adapters | `internal/providers`, `internal/ollama` | `providers_test.go`, `ollama_test.go` | done | deleted |
| `skills/*/scripts/*.py`, `tools/skill_registry.py` | Skill discovery (`SKILL.md`) + native skill execution engine across all archetypes | `internal/skills` (`skills.go`, `executor.go`) | `skills_test.go`, `executor_test.go` | done | deleted |
| `plugins/*/plugin.py`, `tools/plugins.py` | `plugin.yaml` + `config_section` discovery + native execution for all 15 plugins | `internal/plugins` (`plugins.go`, `executors.go`) | `plugins_test.go`, `executors_test.go` | done | deleted |
| `tools/sandbox/*`, `tools/kernel/*` | Allowlist matcher, disposable Docker worker lifecycle, `NET_ADMIN` netns firewall (`iptables-restore`/`ip6tables-restore`), SHA-256 evidence chain, JSON-v1 IPC sidecar | `rust/crates/bp-allowlist`, `bp-exec`, `bp-evidence`, `bp-sidecar`, `internal/allowlist`, `internal/ipc` | `cargo test --workspace` (16 tests), `allowlist_test.go`, `ipc_test.go` | done | deleted |
| `scripts/*.py` | Skill/MCP catalog generators, capability counts, version/release gates, zero-Python scanner | `internal/codegen`, `internal/zeropython`, `cmd/bp-codegen`, `scripts/zero-python-gate.sh`, `scripts/zero-python-gate.ps1` | `codegen_test.go`, `zeropython_test.go` | done | deleted |
| `tests/*.py` (455 files) | Unit, contract, API, and integration test coverage | 25 Go test packages (`internal/...`) + 4 Rust crate test suites (`rust/crates/...`) + 55 WebUI Vitest suites (`webui/src/...`) | `go test ./...`, `cargo test --workspace`, `npm run test` | done | deleted |
