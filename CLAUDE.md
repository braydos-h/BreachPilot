# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

**AI Target Exploitation Engine** (also branded "NetAttackAI") — an AI-driven, locally-run penetration testing / bug bounty research agent. It is a local-first Python application that uses Ollama LLMs to plan and execute authorized security assessments against targets the operator owns or has explicit written authorization to test.

The repo is NOT a generic nmap wrapper. It couples:
- An assessment controller (`main.py` / `app.py`) that opens an MCP exploit session (`tools/mcp_session.py:open_exploit_mcp_session`, an async context manager emitting `[BOOT]`/`[OK]` markers via `AttackUi.boot_step`) and dispatches tool calls.
- A defensive MCP tool server (`mcp_server.py`) that exposes scope-gated Nmap scanning, sanitized vulnerability search, and NVD CVE lookup.
- A second permissive MCP tool server (`mcp_exploit_server.py`, port 8001 by default) that exposes terminal execution, Python file write/run, searchsploit, Metasploit, msfvenom, impacket lateral movement, and credential dumping — gated at the policy layer in `tools/exploit_agent/policy.py`, not in the MCP server itself.
- A multi-agent swarm (`tools/swarm/`) that decomposes work across 6 specialist agents with a shared blackboard.
- A questionary-driven interactive menu and direct CLI entry points.
- An autonomous attack orchestrator (`tools/autonomous_orchestrator.py`) that drives persistent multi-phase campaigns with adaptive aggression levels.

The operator must only ever run this against networks they own or are explicitly authorized to assess. Scope, command, and search safety are enforced in Python code, not just in prompts.

## Common Commands

### Install & verify
```bash
# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
nmap --version                               # must be on PATH or set nmap.path in config.yaml
ollama show glm-5.2:cloud                    # default model — verify reachable
```
```powershell
# Windows PowerShell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
nmap --version
ollama show glm-5.2:cloud
```
On Linux, nmap `-O`/`-sS` need root; set `nmap.sudo: true` in `config.yaml` (uses `sudo -n`) or run as root — otherwise the defensive server auto-downgrades those flags (`nmap.priv_fallback`, default true).

### Makefile targets (Linux/macOS convenience)
```bash
make install          # venv + pip install -r requirements.txt
make install-dev      # venv + pip install -e ".[dev]"
make doctor           # python main.py --doctor
make self-test        # python main.py --self-test
make test             # full pytest suite
make test-one F=tests/test_scope_gate.py  # single file
make run              # interactive menu
make mcp-defensive    # defensive MCP server
make mcp-exploit      # exploit MCP server
make clean            # remove venv + __pycache__ dirs
```

### One-shot bootstrap
```bash
./scripts/setup-linux.sh   # venv + deps + doctor check
```

### Run
```bash
python main.py                               # interactive questionary menu (the DEFAULT no-args behavior)
python main.py --menu                         # same interactive menu, explicit
python main.py --target 10.0.0.50 --mode attack --goal backdoor
python main.py --target 10.0.0.50 --mode recon --recon-first
python main.py --target 10.0.0.50 --mode attack --swarm --critic --reflection --adaptive-exploits
python main.py --exploit --exploit-mode standalone --exploit-target 10.0.0.50 --exploit-cve CVE-2021-44228 --exploit-permission full_access
```

### Legacy research CLI (writes to research_workspace/research.db)
```bash
python cli.py init-mission --config mission.yaml
python cli.py next-task
python cli.py run-task T-00001
python cli.py list-findings
python cli.py generate-report F-00001
python cli.py status
```

### Tests
```bash
python -m pytest tests/ -v
python -m pytest tests/test_scope_gate.py -v          # single file
python -m pytest tests/test_recon_pipeline.py::TestClass::test_method -v   # single test
python -m pytest tests/ -v -k "scope"                  # by keyword
```
The test suite covers scope gates, safety review, semantic memory, recon, MCP workspaces, reporting, CVE lookup, the agent loop, reliability, swarm behavior, retry logic, skills, reasoning, long sessions, peer consultation, audit chains, credential storage, Metasploit integration, and more.

### MCP servers (standalone)
```bash
python mcp_server.py --transport stdio --approved-subnets 192.168.1.0/24
python mcp_server.py --transport http --host 127.0.0.1 --port 8000 --approved-subnets 192.168.1.0/24
python mcp_exploit_server.py   # defaults: stdio, port 8001
```
The HTTP transport refuses to bind to non-loopback interfaces unless `--allow-public-bind` AND `MCP_ALLOW_PUBLIC_BIND=1` are both set.

### Lint / type-check (opt-in, no CI)
```bash
python -m pip install -e ".[dev]"   # includes ruff
ruff check .                         # line-length 120, select E/F/W/I
python -m pytest --cov=tools --cov=main.py --cov=cli.py
```

## Configuration

Everything behavior-defining lives in **`config.yaml`**. Top-level keys (current state):
- `ollama` (host, model `glm-5.2:cloud`, 976K context) + `models.registry` (glm/deepseek/deepseek_flash/kimi/minimax aliases) + `models.default_alias` (glm)
- `mcp` (default_transport, http_host/port)
- `nmap` (path, sudo, priv_fallback)
- `exploit` (mode, permission, attack_mode, timeouts, workspace_dir, allowed_targets, require_explicit_allowlist, shell, msfconsole_path, disallowed_assets, forbidden_actions) — **lab build: default permission is `full_access`** with `attack_mode: true`; the one attack-mode safety kept is the target-IP lock (`require_explicit_allowlist` unions the runtime `--target` via `EXPLOIT_TARGET`). Recon still resolves to `read_only` via the missing-key fallback.
- `stealth` (rotate_ua, dns_over_https) — inert/UI-only legacy block; the live Phase 6.2 block is `opsec`
- `opsec` (enabled, ua_rotation, doh, doh_provider, min_gap_seconds, jitter_seconds, rate_per_minute, quiet_command_patterns, noise_budget, **local_targets_off**, **local_cidrs**, **public_autonomy**) — agent self-hardening + detection-coverage. **Target-aware (Phase 6.2+):** `OpsecProfile.resolve_for_target(ip)` / `OpsecManager.resolve_for_target(ip)` force the profile OFF for private/local target IPs (RFC1918/loopback/link-local/reserved/ULA, plus `local_cidrs`) so the AI moves freely on the operator's own box; a public-routable target keeps the configured posture ON. Classification via `tools/validation_utils.is_private_or_local_target` (distinct from `is_local_target`, which means "operator's own host"). Wired at `AutonomousOrchestrator.__init__` (process-global UA resolved against the primary target) and per-action at `AttackModuleExecutor.execute` (`resolve_for_target(task.target)` before `acquire_pacing`). Defaults: `local_targets_off: true`, `public_autonomy: true`.
- `cve_lookup`, `research`, `swarm`, `reasoning`, `memory`, `adaptive_exploits`, `multi_model` (optional peer consultation; off by default)
- `long_session` (opt-in multi-hour attack mode, also enabled by `--long-session`)
- `skills` (runtime skills system: selection, re-selection, feedback, semantic matching, sanitization)

Mission scope (allowed/disallowed assets, forbidden_actions, risk_profile, testing_modes, rate_limits) is configured in **`mission.yaml`** and loaded by `cli.py` / `mission.py`. The three risk profiles (`low_noise_non_destructive`, `standard_authorized`, `high_authorized_testing`) live in `mission.py:_RISK_PROFILES`. Hard-blocked actions regardless of config: `denial_of_service`, `destructive_exploit`, `social_engineering`, `physical_attack`, `malware`, `credential_theft` (see `scope_gate.py:_HARD_FORBIDDEN_ACTIONS`).

## High-Level Architecture

Two parallel control flows exist in the same checkout and are partially redundant by design. Knowing which one is in play matters when reading any file.

### Flow A — Exploitation engine (modern, `main.py` / `app.py`)
The "what the user actually runs" path. Async, MCP-based, multi-agent-capable.

```
operator ──► main.py (or app.py)
                │
                ├─ open_exploit_mcp_session()  ← async ctx manager (tools/mcp_session.py,
                │     wrapped at main.py); wraps stdio_client / streamable_http_client,
                │     calls session.initialize() capped at MCP_BOOT_TIMEOUT_SECONDS (30s);
                │     sets EXPLOIT_TARGET env on the server subprocess (the target-IP lock);
                │     soft_fail lets the recon-first path degrade to None
                │
                ├─ interactive menu (AttackUi) / CLI args
                │
                ├─ GoalEngine (tools/goal_engine.py) → resolves preset or custom goal,
                │     gates by risk profile (SAFE/GATED/HIGH tags)
                │
                ├─ "Ready-to-begin gate" — prints run summary, asks confirm()
                │
                ├─ build_router() → Ollama model client  +  build ExploitSettings
                │
                ├─ run_exploit_session()  ─►  mcp_exploit_server.py (port 8001)
                │     policy gated by ExploitPolicy in tools/exploit_agent/policy.py
                │     (read_only | approve_only | full_access)
                │
                ├─ if --swarm: AgentLoop.run_autonomous_campaign()
                │     └─ SwarmOrchestrator (tools/swarm/orchestrator.py)
                │           • shared blackboard, critic pre-check, parallel dispatch
                │           • routes to: recon | vuln | exploit | post_exploit
                │                        | critic | reflection agents
                │
                └─ AutonomousOrchestrator (tools/autonomous_orchestrator.py)
                      • persistent multi-phase campaigns with adaptive aggression
                      • auto-triggers attack modules from recon findings
                      • retries with modified parameters on failure
                      • vulnerability chaining + privilege escalation tracking
```

`mcp_exploit_server.py` exposes the actual offensive tools: `run_exploit_terminal`, `write_python_file`, `run_python_file`, `search_exploit_db`, `search_web_exploit`, `search_cve_intel`, `run_msf_module`, `read_workspace_file`, `list_workspace`, `check_os`, `generate_payload` (msfvenom), `lateral_exec` (impacket), `dump_credentials`, `kerberoast`. When `multi_model.enabled` is true or `--multi-model-consult` is passed, it also exposes `consult_peer_models`, an advisory-only tool that asks other configured model aliases for ideas without tool schemas. All target-touching tools require a target IP, are workspace-contained under `exploit_workspace/<ip>/`, and write to `exploit_audit.jsonl`.

### Flow B — Legacy research loop (`cli.py` + `agent_loop.py` / `db.py`)
Database-driven, scope-gated, suitable for headless/CI. Uses SQLite (`research_workspace/research.db`).

```
cli.py command
    └─► mission.yaml ─► MissionController.create_from_config()
    └─► ScopeGate.check_scope()  ← every executor action passes through here
    └─► AgentLoop (agent_loop.py)  ←─ Mission / DB / Memory / Evidence / TargetGraph
         PlannerAgent → TaskQueue → ExecutorAgent → ObserverAgent
              ↓
         ToolRouter → SafetyReviewer.preflight_check()
              ↓
         FindingVerifier → ReportGenerator
              ↓
         Audit log + evidence store + target graph
```

`ScopeGate` is the one chokepoint for *every* executor action in Flow B — it checks allowed/disallowed assets, hard-forbidden actions, third-party detection, rate limit bucket, and risk level. Mirror the same pattern if you add new actions.

### MCP Tool Subpackage (`tools/mcp_tools/`)

The exploit MCP server's tool implementations live in a structured subpackage, registered through `tools/mcp_tools/registry.py`:

| Module | Purpose |
|--------|---------|
| `registry.py` | Central wiring — `@audit_tool` decorator, workspace helpers, model-router resolution, multi-model/consult-alias config, process timeouts. Registers no tools itself. |
| `terminal.py` | `run_exploit_terminal` + package/clone primitives (`apt_install`, `git_clone`, `pip_install`, `run_as_root`, `check_environment`, `install_package`, `download_and_install`, `update_system`) — shell execution with the target-IP lock (`_target_lock_block`) |
| `recon.py` | `check_os`, `quick_scan`, `run_full_recon`, `get_service_fingerprint` |
| `attack_modules.py` | Web-app probes (`jwt_tamper`, `ssti_probe`, `graphql_introspect`, `race_request`, `timing_oracle`, `request_smuggling_probe`, `password_spray`, `cve_to_exploit_synth`, `hash_crack_identify`) + autonomous campaign planner (`create_attack_plan`/`get_current_plan`/`replan`, `start_autonomous_campaign`/`get_campaign_status`/`run_campaign_step`) + `list_attack_modules`, `run_attack_module`, `craft_exploit`, `mutate_exploit` |
| `metasploit.py` | `run_msf_module`, `msfconsole_start`/`stop`/`command`, `msf_run_exploit`, `msf_run_auxiliary`, `msf_list_sessions`, `msf_interact_session`, `msf_run_post_module`, `msf_kill_session`, `msf_generate_payload`, `msf_run_resource_script` |
| `payloads.py` | `generate_payload` — msfvenom payload generation |
| `credentials.py` | Encrypted credential store (`cred_store_add`/`get`/`list`/`confirm`) + `lateral_exec` (impacket), `dump_credentials`, `kerberoast` |
| `workspace.py` | `write_python_file`, `run_python_file`, `read_workspace_file`, `list_workspace` — workspace file I/O (lab build: arbitrary absolute paths allowed) |
| `sessions.py` | tmux/background-job + listener management (`start_tmux_session`, `send_to_session`, `read_session_output`, `kill_session`, `start_background_job`, `read_job_output`, `stop_background_job`, `start_listener`, `read_listener_output`, `stop_listener`, `list_sessions`, `list_processes`, `kill_process`) |
| `research.py` | `search_exploit_db`, `search_web_exploit`, `fetch_webpage`, `deep_research`, `search_cve_intel` |
| `runtime_skills.py` | `list_runtime_skills`, `search_runtime_skills`, `load_runtime_skill`, `list_skill_references` (conditionally registered) |
| `peer_models.py` | `consult_peer_models` (conditionally registered) — multi-model advisory consultation |

**Flow A CLI orchestration layer** (extracted from `main.py` into top-level `tools/*.py` during the cleanup):
- `mcp_session.py` — `open_exploit_mcp_session`, the MCP boot async context manager (see Boot Sequence).
- `exploit_session.py` — `run_exploit_session`: single-target orchestration, wires ScopeGate + MCP session + `run_exploit_agent`.
- `cli_exploit_settings.py` — `build_cli_exploit_settings`, `_resolve_exploit_permission` (missing-key fallback is `read_only`; `--mode attack` only upgrades to full_access when config explicitly grants it).
- `config_cli.py` — `load_config`, `bootstrap_startup_api_keys`.
- `recon_assessment_cli.py` — `run_recon_assessment` (OS/scan/CVE-intel → `ReconAssessment`).
- `resume_state.py` — `--resume` state loader (reloads `recon_assessment.json` + chosen goal).
- `safety_review_cli.py` — `run_safety_review` for recon mode.
- `skills_cli.py` — runtime skill overrides + startup selection (`--skills*` flags).
- `swarm_bridge.py` — `SwarmMcpBridge`: bridges the sync swarm `tool_executor`/`ExploitAgent.run` onto the live MCP `ClientSession` (preserves run_exploit_session's single-session invariant).

### Shared infrastructure
- **`db.py`** — SQLite schema (missions, scope_rules, tasks, observations, graph_nodes, graph_edges, evidence, findings, audit_logs, memories) with `_new_id()` and `_now_iso()` helpers. Versioned migrations table.
### `tools/` Directory — Key Modules

| Module | Purpose |
|--------|---------|
| `exploit_agent/` (pkg, ~3.8K lines) | Split from the old 164K monolith: `loop.py` (main agent loop), `policy.py` (ExploitPolicy / ExploitPermission), `context.py` (context sizing/compaction/attack memory), `prompt.py`, `reflection.py`, `skills.py` (mid-run re-selection), `tool_calls.py`, `ollama_client.py`, `_common.py` (shared import surface) |
| `autonomous_orchestrator.py` (58K) | Persistent multi-phase attack campaigns, aggression levels, auto-retry, vuln chaining |
| `attack_ui.py` (51K) | Interactive questionary-based menu system (AttackUi) |
| `interactive_menu.py` (32K) | Arrow-key-driven main menu (no-args default) |
| `recon_pipeline.py` (63K) | Host discovery, service identification, enrichment, goal suggestion |
| `attack_modules/` (pkg, ~2.2K lines) | Split from the old 87K monolith: `base.py` (AttackModule ABC + ModuleContext), `registry.py` (ranking), `modules/` per-category (`web`, `auth_creds`, `crypto_jwt`, `deserialize`, `network_smb`, `privesc`, `services`, `ssh`, `synthesis`) |
| `command_analyzer.py` (30K) | Destructive command and egress analysis |
| `config_manager.py` (30K) | Config schema, validation, and defaults |
| `payload_crafter.py` (31K) | Payload generation and mutation |
| `metasploit_bridge.py` (30K) | Metasploit RPC integration |
| `persistent_session_manager.py` (36K) | Session persistence, checkpoint, resume |
| `web_researcher.py` (57K) | Provider-backed web research (Ollama/SerpAPI), source ranking, caching |
| `model_router.py` (12K) | Ollama model client routing, retry, context window normalization |
| `model_telemetry.py` (11K) | LLM usage telemetry (tokens, context, duration, tokens/sec) |
| `validation_utils.py` (10K) | IP validation, command sanitization, banner parsing |
| `mcp_shared.py` (45K) | Workspace path checks, allowlist checks, audit helpers, redaction |
| `skill_registry.py` (15K) | Skill catalog loading, sanitization, metadata |
| `skill_selector.py` (15K) | Deterministic + semantic skill selection |
| `skill_embeddings.py` (7K) | nomic-embed-text cosine similarity ranking |
| `skill_pipeline.py` (8K) | Skill context injection into agent prompts |
| `skill_feedback.py` (5K) | Cross-mission skill outcome feedback (ExperienceStore) |
| `semantic_memory.py` (15K) | Ollama nomic-embed-text cross-mission learning |
| `experience_store.py` (10K) | Bayesian confidence scoring for attack outcomes |
| `attack_memory.py` (17K) | Per-attempt memory with context window management |
| `credential_store.py` (21K) | Encrypted credential storage |
| `cve_lookup.py` (12K) | NVD CVE lookup with circuit breaker + rate limiting |
| `goal_engine.py` (16K) | Goal preset resolution and risk gating |
| `goal_suggester.py` (31K) | Recon-driven goal suggestion |
| `enhanced_reporting.py` (37K) | Exploit-session reporting, timelines, CVSS, chains |
| `exploit_search.py` (11K) | Exploit database search (searchsploit wrapper) |
| `exploit_mutator.py` (8K) | Exploit parameter mutation strategies |
| `session_manager.py` (11K) | Session lifecycle management |
| `attack_planner.py` (12K) | Attack plan generation and step sequencing |
| `safety_reviewer.py` (4K) | Pre-flight safety checks for tool calls |
| `doctor.py` (12K) | Environment and configuration diagnostics |
| `self_test.py` (10K) | Safe localhost smoke test |
| `api_key_store.py` (8K) | API key collection, storage, env loading |
| `activity_log.py` (6K) | Per-run activity JSONL logging |
| `reliability.py` (38K) | Retry logic, circuit breakers, error classification |
| `post_exploit.py` (6K) | Post-exploitation helpers |
| `demo_mode.py` (7K) | Demo/presentation mode |
| `logging_setup.py` (5K) | Logging configuration |
| `exceptions.py` (1.5K) | `_EXC_GROUP_CATCH`, `_is_exception_group`, `_log_nested_exceptions` |

## Boot Sequence (Flow A)

The MCP exploit session is opened by `tools/mcp_session.py:open_exploit_mcp_session` (an async context manager, re-wrapped at `main.py:open_exploit_mcp_session` and re-bound into `tools/exploit_session.py`). It emits `[BOOT]`/`[OK]` progress markers via `AttackUi.boot_step` / `boot_section` (grep `boot_step` to find them), then per transport:

- **stdio** (default): spawns the exploit MCP server subprocess, wraps `mcp.client.stdio.stdio_client`, and calls `session.initialize()` capped at `MCP_BOOT_TIMEOUT_SECONDS` (30s). The subprocess env gets `EXPLOIT_TARGET` (the runtime `--target`), `EXPLOIT_WORKSPACE`, and the active-model/multi-model flags — this is how the target-IP lock reaches the server (see Permission Model).
- **http**: starts the loopback HTTP child in its own process group, then retries a real MCP `initialize()` + `list_tools()` readiness handshake within the same 30s cold-start budget. A successful probe is followed by the live `streamable_http_client` session. Startup/readiness/initialization failures safely fall back to stdio; failures after a live session has been yielded never fall back (to avoid repeating a partially completed tool call). `MCP_HTTP_TOKEN`, when configured, is sent by both the readiness probe and live client. HTTP shutdown signals the process group and escalates to descendant-tree termination on Windows. Startup errors include a bounded, credential-redacted tail of `mcp_exploit_server.log`.

`soft_fail=True` yields `None` so the recon-first path can degrade when MCP is unavailable; hard-fail re-raises. The old runtime recon-module checklist is gone — heavy modules (`exploit_search`, `cve_lookup`, `web_researcher`, `recon_pipeline`, `attack_planner`, `attack_modules`, `payload_crafter`, `metasploit_runner`) are now imported by the server at subprocess boot (enumerated in the `MCP_BOOT_TIMEOUT_SECONDS` comment, not a runtime-checked list).

Critical detail: anyio task groups (used by the MCP SDK's `stdio_client`) raise `BaseExceptionGroup` on subprocess death, which is **not** a subclass of `Exception`. The module-level `_EXC_GROUP_CATCH` tuple and `_is_exception_group` / `_log_nested_exceptions` helpers (in `tools/exceptions.py`, imported by `mcp_session.py`) exist precisely because `except Exception` silently misses it. New code wrapping MCP tool calls or session lifecycle must use `_EXC_GROUP_CATCH`, not bare `except Exception`.

## Permission Model (exploit layer)

This is a **lab-only build**. The operator runs it against systems they own or are
explicitly authorized to test, on a throwaway operator box. The attack path is
**unrestricted but target-locked**: the AI may do whatever it takes to the one
target IP. Recon keeps its full safety (post-session SafetyReviewer, READ_ONLY
propose-only, goal-menu SAFE/GATED narrowing, defensive scope-gated MCP server).

Three levels, defined in `tools/exploit_agent/policy.py`:
- **`full_access`** (config + schema default) — the lab attack posture. `ExploitPolicy.approve_action` auto-approves every action with **no command-content or scope inspection** — destructive commands, egress, reverse shells, credential dumping, Metasploit, and Python file write/run are all allowed. The `is_full_access` branch just increments the per-session command budget and returns True. `_check_command_safety` / `_check_scope_gate` / `_gate_pivot_and_count` were removed from this branch.
- **`approve_only`** — every tool call prints an "EXPLOIT ACTION REQUIRES APPROVAL" banner; user must type `ALLOW <target_ip>` to proceed. Used by recon/interactive paths; the banner code stays but is unreachable from attack mode.
- **`read_only`** — agent gathers intel and proposes attacks without executing them. Recon uses this (`tools/cli_exploit_settings.py:_resolve_exploit_permission` hard-codes `read_only` as the missing-key fallback so a partial config never silently becomes live).

**The ONE attack-mode safety kept: target-IP lock (no pivoting to other hosts).**
It is enforced at the MCP tool layer, not the policy:
- `tools/mcp_shared._allowed_target_list` unions `os.environ["EXPLOIT_TARGET"]` (set to the runtime `--target` in `tools/mcp_session.py`) with `exploit.allowed_targets`.
- The target-IP lock is enforced by `tools/mcp_tools/terminal._target_lock_block`, gated by `ctx.require_allowlist` (driven by `exploit.require_explicit_allowlist` + a non-empty allowlist via `registry.make_require_allowlist`) and run on every target-touching tool. It extracts every destination (URL authorities, `/dev/tcp` hosts, LHOST/RHOST, scanner-verb targets, bare IPs) via `command_analyzer._extract_destinations` / `extract_ips_from_command` / `_SCANNER_TARGET_RE` and refuses any not in `is_target_in_allowlist`. Operator-authorized callback/C2 hosts are added via `exploit.allowed_targets`.
- The autonomous orchestrator's no-MCP "Path B" (`tools/autonomous_orchestrator.py` `AttackModuleExecutor`) is target-locked by its `scope_gate.check_scope(asset=task.target)` — that is why its scope/risk/critic gates were **kept** (removing the scope_gate would lose the Path-B target lock). Its `max_pivot_depth` defaults to 0 (no host-pivoting recursion).

**Operator-box filesystem is unrestricted.** The workspace path-traversal
protection, sensitive-credential denylist, and `list_workspace` credentials/
hiding were removed (`tools/mcp_tools/registry.py:read_workspace`,
`tools/mcp_tools/workspace.py`). `write_python_file` accepts arbitrary
paths/sizes/code (absolute paths write anywhere on the operator box);
`read_workspace_file` reads any path (including `/etc/hosts`, the vault keyfile).

Operational guards that remain regardless of mode: command timeouts (default
300s terminal / 300s python / 600s msf), full JSONL audit trail
(`exploit_audit.jsonl`) with SHA256 of generated code, OS-aware tooling
instructions (Windows attacker = Python-only exploits; Linux attacker = full
Kali arsenal including searchsploit/metasploit/hydra/crackmapexec/impacket).
`tools/command_analyzer.py` is **kept and load-bearing** — the tool-layer target-lock destination extraction (`terminal._target_lock_block`, `registry.py`) plus `exploit_agent/_common.py` and `swarm_bridge.py` import `analyze_command` / `_extract_destinations` / `analysis_payload` from it. It is no longer a *policy* gate on the attack path, but it is not dormant.

## Workspace Layout

- `reports/<run_id>/` — per-run artifacts (activity.jsonl, raw_nmap/, xml_nmap/, host_<ip>.md, network_summary.{md,html}, findings.csv, mcp_server.log, exploit_workspace/)
- `research_workspace/<mission_id>/` — Flow B mission data (research.db, evidence/, reports/)
- `exploit_workspace/<target_ip>/<attempt_id>/` — per-attempt exploit artifacts (exploit_script.py, terminal.log, python_run.log, msf_output.log, run_active_check.ps1) + `exploit_audit.jsonl`
- `swarm_workspace/` — created on demand by main.py

## Testing Notes

- ~80 test files, all in `tests/`. No fixtures for live Nmap; everything mocks subprocess / network.
- New safety-relevant code needs regression tests in `test_scope_gate.py`, `test_safety_reviewer.py`, `test_validation_utils.py` (or a new file if the surface is new).
- `pyproject.toml` configures pytest with `asyncio_mode = "auto"` and `testpaths = ["tests"]`. Coverage is configured for `tools/`, `main.py`, and `cli.py`.
- No linter / formatter / mypy / CI config is checked in. `pyproject.toml` has optional `ruff` (line-length 120, select E/F/W/I) and `mypy` configs. If adding `ruff` or `mypy`, keep config minimal so security-sensitive diffs stay readable.

## Things To Watch Out For

- **`config.yaml` exploit.permission defaults to `read_only`** — do not change this default. First-run users must opt in to `approve_only` / `full_access` explicitly.
- **The `BaseExceptionGroup` thing** — any new code that wraps MCP `stdio_client` / `streamable_http_client` / `ClientSession.initialize()` calls must use `_EXC_GROUP_CATCH` and the `_is_exception_group` / `_log_nested_exceptions` helpers, not `except Exception`.
- **`config.yaml` exploit.permission defaults to `full_access` (lab build).** The attack path is unrestricted; the one safety kept is the target-IP lock (above). Recon still uses `read_only` via `_resolve_exploit_permission`'s missing-key fallback. Do not re-add the removed attack-path gates (command-content/scope/pivot) without first ensuring the MCP allowlist target-lock covers the path you are de-restricting — the allowlist IS the lock.
- **Two mission/agent paths coexist** (`main.py` exploit engine vs `cli.py` legacy). When touching `scope_gate.py`, `risk_controller.py`, `mission.py`, `db.py` — those affect Flow B. When touching `tools/exploit_agent/`, `mcp_exploit_server.py`, `tools/swarm/`, `tools/mcp_tools/` — those affect Flow A. The two share `db.py` and `mission.py` schemas. **Do not edit `scope_gate.py`, `safety_reviewer.py`, or Flow B's `agent_loop.py`/`tool_router.py`/`risk_controller.py`/`mission.py`/`db.py` — recon safety depends on them.**
- **The exploit workspace is shared host filesystem state.** `mcp_exploit_server.py` and `tools/exploit_agent/` both write into `exploit_workspace/`. **Lab build: path-traversal protection was removed** — the operator box is unrestricted. The MCP tool layer enforces only the target-IP allowlist lock.
- **Ollama is required at runtime** — the model client is built at the top of `main.py`; if Ollama is unreachable, the boot will surface this as a `[WARN]` line on the recon path or a hard fail on the attack path.
- **No CI is configured.** Before opening a PR, run `python -m pytest tests/ -v` and verify README flags/config still match reality.
- **The README is the canonical user-facing doc**. When adding a CLI flag, MCP tool, or config key, update the relevant section there. The CHANGELOG is for user-visible releases; the v1.0.0 entry there is a good template.
- **`pyproject.toml` and `requirements.txt` are not fully synchronized** — both list runtime deps but `pyproject.toml` has additional dev extras (coverage, ruff). The `opencode.json` file configures an Ollama Cloud provider for the opencode.ai editor, not for the app itself.
- **`tools/mcp_tools/registry.py` is the central wiring point** for all exploit MCP tools — new tools must be registered there with the `@audit_tool` decorator and added to the tool list in `mcp_exploit_server.py`.
- **`tools/autonomous_orchestrator.py` is a separate campaign engine** from the swarm — it drives persistent multi-phase attacks with adaptive aggression levels, while the swarm is a parallel specialist-agent decomposition. They can be used independently.
