# NetAttackAI

<div align="center">

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![Status](https://img.shields.io/badge/status-beta-6f42c1?style=flat-square)
![License](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)
![Models](https://img.shields.io/badge/LLM-Ollama%20Cloud-22c55e?style=flat-square)
![MCP](https://img.shields.io/badge/MCP-1.27%2B-f97316?style=flat-square)
![WebUI](https://img.shields.io/badge/WebUI-React%20%2B%20Vite-06b6d4?style=flat-square)
![Skills](https://img.shields.io/badge/skills-146-a855f7?style=flat-square)
![Swarm](https://img.shields.io/badge/swarm-6%20agents-f59e0b?style=flat-square)
![Tests](https://img.shields.io/badge/tests-248%20mocked-10b981?style=flat-square)
![Models](https://img.shields.io/badge/peers-Kimi%20%7C%20DeepSeek%20%7C%20GLM%20%7C%20Minimax-3b82f6?style=flat-square)
![Transport](https://img.shields.io/badge/transport-stdio%20%7C%20http-8b5cf6?style=flat-square)
![Context](https://img.shields.io/badge/context-976K-ec4899?style=flat-square)
![Audit](https://img.shields.io/badge/audit-SHA256%20chain-ef4444?style=flat-square)
<img width="1725" height="912" alt="web" src="https://github.com/user-attachments/assets/45b6af2f-91e2-4eaf-a4cd-1352dbd42e0c" />


**An AI-driven, local-first penetration testing & bug bounty research agent. All in One Web Interface!**

Plan, reconnoiter, exploit, and report end to end against targets you own
or are explicitly authorized to assess. An autonomous operator that thinks in
kill-chains, not checklists: it scouts the surface, picks the attack, runs it,
proves the outcome with evidence, and writes the report. Powered by Ollama
LLMs, the Model Context Protocol, and a 146-skill advisory knowledge base.
Lab-only, target-locked, fully audited.

</div>

---

> [!WARNING]
> **Authorized use only.** Run NetAttackAI solely against networks and systems
> you own or have explicit written authorization to test, on a throwaway
> operator box.
>
> **Attack mode ships as `full_access`**: every action is auto-approved with
> no command-content or scope inspection. The operator-box filesystem is
> unrestricted (`write_python_file` / `read_workspace_file` reach any path).
> The single remaining attack-path safety is the **target-IP allowlist lock**,
> a destination guard that refuses off-target hosts. It is not authorization
> proof, not a sandbox, and a statically-constructed or DNS-resolved
> destination may evade it. **Recon keeps its full scope-gated safety model.**
>
> See [Safety model](#-safety-model) and [`docs/safety-model.md`](docs/safety-model.md).

---

## What it is

A coupled assessment engine, not an nmap wrapper with a chatbot on top:

- **Assessment controller** (`main.py` / `app.py`): opens an MCP exploit
  session, dispatches tool calls, streams live events to a CLI or browser.
- **Defensive MCP server** (`mcp_server.py`): scope-gated Nmap, sanitized
  vulnerability search, NVD CVE lookup. Read-only by design.
- **Permissive exploit MCP server** (`mcp_exploit_server.py`, port 8001):
  terminal, Python write/run, searchsploit, Metasploit, msfvenom, impacket
  lateral movement, credential dumping, kerberoasting, web scanning, hash
  cracking. Gated by the target-IP allowlist lock at the tool layer.
- **Multi-agent swarm** (`tools/swarm/`): 6 specialist agents (recon, vuln,
  exploit, post-exploit, critic, reflection) with a shared blackboard.
- **Autonomous attack orchestrator** (`tools/autonomous_orchestrator.py`):
  persistent multi-phase campaigns with adaptive aggression, vuln chaining,
  and auto-retry.
- **Runtime skills system**: 146 advisory `SKILL.md` files indexed,
  deterministically + semantically selected, injected into LLM context per
  phase. Advisory only, never grants execution authority.
- **Bundled WebUI** (React + Vite + TypeScript) served by a loopback-only
  REST + WebSocket API daemon.

For the full architecture, Flow A/B split, and module map, see
[`docs/architecture.md`](docs/architecture.md) and
[`docs/module-guide.md`](docs/module-guide.md).

## Highlights

- **Cloud-first, local-capable.** Default model path is Ollama Cloud
  (`glm-5.2:cloud`, 976K context). Swap `ollama.host` to a local daemon and
  the same code path runs against it. Embeddings stay local via
  `nomic-embed-text`.
- **Multi-model war room.** Ask Kimi K2.6, DeepSeek V4 Pro/Flash, GLM-5.2,
  and Minimax M3 for advisory ideas mid-run. Peers have no tool schemas and
  cannot execute commands.
- **146-skill advisory brain.** Each `SKILL.md` carries NIST CSF + MITRE
  ATT&CK metadata. Selected deterministically + semantically, re-selected
  mid-run as new services/CVEs surface, with cross-mission Bayesian feedback.
- **Hypothesis-driven outcome judgment.** Every executed check produces
  structured observations; `OutcomeJudge` evaluates them against task
  criteria and persists a terminal `confirmed` / `refuted` / `exhausted`
  verdict. Execution success ≠ evidential success.
- **Capability model + task graph.** Every attack module declares what it
  *requires* and *produces*; `find_producers()` resolves missing prerequisites
  dynamically, `AttackPlan` exposes a real DAG (ready/blocked steps, priority,
  per-step status/hypothesis), and a shared failure taxonomy
  (`tools/failure_taxonomy.py`) decides retry-with-params vs. create-prereq vs.
  switch-capability vs. stop. The agent can inspect its own state and drive the
  graph through six new MCP tools (`get_assessment_state`, `query_capabilities`,
  `get_capability_details`, `get_evidence`, `record_hypothesis`, `update_task`)
  — decisions land in an append-only `decision_log.jsonl` per run.
- **Tamper-evident audit chain.** Every target-touching action lands in
  `exploit_workspace/<ip>/exploit_audit.jsonl` with SHA256 of generated code.
  Chain validity is verified and surfaced in the WebUI.
- **Target-aware OPSEC.** Pacing, UA rotation, DNS-over-HTTPS, and
  quiet-command hints auto-disable for private/local IPs and engage for
  public-routable targets. Advisory-only, never a gate.
- **Domain targeting.** Pass `--target example.com`; the agent resolves it,
  expands subdomains (crt.sh + DNS bruteforce + subfinder/amass), and
  auto-authorizes each discovered host through the allowlist lock.
- **Long-session mode.** Opt-in multi-hour runs send the model's real context
  window to Ollama, bound each LLM call with an httpx timeout, and checkpoint
  compacted state for crash recovery.
- **Interactive Attack Graph.** A dedicated WebUI page (`/graph`) renders each
  run's Attack Graph v2 as a pan/zoom/reactable React Flow canvas — filter by
  node type/status/confidence, search, expand neighborhoods (+1/+2 hops),
  find bounded attack paths, inspect node provenance, and surface merge
  conflicts, with live refresh while the run is active. Read-only, scoped per
  run, gated by `api.graph_route`.
- **Eval harness.** Benchmark regression against target labs with JSON/Markdown/HTML
  reports under `reports/eval/<run_id>/`.
- **248-test suite, all mocked.** No live Nmap, no live network: every test
  mocks subprocess/network and runs offline.

## Quick start

### 1. Prerequisites

- **Python 3.11+** (the `--doctor` check rejects 3.10)
- `nmap` on `PATH` (or set `nmap.path` in `config.yaml`)
- An Ollama endpoint: **cloud is the default** (`https://api.ollama.com`,
  needs `OLLAMA_API_KEY`) or a local daemon (`ollama.host:
  http://localhost:11434`)
- Optional, Linux full arsenal: Metasploit, searchsploit, impacket, tmux
- For the WebUI: Node.js + npm (only on first `--web` run)
- **ChatGPT provider (optional):** [bun](https://bun.sh) ≥ 1.3.11 to run the
  vendored `oauth/` proxy from source (only when `models.provider:
  chatgpt`). A local Ollama is still required for embeddings even under the
  ChatGPT provider. See [docs/providers.md](docs/providers.md).

### 2. Install

#### Windows — one-click (recommended for new users)

```powershell
# Double-click install.bat in Explorer, or from PowerShell:
.\install.bat          # walks you through Python/Node/Nmap/Ollama + venv + WebUI + --doctor
.\START.bat            # after install: double-click to launch (WebUI at http://127.0.0.1:8765)
```

`install.bat` is the easy path: it checks for Python 3.11+, Node.js, Nmap, and
Ollama (offers to install any missing tool via `winget` when you approve),
creates `.venv`, installs Python deps, builds the WebUI (`webui/dist/`),
starts Ollama and pulls `glm-5.2:cloud` + `nomic-embed-text`, guides you
through `OLLAMA_API_KEY`, runs `python main.py --doctor`, and installs the
`natai` launcher to `%USERPROFILE%\.local\bin` (added to your user PATH).
Safe to re-run any time. Options: `install.bat --check` (audit only),
`install.bat --yes` (non-interactive), `install.bat --uninstall` (remove
`natai`), `install.bat --help`. `START.bat` is a double-click launcher that
passes extra args through (e.g. `START.bat --menu`, `START.bat --help`).

#### Windows — manual

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

#### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
./scripts/setup-linux.sh        # one-shot bootstrap: venv + deps + doctor
# or: ./install.sh              # full bootstrap (OS prereqs + Ollama + venv + natai)
```

Linux nmap `-O`/`-sS` need root: set `nmap.sudo: true` (uses `sudo -n`) or run
as root; otherwise `nmap.priv_fallback` (default true) auto-downgrades.

**ChatGPT provider one-time setup** (only if you'll set
`models.provider: chatgpt`):

```bash
cd openai-oauth && bun install && cd ..   # bun@1.3.11; makes ./src/cli.ts runnable
```

`install.bat` / `install.sh` / `scripts/setup-linux.sh` run this best-effort
when `bun` is on PATH; it never aborts the install if bun is missing, since
ChatGPT is opt-in. No global Codex CLI install is required.

### 3. Configure API keys (before `--doctor`)

The default cloud path requires `OLLAMA_API_KEY` or the doctor's Ollama
reachability check will 401. Keys are read from **process environment
variables** or `secr.json`; there is no `.env` auto-load. Set them with:

```bash
python main.py --setup-api-keys      # prompts + writes secr.json (gitignored)
```

| Var | Purpose |
|-----|---------|
| `OLLAMA_API_KEY` | **Required** for the default Ollama Cloud path |
| `NVD_API_KEY` | Raises NVD CVE lookup rate limit |
| `GITHUB_TOKEN` | Raises `cve_to_poc` GitHub Search API limit 60→5000/hr |
| `SERPAPI_API_KEY` | Optional fallback web research provider |
| `NETATTACKAI_API_TOKEN` | Override the auto-generated WebUI bearer token |

`.env.example` documents the same vars; copy it to `.env` for your own
shell-load workflow, but the app itself does not read `.env`.

> **ChatGPT provider** (opt-in, `models.provider: chatgpt`) does **not** use an
> env API key. It authenticates via a browser "Sign in with ChatGPT" OAuth flow
> whose tokens live in `~/.codex/auth.json` (managed by the vendored
> `oauth/` proxy). They are never copied into `config.yaml` or logged.
> Run `python main.py` → choose **ChatGPT** → **Sign in with ChatGPT**, or see
> [docs/providers.md](docs/providers.md).

### 4. Verify

```bash
python main.py --doctor          # env check (Python/nmap/Ollama/models/config; +ChatGPT when provider=chatgpt)
python main.py --self-test       # safe localhost smoke test
python main.py                   # WebUI daemon (default no-args; opens browser)
python main.py --menu            # terminal interactive menu (legacy)
```

`--doctor` exits 0 when all checks pass. Cloud models are verified by running
a 1-token generation (the programmatic `ollama run`); local models report a
`ollama pull <spec>` hint if missing. When `models.provider: chatgpt`, the
doctor adds a ChatGPT block: openai-oauth source found, runtime (bun/node) on
PATH, OAuth login present, proxy running, and `/v1/models` reachable. It never
displays token contents.

## Choose an interface

| Interface | Start | Notes |
|---|---|---|
| **WebUI** | `python main.py` | Default. Builds `webui/dist/` on first run (needs Node/npm), opens `http://127.0.0.1:8765` |
| **CLI menu** | `python main.py --menu` | Guided questionary flow; no extra deps |
| **CLI direct** | `python main.py --target <ip> --mode recon\|attack\|fast` | Flags below. `fast` runs bounded parallel recon first, then gives the completed context to the AI agent. |
| **API only** | `python main.py --demon` | Daemon without the SPA |

WebUI: bearer token auto-generated into `.webui_secret_key` (gitignored) or
set `NETATTACKAI_API_TOKEN`. Loopback-only, one active run at a time (HTTP
409 on conflict). Docs at `http://127.0.0.1:8765/docs`. Full SPA reference in
[`docs/webui.md`](docs/webui.md) and [`docs/api.md`](docs/api.md). The WebUI
includes an interactive **Attack Graph** page at `/graph` (requires
`api.graph_route: true` in `config.yaml`) — see
[`docs/webui.md`](docs/webui.md#attack-graph-page) and the graph routes in
[`docs/api.md`](docs/api.md#graph-explorer-routes).

### Choose an AI provider

The default is **Ollama** (cloud or local daemon). To use **ChatGPT** instead,
pick it in the interactive menu (`python main.py --menu` → *Select AI
provider* → *ChatGPT* → *Sign in with ChatGPT*) or the WebUI's System page, or
set `models.provider: chatgpt` in `config.yaml`. Both providers share the same
`ModelClient`/`ModelRouter` surface, so every run path (CLI, WebUI, swarm,
autonomous) works unchanged; embeddings always stay on Ollama. Full setup,
proxy lifecycle, and security notes in [`docs/providers.md`](docs/providers.md).

### CLI showcase

```bash
# Recon against an allowed target (propose-only, safe)
python main.py --target 10.0.0.50 --mode recon --recon-first

# Attack with a preset goal
python main.py --target 10.0.0.50 --mode attack --goal backdoor

# Full-power swarm run
python main.py --target 10.0.0.50 --mode attack --swarm --critic \
    --reflection --adaptive-exploits

# Multi-hour attack mode (raises context window, budgets, checkpoints)
python main.py --target 10.0.0.50 --mode attack --long-session

# Domain targeting — resolve, expand subdomains, attack the surface
python main.py --target example.com --mode attack

# Engine advisory MCP server (read-only surface for foreign AI assistants)
python mcp_engine_server.py
```

Notable flags: `--model <alias>`, `--mcp-transport stdio|http`,
`--parallel-swarm`, `--multi-model-consult`, `--ultrathink`, `--skills on|off|hints|lookup`,
`--skills-list`, `--eval`, `--ctf` (CTF autopilot with goal-completion detection),
`--resume <run_id>`, `--yes` (skip confirm gate).
Run `python main.py --help` for the full list.

### Legacy research CLI (Flow B, SQLite-backed, frozen)

> **Flow B is frozen** — canonical code lives in `legacy/` (see `legacy/README.md`). Root shims
> (`cli.py`, `agent_loop.py`, `mission.py`, …) remain for one release and emit `DeprecationWarning`.
> New code must use Flow A (`main.py` / `app.py` → `tools/exploit_agent/` / `tools/mcp_tools/`).
> Active engine is Flow A; Flow B is a frozen SQLite reference loop.

```bash
python -m legacy.cli init-mission --config mission.yaml  # canonical
python cli.py next-task                                   # shim (deprecated)
python cli.py run-task T-00001
python cli.py list-findings
python cli.py generate-report F-00001
python cli.py status
```

Flow B is the database-driven, scope-gated research loop. See
[`docs/runtime-flows.md`](docs/runtime-flows.md) and [`legacy/README.md`](legacy/README.md).

## Safety model

This is a **lab-only build**. The attack path is **unrestricted but
target-locked**.

| Context | Effective permission |
|---|---|
| `--mode recon` | Always `read_only`: gathers and proposes, no offensive execution |
| `--mode attack` | Uses `exploit.permission` from `config.yaml` |
| Shipped attack default | **`full_access`**: auto-approves every action, no content/scope inspection |
| Safer attack posture | `approve_only`: prints an approval banner per action |

**The one attack-mode safety: the target-IP allowlist lock**, enforced at the
MCP tool layer (`tools/mcp_shared._allowed_target_list` +
`tools/mcp_tools/terminal._target_lock_block`), not in policy. It unions
`EXPLOIT_TARGET` (the runtime `--target`) with `exploit.allowed_targets`,
plus `EXPLOIT_TARGET_IP` / `EXPLOIT_TARGET_DOMAIN` /
`EXPLOIT_DISCOVERED_TARGETS` for domain targeting. Every destination in every
command (URL authorities, `/dev/tcp` hosts, LHOST/RHOST, scanner verbs, bare
IPs, hostnames) is extracted and refused if not in the allowlist. Supports
domains + `*.wildcard` + CIDR. Interactive target entry persists to
`exploit.allowed_targets`; domain enumeration auto-authorizes discovered
hosts; callback/C2 hosts must be added explicitly.

**What the lock is not:** authorization proof, a sandbox, or a guarantee that
a dynamically-constructed or DNS-resolved destination is caught. It is a
destination guard. Recon keeps its full safety (post-session
`SafetyReviewer`, READ_ONLY propose-only path, goal-menu SAFE/GATED
narrowing, defensive scope-gated `mcp_server.py`).

**Operational guards that remain regardless of mode:** command timeouts (300s
terminal / 300s python / 600s msf), full JSONL audit trail
(`exploit_workspace/<ip>/exploit_audit.jsonl`) with SHA256 of generated code,
OS-aware tooling (Windows attacker = Python-only; Linux = full Kali arsenal).

**OPSEC is advisory-only, never a gate.** Pacing, UA rotation, DoH, and
quiet-command hints auto-disable for private/local target IPs and engage for
public-routable targets. `is_quiet_blocked` / `noise_budget` stay dormant.

Full layered model: [`docs/safety-model.md`](docs/safety-model.md).

## Configuration

All runtime behavior lives in **`config.yaml`** — validated by `tools/config_manager.py::CONFIG_SCHEMA` (source of truth; `config.yaml` and schema are proven in sync by `tests/test_config_manager.py::test_config_yaml_keys_subset_of_schema`). Every top-level key is documented below; see `docs/config-reference.md` for per-key types, defaults, and consumers.

> **Stealth vs OPSEC:** `stealth` is legacy/inert UI-only (kept for compat; `tools/opsec.py` is canonical). `opsec` is the active detection-evasion block (pacing/jitter/UA-rotation/DoH/quiet-commands, target-aware via `local_targets_off`). Do not use `stealth` for new config — use `opsec`.

| Key | Purpose |
|-----|---------|
| `ollama` | host, model (`glm-5.2:cloud`), `embed_host` (local embeddings), `api_key_env` |
| `models` | `provider` (`ollama` default \| `chatgpt`), registry (kimi/deepseek/deepseek_flash/glm/minimax), `default_alias`, `roles` per-role routing, `info` context windows |
| `models.roles` | per-role model routing (`planner`/`executor`/`interpreter`/`code_generator`/`critic`/`summarizer`); empty string = `models.default_alias`. Consumed by `ModelRouter.get_client_for_role` |
| `chatgpt` | opt-in ChatGPT provider: `base_url` (loopback `127.0.0.1:10531`), `auto_start`, `local_repo`, `runtime`, `default_model`, `context_window`, discovery/login/proxy timeouts |
| `mcp` | exploit MCP transport: `default_transport` (`stdio`\|`http`), `http_host`/`http_port` (loopback-only) |
| `engine_mcp` | advisory MCP server for foreign AI assistants (skill search/CVE lookup/run history): `enabled`, `host`, `port` (read-only, no target touch) |
| `nmap` | Linux-friendly nmap invocation: `path`, `sudo` (`sudo -n`), `priv_fallback` (auto-downgrade `-sS`/`-O`) |
| `exploit` | attack path: `permission` (`read_only`\|`approve_only`\|`full_access` — **strict**, typo fails validation), `attack_mode`, timeouts/budgets, `allowed_targets`/`require_explicit_allowlist` (target-IP lock), AD/Kerberos suite, MSF recipes, listeners, `max_pivot_depth`, workspaces, `attacker_os` |
| `stealth` | **LEGACY** inert/UI-only; kept for compat. Use `opsec` instead. Keys: `rotate_ua`, `dns_over_https`, `doh_provider` |
| `opsec` | target-aware OPSEC (pacing `min_gap_seconds`/`jitter_seconds`, `ua_rotation`, `doh`/`doh_provider`, `rate_per_minute`, `quiet_command_patterns`, `noise_budget`, `local_targets_off`/`local_cidrs`/`public_autonomy`) |
| `cve_lookup` | NVD CVE lookup: `enabled`, `max_results`, `rate_limit_seconds`, `circuit_failure_threshold`/`circuit_recovery_timeout`, `search_rate_limit_per_minute`, `epss_enabled`/`kev_enabled` (lab default `true`), `kev_cache_ttl_seconds`/`kev_cache_path`, `github.token_env` (`GITHUB_TOKEN`) |
| `threat_intel` | continuous OSV.dev + GHSA + CISA KEV feed (`search_threat_intel`): `enabled` (lab `true`), `cache_dir`/`cache_ttl_seconds`, `sources` (osv/ghsa/kev/exploitdb_rss), `max_results`, `github_token_env` (shared `GITHUB_TOKEN`) |
| `research` | web research: `enabled`, `provider`/`fallback_provider` (`ollama`\|`serpapi`\|`stdlib`), timeouts, caches, `ollama`/`serpapi`/`assistant` sub-blocks |
| `swarm` | multi-agent swarm: `enabled`, `agents`, `max_parallel_agents`, `parallel_enabled`/`per_phase_concurrency`/`exploit_parallel`/`subagent_timeout_seconds`, `negotiation_rounds` (0 legacy one-shot, 2 lab) |
| `witness` | advisory audit-stream watcher (`enabled` lab `true`/schema `false`, `log_path`, `poll_interval_seconds`, `escalate_to_event_broker`, `max_flags_per_signal_per_minute`, `dos_*`) — flags anomalies, never blocks |
| `autonomous` | orchestrator Phase 2: `persistence_phase`, `checkpoint_every`, `adaptive_replan`, `max_cycles`, `max_pivot_depth`, plus Phase 5 preflight `dedup_targets`/`skip_non_routable`/`hard_target_max_rounds` |
| `orchestrator` | `semantic_memory` (cross-mission lesson consumer; lab `true`, matching `memory.semantic_enabled`) |
| `recon` | recon coverage & depth: `extended_enumerators`, `udp_top_ports`, `shodan_api_key`, `preflight_probe`/`preflight_ports`/`preflight_timeout_ms`, `max_retries`/`retry_delay`/`timeout_seconds`, `domain_resolution` (subdomain sources, AXFR, WHOIS), `subdomain_enum`/`vhost_discovery`/`waf_fingerprint`/`asn_whois`/`cloud_metadata_probe`/`snmp_enum`/`dns_zone_transfer`, `fast` (parallel recon preset) |
| `memory` | learning stores: `semantic_enabled`, `embedding_model` (`nomic-embed-text`), `cross_mission_learning`, `attack_memory_enabled`/`attack_memory_max_context_chars`, `experience_min_samples`/`experience_time_decay_days` |
| `reasoning` | agent reasoning: `chain_of_thought`, `reflection_every_n_actions`, `critic_enabled`, `observer_mode` (`heuristic`\|`llm`\|`hybrid`), `ultrathink`/`ultrathink_reflection_interval`, `llm_reflection`, `peer_consult_on_failure_threshold` |
| `outcome_judgment` | evidence-grounded verdicts: `max_inconclusive_attempts`, `confirmation_threshold`/`refutation_threshold`, `min_evidence_references`, `flow_a` (Flow A judge), `peer_review` (cross-model grading) |
| `poc_verification` | self-healing PoC verification: `enabled`, `docker_image`, `compile_timeout_seconds`, `max_retries`, `docker_network`/`docker_read_only`/`docker_memory` |
| `replay_simulator` | pre-commit attack-plan critique (`replay_simulate`): `enabled` |
| `adaptive_exploits` | exploit mutation: `enabled`, `max_mutations`, `mutation_strategies` |
| `multi_model` | peer-model consultation (advisory): `enabled` (lab `true`/schema `false`), `consult_aliases`, `max_consultations`, `max_question_chars`/`max_answer_chars` |
| `skills` | runtime skill pipeline: `enabled`, `roots`, `default_enabled`, `include_tags`/`exclude_names`, `maybe_enabled`, `allow_model_lookup`, `inject_startup_context`, budgets (`max_active_skills`/`max_chars_per_skill`/`max_total_chars`...), weights, `reselect_*`, `swarm_inject`, `feedback_*`, `semantic_*`, `diversity_penalty`, `include_metadata`/`allow_reference_listing` |
| `plugins` | out-of-tree plugin enable/disable: `enabled`/`disabled`, `search_paths`, `entry_points` |
| `webhook_notify` | outbound Slack/Discord run-status notifications: `enabled` (lab `true`), `url` (secret), `events`, `timeout_seconds`, `max_retries`, `backoff_seconds`, `max_payload_chars` |
| `mitre` | MITRE ATT&CK Navigator export: `enabled` (lab `true`), `technique_map`, `navigator_output_dir`, `include_skill_tags` |
| `ticketing` | remediation ticket generation (Jira/GitHub): `enabled` (lab `true`), `provider`, `base_url`, `token_env` (`TICKETING_TOKEN`), `project_key`, `max_retries`, `backoff_seconds` |
| `api` | WebUI daemon: `enabled`, `host`/`port` (loopback-only), `token_file`, `allowed_origins`, `event_buffer_size`, `shutdown_timeout_seconds`, `serve_webui`, `graph_route`, `max_concurrent_runs` (D3: lab 3/schema 1), `multi_operator` (D4) |
| `ics` | D8 ICS write-side modules: `allow_write` (default **false**: read-only ICS enum) + `destructive_ics` — **both must be true** plus `@require_allowlist` to run `ModbusWriteCoil`/`ModbusWriteRegister`/`S7PlcStop`/`S7PlcStart` (PHYSICAL-DAMAGE RISK) |
| `long_session` | multi-hour mode: `enabled`, `request_timeout_seconds`, `swarm_session_timeout_minutes`, `attack_max_rounds`/`attack_max_commands`/`attack_max_duration_minutes`, `persist_messages` |
| `eval` | eval/benchmark harness: `enabled`, `output_dir`, `max_rounds`, `write_markdown`/`write_html` |
| `caldera` | Caldera adversary emulation plugin: `enabled` (lab `true`), `url`, `api_key_env` (`CALDERA_API_KEY`) |
| `agent` | capability-upgrade toggles + budgets: `task_graph_enabled`, `capability_discovery_enabled`, `state_tools_enabled`, `planner_hints_enabled`, `decision_log_enabled`, `reflection_enabled`, `max_retries_per_task`, `max_actions` (0 = legacy exploit budgets), `generated_code_repair_attempts` |

Mission scope (allowed/disallowed assets, forbidden actions, risk profiles)
for Flow B lives in **`mission.yaml`**. Three risk profiles:
`low_noise_non_destructive`, `standard_authorized`, `high_authorized_testing`.

Hard-blocked actions regardless of config: `denial_of_service`,
`destructive_exploit`, `social_engineering`, `physical_attack`, `malware`,
`credential_theft` (see `scope_gate.py:_HARD_FORBIDDEN_ACTIONS`).

## Testing

```bash
python -m pytest tests/ -v                              # full suite (248 files)
python -m pytest tests/test_scope_gate.py -v            # single file
python -m pytest tests/test_recon_pipeline.py::TestClass::test_method  # one test
python -m pytest tests/ -v -k "scope"                   # by keyword
python -m pytest --cov=tools --cov=main --cov=cli # coverage
```

All tests mock subprocess/network: no live Nmap, no live network. pytest
config: `asyncio_mode = "auto"`, `testpaths = ["tests"]`.

### CI (GitHub Actions)

CI runs on every push and pull request (concurrency-cancelled, no secrets
required, nothing touches the network):

- **Python tests** on Python 3.11, 3.12, and 3.13 — the full mocked/offline
  suite (`python -m pytest tests/ -v`).
- **Coverage** on Python 3.12: terminal report + `coverage.xml` artifact.
- **Ruff** repo-wide: `ruff check .` and `ruff format --check .` (0 errors, 0 format diffs).
  Per-file-ignores document intentional patterns: `tools/mcp_tools/*.py` star-import helpers,
  `tools/exploit_agent/__init__.py` facade re-exports, `skills/**/*.py` try/except availability checks,
  `main.py`/`tools/exploit_agent/loop.py` late imports after `ui` bootstrap.
- **mypy** repo-wide: `mypy --follow-imports=skip tools` (216 files, 0 errors with current
  `disable_error_code` masks; without masks 298 errors — incremental per-family re-enable tracked in
  `pyproject.toml:136` comment). No scoped core — whole `tools/` is checked.
- **Package build**: `python -m build` + `python -m twine check dist/*`.
- **WebUI**: `npm ci`, `npm run build` (tsc + vite), `npm run test` (vitest).

Security automation: CodeQL (Python + JavaScript/TypeScript) on push/PR/weekly,
GitHub dependency review on pull requests, and Dependabot for pip / GitHub
Actions / npm (weekly, grouped).

Before opening a PR, run the same checks locally:

```bash
python -m pip install -e ".[dev]"
python -m pytest tests/ -v
ruff check .
ruff format --check .
mypy --follow-imports=skip tools
cd webui && npm ci && npm run build && npm run test
```

and verify README flags/config still match reality.

## Plugins

Out-of-tree extensions managed by `tools/plugins.py` (pure stdlib). A plugin
can contribute an attack module, MCP tools, a skills directory, and a config
section. Plugins are disabled by default; enable via `config plugins.enabled`.
A reference plugin lives at `plugins/example_recon_report/`. See
[`docs/plugin-development.md`](docs/plugin-development.md).

Shipped plugins (lab build: enabled by default; enabling requires both
`plugins.enabled` and the API key/token in `config.yaml`):

- **`shodan_recon`**: passive Shodan OSINT (`shodan_host_lookup`,
  `shodan_search` MCP tools). Advisory-only, never touches the target.
  Requires `recon.shodan_api_key`; MCP tool returns `BLOCKED:` when unset.
  Pure stdlib (urllib).
- **`github_dorks`**: authorized-target code-leak discovery
  (`search_github_dorks` MCP tool). Runs curated dorks against a target
  org's public GitHub repos. Requires `GITHUB_TOKEN`
  (`cve_lookup.github.token_env`); MCP tool returns `BLOCKED:` when unset.
  Advisory-only.

## Documentation

Engineering docs in [`docs/`](docs/):

**Operators**
- [Getting Started](docs/getting-started.md): setup, common commands, dev loop
- [Model Providers](docs/providers.md): Ollama (default) + ChatGPT (openai-oauth), proxy/login lifecycle
- [Safety Model](docs/safety-model.md): scope, risk, permission, audit
- [WebUI](docs/webui.md): the bundled React/Vite SPA
- [WebUI API](docs/api.md): `/api/v1` REST + WebSocket reference

**Integrators**
- [Runtime Skills](docs/skills.md): advisory skill pipeline
- [Plugin Development](docs/plugin-development.md): out-of-tree plugins
- [Attack Modules](docs/attack-modules.md): pre-packaged exploit logic + capability metadata
- [Capability Upgrade Design](docs/capability-upgrade-design.md): task graph, hypotheses, failure taxonomy, assessment state (the 28-section upgrade map)


**Contributors**
- [Architecture](docs/architecture.md): system shape, entry points, persistence
- [Runtime Flows](docs/runtime-flows.md): recon, execution, exploitation, swarm, MCP
- [Module Guide](docs/module-guide.md): responsibilities of top-level modules
- [Extension Guide](docs/extension-guide.md): exact edit points for in-tree changes
- [Testing Guide](docs/testing-guide.md): test layout, focused commands
- [`AGENTS.md`](AGENTS.md): compact agent guide with non-obvious rules
- [`CLAUDE.md`](CLAUDE.md): architecture/safety depth for AI coding agents

## Contributing

1. Read [`AGENTS.md`](AGENTS.md) first: it lists the non-obvious rules you
   will otherwise break.
2. Run `python main.py --doctor` and `python main.py --self-test` after
   safety-sensitive changes.
3. Run the CI checks locally before opening a PR — see [CI (GitHub Actions)](#ci-github-actions) above.
4. Do not edit Flow B safety files (`scope_gate.py`, `safety_reviewer.py`,
   Flow B's `agent_loop.py`/`tool_router.py`/`risk_controller.py`/`mission.py`/
   `db.py`): recon safety depends on them.
5. New exploit MCP tools: single-source registration — add `@audit_tool` (or `@require_allowlist()` for target-touching) in `tools/mcp_tools/<family>.py` only; `mcp_exploit_server.py` auto-discovers every `register_*_tools` via `tools/mcp_tools/registry.py:collect_tools()` (pkgutil + AST validation, fails CI if decorator missing). No manual list edit in `mcp_exploit_server.py`.
6. When adding a CLI flag, MCP tool, or config key, update the relevant
   README section.

## License

NetAttackAI, Copyright (c) 2026 NetAttackAI contributors.

Licensed under the **Apache License 2.0**. See
[`LICENSE`](LICENSE) for the full text.
