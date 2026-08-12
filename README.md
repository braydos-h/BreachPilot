# NetAttackAI

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![Status](https://img.shields.io/badge/status-beta-6f42c1?style=flat-square)
![License](https://img.shields.io/badge/license-GPL--3.0--only-blue?style=flat-square)
![Models](https://img.shields.io/badge/LLM-Ollama%20Cloud-22c55e?style=flat-square)
![MCP](https://img.shields.io/badge/MCP-1.27%2B-f97316?style=flat-square)
![WebUI](https://img.shields.io/badge/WebUI-React%20%2B%20Vite-06b6d4?style=flat-square)

**An AI-driven, local-first penetration testing & bug bounty research agent.**

An autonomous operator-grade attack engine that plans, reconnoiters, exploits,
and reports against targets you own or are explicitly authorized to assess —
powered by Ollama LLMs, the Model Context Protocol, and a 140-skill advisory
knowledge base. Lab-only, target-locked, fully audited.

</div>

---

> [!WARNING]
> **Authorized use only.** Run NetAttackAI solely against networks and systems
> you own or have explicit written authorization to test, on a throwaway
> operator box. The attack path is **unrestricted but target-locked** — the
> single remaining safety is the target-IP allowlist. Recon retains its full
> scope-gated safety model. See [Safety Model](#-safety-model).

---

## Table of Contents

- [What it is](#-what-it-is)
- [Highlights](#-highlights)
- [Quick start](#-quick-start)
- [CLI showcase](#-cli-showcase)
- [The WebUI](#-the-webui)
- [Architecture](#-architecture)
- [MCP tool surface](#-mcp-tool-surface)
- [Runtime skills](#-runtime-skills)
- [Configuration](#-configuration)
- [Safety model](#-safety-model)
- [Plugins](#-plugins)
- [Testing](#-testing)
- [Project layout](#-project-layout)
- [Documentation](#-documentation)
- [Contributing](#-contributing)
- [License](#-license)

## What it is

NetAttackAI is **not** an nmap wrapper with a chatbot on top. It is a coupled
assessment engine:

- An **assessment controller** (`main.py` / `app.py`) that opens an MCP exploit
  session, dispatches tool calls, and streams live events to a CLI or browser.
- A **defensive MCP server** (`mcp_server.py`) — scope-gated Nmap, sanitized
  vulnerability search, NVD CVE lookup. Read-only by design.
- A **permissive exploit MCP server** (`mcp_exploit_server.py`, port 8001) —
  terminal, Python write/run, searchsploit, Metasploit, msfvenom, impacket
  lateral movement, credential dumping, kerberoasting, web scanning, hash
  cracking. Gated by the **target-IP allowlist lock** at the tool layer.
- A **multi-agent swarm** (`tools/swarm/`) — 6 specialist agents (recon, vuln,
  exploit, post-exploit, critic, reflection) with a shared blackboard.
- An **autonomous attack orchestrator** (`tools/autonomous_orchestrator.py`)
  that drives persistent multi-phase campaigns with adaptive aggression,
  vuln chaining, and auto-retry on failure.
- A **runtime skills system** — 140 advisory `SKILL.md` files indexed,
  deterministically selected, and injected into the LLM context per phase.
- A **bundled WebUI** (React + Vite + TypeScript) served by a loopback-only
  REST + WebSocket API daemon.

## Highlights

- **Local-first, cloud-capable.** Default model path is Ollama Cloud
  (`glm-5.2:cloud`, 976K context). Override `ollama.host` to point at a local
  daemon and the same code path runs against it. Embeddings stay local via
  `nomic-embed-text`.
- **Multi-model peer consultation.** Ask Kimi K2.6, DeepSeek V4 Pro/Flash,
  GLM-5.2, and Minimax M3 for advisory ideas mid-run — peers have no tool
  schemas and cannot execute commands.
- **140-skill advisory knowledge base.** Each `SKILL.md` carries YAML
  frontmatter (NIST CSF, MITRE ATT&CK, tags) + a sanitized markdown body.
  Selected deterministically + semantically, re-selected mid-run as new
  services/CVEs appear, with cross-mission Bayesian feedback.
- **Hypothesis-driven outcome judgment.** Every executed check produces
  structured observations; `OutcomeJudge` evaluates them against task
  criteria/stop conditions and persists a terminal `confirmed` / `refuted` /
  `exhausted` verdict. Execution success ≠ evidential success.
- **Tamper-evident audit chain.** Every target-touching action lands in
  `exploit_workspace/<ip>/exploit_audit.jsonl` with SHA256 of generated code.
  Chain validity is verified and surfaced in the WebUI.
- **Target-aware OPSEC.** Pacing, UA rotation, DNS-over-HTTPS, and quiet-command
  hints auto-disable for private/local target IPs (RFC1918/loopback/etc.) and
  engage for public-routable targets. Advisory-only — never a gate.
- **Domain targeting (Phase 4).** Pass `--target example.com` and the agent
  resolves it, carries both domain and IP, expands subdomains (crt.sh + DNS
  bruteforce + subfinder/amass), and auto-authorizes each discovered host
  through the allowlist lock.
- **Long-session mode.** Opt-in multi-hour attack runs send the model's real
  context window to Ollama, bound each LLM call with an httpx timeout, and
  checkpoint compacted conversation state for crash recovery.
- **Eval harness.** Benchmark runs against target labs with JSON/Markdown/HTML
  reports under `reports/eval/<run_id>/`.
- **180-test suite, all mocked.** No live Nmap, no live network — every test
  mocks subprocess/network and runs offline.

## Quick start

### Prerequisites

- Python 3.10+ (3.11+ recommended)
- `nmap` on `PATH` (or set `nmap.path` in `config.yaml`)
- An Ollama endpoint — cloud (default, needs `OLLAMA_API_KEY`) or local
  (`ollama.host: http://localhost:11434`)
- Optional: Metasploit, searchsploit, impacket, tmux (Linux full arsenal)
- For the WebUI: Node.js + npm (only on first `--web` run)

### Install

```powershell
# Windows PowerShell (this repo's primary dev platform)
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python main.py --doctor          # env check (Python/nmap/Ollama/config)
python main.py --self-test      # safe localhost smoke test
python main.py                  # interactive menu (default no-args)
```

```bash
# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
./scripts/setup-linux.sh        # one-shot bootstrap: venv + deps + doctor
```

Linux nmap `-O`/`-sS` need root: set `nmap.sudo: true` (uses `sudo -n`) or run
as root — otherwise `nmap.priv_fallback` (default true) auto-downgrades.

### API keys

Copy `.env.example` to `.env` and fill in what you have. Keys are optional
but recommended:

| Var | Purpose |
|-----|---------|
| `OLLAMA_API_KEY` | Required for Ollama Cloud path (default) |
| `NVD_API_KEY` | Raises NVD CVE lookup rate limit |
| `GITHUB_TOKEN` | Raises `cve_to_poc` GitHub Search API limit 60→5000/hr |
| `SERPAPI_API_KEY` | Optional fallback web research provider |
| `NETATTACKAI_API_TOKEN` | Override the auto-generated WebUI bearer token |

Or run `python main.py --setup-api-keys` to store them in `secr.json`.

## CLI showcase

```bash
# Interactive questionary menu (the default no-args behavior)
python main.py
python main.py --menu

# Recon against an allowed target
python main.py --target 10.0.0.50 --mode recon --recon-first

# Attack with goal
python main.py --target 10.0.0.50 --mode attack --goal backdoor

# Full-power swarm run with critic, reflection, adaptive exploits
python main.py --target 10.0.0.50 --mode attack --swarm --critic \
    --reflection --adaptive-exploits

# Standalone exploit against a specific CVE with full access
python main.py --exploit --exploit-mode standalone \
    --exploit-target 10.0.0.50 --exploit-cve CVE-2021-44228 \
    --exploit-permission full_access

# Multi-hour attack mode
python main.py --target 10.0.0.50 --mode attack --long-session

# Domain targeting — resolve, expand subdomains, attack the surface
python main.py --target example.com --mode attack

# Engine advisory MCP server (read-only surface for foreign AI assistants)
python mcp_engine_server.py
```

### Legacy research CLI (Flow B, SQLite-backed)

```bash
python cli.py init-mission --config mission.yaml
python cli.py next-task
python cli.py run-task T-00001
python cli.py list-findings
python cli.py generate-report F-00001
python cli.py status
```

## The WebUI

A Vite + React 18 + TypeScript SPA under `webui/`, served by the local API
daemon and talking to the same `/api/v1` REST + WebSocket surface.

```powershell
python main.py --web             # build webui/ if needed, serve, open browser
python main.py --demon           # API only, no SPA
python main.py --daemon --api-port 9000
```

- **URL:** `http://127.0.0.1:8765` (loopback-only, no public-bind override)
- **Docs:** `http://127.0.0.1:8765/docs` (Swagger) / `/openapi.json`
- **Auth:** bearer token auto-generated into `.webui_secret_key` (gitignored)
  or set `NETATTACKAI_API_TOKEN`
- **Real-time:** WebSocket primary, SSE fallback, exponential backoff
- **One active run at a time** (HTTP 409 on conflict)

The wizard mirrors the CLI questionary flow in 4 steps (`path → settings →
target → review`), streams live boot/tool/decision/progress events, surfaces
pending decisions inline (start-confirm, goal-select, tool-approval), and
exposes artifacts, audit chain, loot/credentials, and a manual tool panel.

See [`docs/webui.md`](docs/webui.md) and [`docs/api.md`](docs/api.md).

## Architecture

Two parallel control flows coexist in one checkout — knowing which is in play
matters when reading any file.

```
                       ┌─────────────────────────────────────────┐
                       │            operator                      │
                       └──────┬──────────────┬─────────────────────┘
                              │              │
                     CLI (main.py)    WebUI (app.py → tools/api/)
                              │              │
                              └──────┬───────┘
                                     ▼
                       AssessmentService (tools/run_service/)
                                     │
                ┌────────────────────┼────────────────────┐
                ▼                    ▼                    ▼
         GoalEngine            open_exploit_mcp_session    build_router
         (preset/custom,       (stdio or http, 30s boot)   (Ollama client)
          risk-gated)                │
                                     ▼
                       run_exploit_session  ─►  mcp_exploit_server.py:8001
                                     │       (target-IP allowlist lock)
                                     ▼
                          ┌──────────┴──────────┐
                          ▼                     ▼
                   AutonomousOrchestrator    SwarmOrchestrator
                   (persistent campaigns,      (parallel specialists:
                    adaptive aggression,       recon/vuln/exploit/
                    vuln chaining, retry)      post_exploit/critic/
                                              reflection + blackboard)
```

### Flow A — Exploitation engine (modern, what users run)

Async, MCP-based, multi-agent-capable. The CLI (`main.async_main`) and the
WebUI API daemon both drive assessments through `AssessmentService` — a
transport-neutral preparation + execution service with typed
`RunRequest`/`RunPreview`/`RunResult` contracts and
`DecisionProvider`/`EventSink`/`ApprovalProvider` protocols.

### Flow B — Legacy research loop (`cli.py` + `agent_loop.py` / `db.py`)

Database-driven, scope-gated, suitable for headless/CI. Uses SQLite
(`research_workspace/research.db`). `ScopeGate` is the single chokepoint for
every executor action — allowed/disallowed assets, hard-forbidden actions,
third-party detection, rate limit bucket, risk level.

### Shared infrastructure

- **`db.py`** — SQLite schema (missions, scope_rules, tasks, observations,
  graph_nodes, graph_edges, evidence, findings, audit_logs, memories) with
  versioned migrations.
- **`mcp_session.py`** — the MCP boot async context manager. Handles the
  `BaseExceptionGroup` quirk (anyio task groups raise it on subprocess death;
  it's not a subclass of `Exception`, so bare `except Exception` silently
  misses it — use `_EXC_GROUP_CATCH` from `tools/exceptions.py`).

## MCP tool surface

The exploit MCP server (`mcp_exploit_server.py`) exposes these categories,
all registered through `tools/mcp_tools/registry.py`:

| Category | Tools |
|----------|-------|
| **Terminal** | `run_exploit_terminal`, apt/git/pip install, `run_as_root`, `check_environment` |
| **Workspace** | `write_python_file`, `run_python_file`, `read_workspace_file`, `list_workspace` |
| **Recon** | `check_os`, `quick_scan`, `run_full_recon`, `get_service_fingerprint` |
| **Attack modules** | JWT/SSTI/GraphQL/race/timing/smuggling probes, `password_spray`, `cve_to_exploit_synth`, autonomous campaign planner, `craft_exploit`, `mutate_exploit` |
| **Metasploit** | `run_msf_module`, msfconsole start/stop/command, run_exploit/auxiliary, session interact, post modules, payload generation, resource scripts |
| **Payloads** | `generate_payload` (msfvenom) |
| **Web scanning** | nikto/nuclei/sqlmap/gobuster/feroxbuster/whatweb/wpscan/dirb (target-allowlist-locked, argv-list, no shell) |
| **Cracking** | `run_hash_crack` (hashcat/john, local-only, auto hash-type ID) |
| **Credentials** | encrypted `cred_store`, `lateral_exec` (impacket), `dump_credentials`, `kerberoast` |
| **Sessions** | tmux/background jobs + listener management |
| **Research** | `search_exploit_db`, `search_web_exploit`, `fetch_webpage`, `deep_research`, `search_cve_intel` |
| **Domain** | `resolve_domain`, `enumerate_subdomains`, `dns_recon`, `vhost_enum`, `domain_whois` |
| **Peer models** | `consult_peer_models` (advisory-only, no tool schemas) |

Every target-touching tool requires a target IP and is gated by
`@require_allowlist()`. All actions write to `exploit_audit.jsonl`.

## Runtime skills

140 advisory `SKILL.md` files under `skills/`, each with YAML frontmatter
(name, description, domain, tags, NIST CSF, MITRE ATT&CK) and a sanitized
markdown body. The engine:

1. **Indexes** them via `skill_registry.load_skill_registry` (parse + sanitize
   + cache — role directives and tool-call mimics are stripped).
2. **Selects** the top `max_active_skills` per context via deterministic tag
   scoring + cross-mission Bayesian feedback boost + semantic cosine
   similarity over `nomic-embed-text` embeddings.
3. **Re-selects** mid-run as new services/CVEs appear (rate-guarded, sticky
   defaults, no prompt churn on identical sets).
4. **Injects** as compact hints into the system prompt; full bodies are
   pull-only via the `load_runtime_skill` MCP tool.

**Skills never grant execution authority.** They never change
`ExploitPermission`, widen `scope_gate`, bypass the allowlist, or suppress
audit. See [`docs/skills.md`](docs/skills.md).

## Configuration

All runtime behavior lives in **`config.yaml`**. Top-level keys:

| Key | Purpose |
|-----|---------|
| `ollama` | host, model (`glm-5.2:cloud`), `embed_host` (local embeddings) |
| `models` | registry (kimi/deepseek/deepseek_flash/glm/minimax), `default_alias` |
| `mcp` | default transport, http host/port |
| `engine_mcp` | advisory MCP server for foreign AI assistants (port 8002) |
| `nmap` | path, sudo, priv_fallback |
| `exploit` | permission, attack_mode, timeouts, workspace, allowed_targets, require_explicit_allowlist, AD/Kerberos suite, MSF recipes, listeners |
| `opsec` | target-aware OPSEC (pacing, UA rotation, DoH, quiet-commands, local_targets_off) |
| `cve_lookup` | NVD + EPSS + KEV + GitHub PoC |
| `research` | Ollama/SerpAPI providers, fetch depth, caching |
| `swarm` | agents, parallel_enabled, per_phase_concurrency |
| `autonomous` | persistence phase, checkpoint, adaptive_replan, max_cycles |
| `recon` | extended enumerators, UDP top-ports, Shodan, domain resolution |
| `reasoning` | chain_of_thought, reflection, critic, ultrathink, LLM reflection |
| `memory` | semantic, cross-mission learning, attack memory |
| `outcome_judgment` | confirmation/refutation thresholds, Flow A toggle |
| `adaptive_exploits` | mutation strategies |
| `multi_model` | consult aliases, max consultations |
| `long_session` | multi-hour mode, request timeout, checkpoint |
| `skills` | selection, re-selection, feedback, semantic matching |
| `api` | WebUI daemon host/port/token/origins |
| `eval` | benchmark harness output + budgets |

Mission scope (allowed/disallowed assets, forbidden actions, risk profiles)
lives in **`mission.yaml`** for Flow B. Three risk profiles:
`low_noise_non_destructive`, `standard_authorized`, `high_authorized_testing`.

Hard-blocked actions regardless of config: `denial_of_service`,
`destructive_exploit`, `social_engineering`, `physical_attack`, `malware`,
`credential_theft` (see `scope_gate.py:_HARD_FORBIDDEN_ACTIONS`).

## Safety model

This is a **lab-only build**. The attack path is **unrestricted but
target-locked**:

- **Three permission levels** (`tools/exploit_agent/policy.py`):
  - `full_access` — lab posture, auto-approves everything with no
    command-content/scope inspection
  - `approve_only` — every action prints an approval banner
  - `read_only` — propose-only, no execution (recon default; missing-key fallback)

- **The ONE attack-mode safety: the target-IP allowlist lock**, enforced at
  the MCP tool layer (`tools/mcp_shared._allowed_target_list` +
  `tools/mcp_tools/terminal._target_lock_block`), not in policy. It unions
  `EXPLOIT_TARGET` (the runtime `--target`) with `exploit.allowed_targets`,
  plus `EXPLOIT_TARGET_IP`/`EXPLOIT_TARGET_DOMAIN`/`EXPLOIT_DISCOVERED_TARGETS`
  for domain targeting. Every destination in every command (URL authorities,
  `/dev/tcp` hosts, LHOST/RHOST, scanner verbs, bare IPs, hostnames) is
  extracted and refused if not in the allowlist. Supports domains + `*.wildcard`
  + CIDR.

- **Recon keeps its full safety.** Post-session `SafetyReviewer`, READ_ONLY
  propose-only path, goal-menu SAFE/GATED narrowing, defensive scope-gated
  `mcp_server.py` — all unchanged.

- **Operational guards remain regardless of mode:** command timeouts (300s
  terminal / 300s python / 600s msf), full JSONL audit trail with SHA256 of
  generated code, OS-aware tooling (Windows attacker = Python-only; Linux =
  full Kali arsenal).

- **OPSEC is advisory-only, never a gate.** `is_quiet_blocked` / `noise_budget`
  stay dormant; the command always executes. Target-aware: forced OFF for
  private/local IPs, ON for public-routable.

- **Plugins are trusted Python** with full operator-box privileges, OFF by
  default. Any MCP tool a plugin registers MUST wrap its handler with
  `ctx.require_allowlist()` or `ctx.audit_tool`.

See [`docs/safety-model.md`](docs/safety-model.md) for the full layered model.

## Plugins

Out-of-tree extensions managed by `tools/plugins.py` (pure stdlib). A plugin
can contribute:

- an **attack module** (`AttackModule` subclass the AI can select)
- **MCP tools** (`@mcp.tool()` handlers registered onto the exploit MCP server)
- a **skills directory** (extra `SKILL.md` roots)
- a **config section** (treated as known by `ConfigValidator`)

Plugins are disabled by default — enable via `config plugins.enabled`. A
reference plugin lives at `plugins/example_recon_report/`. See
[`docs/plugin-development.md`](docs/plugin-development.md).

## Testing

```bash
python -m pytest tests/ -v                              # full suite (180 files)
python -m pytest tests/test_scope_gate.py -v            # single file
python -m pytest tests/test_recon_pipeline.py::TestClass::test_method  # single test
python -m pytest tests/ -v -k "scope"                   # by keyword
python -m pytest --cov=tools --cov=main.py --cov=cli.py # coverage
```

All tests mock subprocess/network — no live Nmap, no live network. pytest
config: `asyncio_mode = "auto"`, `testpaths = ["tests"]`.

### Lint (opt-in, no CI)

```bash
python -m pip install -e ".[dev]"    # ruff + pytest + coverage
ruff check .                        # line-length 120, select E/F/W/I, E501 ignored
```

**No CI is configured.** Before a PR: run `python -m pytest tests/ -v`,
`ruff check .`, and verify README flags/config still match reality.

## Project layout

```
NetAttackAi/
├── main.py                    # Flow A entry: CLI, recon, attack, menu, doctor
├── app.py                     # ASGI factory for the WebUI API daemon
├── cli.py                     # Flow B entry: SQLite-backed research CLI
├── mcp_server.py              # defensive, scope-gated MCP server
├── mcp_exploit_server.py      # exploit MCP server (port 8001)
├── mcp_engine_server.py       # advisory MCP server for foreign AI (port 8002)
├── config.yaml                # runtime source of truth
├── mission.yaml               # Flow B mission scope config
├── agent_loop.py              # Flow B research loop orchestration
├── scope_gate.py              # Flow B scope enforcement (DO NOT EDIT for attack path)
├── tools/
│   ├── exploit_agent/         # main agent loop, policy, context, prompt, reflection
│   ├── autonomous_orchestrator.py   # persistent multi-phase campaigns
│   ├── attack_modules/        # AttackModule ABC + per-category modules
│   ├── mcp_tools/             # exploit MCP tool implementations (registry.py is the hub)
│   ├── swarm/                 # 6 specialist agents + orchestrator + blackboard
│   ├── run_service/           # transport-neutral AssessmentService
│   ├── api/                   # WebUI API daemon (auth, routes, persistence, events)
│   ├── skill_*.py             # skill registry/selector/embeddings/pipeline/feedback
│   ├── opsec.py               # target-aware OPSEC (advisory-only)
│   ├── recon_pipeline.py      # host discovery, fingerprinting, enrichment
│   └── ...
├── skills/                    # 140 advisory SKILL.md files
├── webui/                     # Vite + React + TypeScript SPA
├── plugins/                   # out-of-tree plugin example
├── tests/                     # 180 test files, all mocked
├── docs/                      # engineering docs
├── reports/                   # per-run artifacts (gitignored)
├── exploit_workspace/         # per-target exploit artifacts (gitignored)
└── research_workspace/        # Flow B SQLite mission data (gitignored)
```

## Documentation

Engineering docs live in [`docs/`](docs/):

- [Getting Started](docs/getting-started.md) — setup, common commands, dev loop
- [Architecture](docs/architecture.md) — system shape, entry points, persistence
- [Runtime Flows](docs/runtime-flows.md) — recon, execution, exploitation, swarm, MCP
- [Module Guide](docs/module-guide.md) — responsibilities of top-level modules
- [Extension Guide](docs/extension-guide.md) — exact edit points for in-tree changes
- [Safety Model](docs/safety-model.md) — scope, risk, permission, audit
- [Testing Guide](docs/testing-guide.md) — test layout, focused commands
- [Runtime Skills](docs/skills.md) — advisory skill pipeline
- [Plugin Development](docs/plugin-development.md) — out-of-tree plugins
- [WebUI API](docs/api.md) — `/api/v1` REST + WebSocket reference
- [WebUI](docs/webui.md) — the bundled React/Vite SPA

For AI coding agents working in this repo: read [`AGENTS.md`](AGENTS.md) first,
then [`CLAUDE.md`](CLAUDE.md) for architecture/safety depth.

## Contributing

1. Read [`AGENTS.md`](AGENTS.md) — the compact agent guide with non-obvious
   rules you will otherwise break.
2. Run `python main.py --doctor` and `python main.py --self-test` after
   safety-sensitive changes.
3. Run `python -m pytest tests/ -v` before opening a PR. No CI is configured.
4. Do not edit Flow B safety files (`scope_gate.py`, `safety_reviewer.py`,
   Flow B's `agent_loop.py`/`tool_router.py`/`risk_controller.py`/`mission.py`/
   `db.py`) — recon safety depends on them.
5. New exploit MCP tools must be registered twice: `@audit_tool` in
   `tools/mcp_tools/<family>.py`, then added to the tool list in
   `mcp_exploit_server.py`. Target-touching tools require a target IP and
   the `@require_allowlist()` gate.
6. When adding a CLI flag, MCP tool, or config key, update the relevant
   README section.

## License

NetAttackAI — Copyright (c) 2026 NetAttackAI contributors.

Licensed under the **GNU General Public License v3.0 only**. See
[`LICENSE`](LICENSE) for the full text.