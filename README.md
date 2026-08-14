# NetAttackAI

<div align="center">

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![Status](https://img.shields.io/badge/status-beta-6f42c1?style=flat-square)
![License](https://img.shields.io/badge/license-GPL--3.0--only-blue?style=flat-square)
![Models](https://img.shields.io/badge/LLM-Ollama%20Cloud-22c55e?style=flat-square)
![MCP](https://img.shields.io/badge/MCP-1.27%2B-f97316?style=flat-square)
![WebUI](https://img.shields.io/badge/WebUI-React%20%2B%20Vite-06b6d4?style=flat-square)
![Skills](https://img.shields.io/badge/skills-140-a855f7?style=flat-square)
![Swarm](https://img.shields.io/badge/swarm-6%20agents-f59e0b?style=flat-square)
![Tests](https://img.shields.io/badge/tests-179%20mocked-10b981?style=flat-square)
![Models](https://img.shields.io/badge/peers-Kimi%20%7C%20DeepSeek%20%7C%20GLM%20%7C%20Minimax-3b82f6?style=flat-square)
![Transport](https://img.shields.io/badge/transport-stdio%20%7C%20http-8b5cf6?style=flat-square)
![Context](https://img.shields.io/badge/context-976K-ec4899?style=flat-square)
![Audit](https://img.shields.io/badge/audit-SHA256%20chain-ef4444?style=flat-square)

**An AI-driven, local-first penetration testing & bug bounty research agent.**

Plan, reconnoiter, exploit, and report — end to end — against targets you own
or are explicitly authorized to assess. An autonomous operator that thinks in
kill-chains, not checklists: it scouts the surface, picks the attack, runs it,
proves the outcome with evidence, and writes the report. Powered by Ollama
LLMs, the Model Context Protocol, and a 140-skill advisory knowledge base.
Lab-only, target-locked, fully audited.

</div>

---

> [!WARNING]
> **Authorized use only.** Run NetAttackAI solely against networks and systems
> you own or have explicit written authorization to test, on a throwaway
> operator box.
>
> **Attack mode ships as `full_access`** — every action is auto-approved with
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

- **Assessment controller** (`main.py` / `app.py`) — opens an MCP exploit
  session, dispatches tool calls, streams live events to a CLI or browser.
- **Defensive MCP server** (`mcp_server.py`) — scope-gated Nmap, sanitized
  vulnerability search, NVD CVE lookup. Read-only by design.
- **Permissive exploit MCP server** (`mcp_exploit_server.py`, port 8001) —
  terminal, Python write/run, searchsploit, Metasploit, msfvenom, impacket
  lateral movement, credential dumping, kerberoasting, web scanning, hash
  cracking. Gated by the target-IP allowlist lock at the tool layer.
- **Multi-agent swarm** (`tools/swarm/`) — 6 specialist agents (recon, vuln,
  exploit, post-exploit, critic, reflection) with a shared blackboard.
- **Autonomous attack orchestrator** (`tools/autonomous_orchestrator.py`) —
  persistent multi-phase campaigns with adaptive aggression, vuln chaining,
  and auto-retry.
- **Runtime skills system** — 140 advisory `SKILL.md` files indexed,
  deterministically + semantically selected, injected into LLM context per
  phase. Advisory only — never grants execution authority.
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
  and Minimax M3 for advisory ideas mid-run — peers have no tool schemas and
  cannot execute commands.
- **140-skill advisory brain.** Each `SKILL.md` carries NIST CSF + MITRE
  ATT&CK metadata. Selected deterministically + semantically, re-selected
  mid-run as new services/CVEs surface, with cross-mission Bayesian feedback.
- **Hypothesis-driven outcome judgment.** Every executed check produces
  structured observations; `OutcomeJudge` evaluates them against task
  criteria and persists a terminal `confirmed` / `refuted` / `exhausted`
  verdict. Execution success ≠ evidential success.
- **Tamper-evident audit chain.** Every target-touching action lands in
  `exploit_workspace/<ip>/exploit_audit.jsonl` with SHA256 of generated code.
  Chain validity is verified and surfaced in the WebUI.
- **Target-aware OPSEC.** Pacing, UA rotation, DNS-over-HTTPS, and
  quiet-command hints auto-disable for private/local IPs and engage for
  public-routable targets. Advisory-only — never a gate.
- **Domain targeting.** Pass `--target example.com` — the agent resolves it,
  expands subdomains (crt.sh + DNS bruteforce + subfinder/amass), and
  auto-authorizes each discovered host through the allowlist lock.
- **Long-session mode.** Opt-in multi-hour runs send the model's real context
  window to Ollama, bound each LLM call with an httpx timeout, and checkpoint
  compacted state for crash recovery.
- **Eval harness.** Benchmark against target labs with JSON/Markdown/HTML
  reports under `reports/eval/<run_id>/`.
- **179-test suite, all mocked.** No live Nmap, no live network — every test
  mocks subprocess/network and runs offline.

## Quick start

### 1. Prerequisites

- **Python 3.11+** (the `--doctor` check rejects 3.10)
- `nmap` on `PATH` (or set `nmap.path` in `config.yaml`)
- An Ollama endpoint — **cloud is the default** (`https://api.ollama.com`,
  needs `OLLAMA_API_KEY`) or a local daemon (`ollama.host:
  http://localhost:11434`)
- Optional, Linux full arsenal: Metasploit, searchsploit, impacket, tmux
- For the WebUI: Node.js + npm (only on first `--web` run)

### 2. Install

```powershell
# Windows PowerShell (this repo's primary dev platform)
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
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

### 3. Configure API keys (before `--doctor`)

The default cloud path requires `OLLAMA_API_KEY` or the doctor's Ollama
reachability check will 401. Keys are read from **process environment
variables** or `secr.json` — there is no `.env` auto-load. Set them with:

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

### 4. Verify

```bash
python main.py --doctor          # env check (Python/nmap/Ollama/models/config)
python main.py --self-test       # safe localhost smoke test
python main.py                   # WebUI daemon (default no-args; opens browser)
python main.py --menu            # terminal interactive menu (legacy)
```

`--doctor` exits 0 when all checks pass. Cloud models are verified by running
a 1-token generation (the programmatic `ollama run`); local models report a
`ollama pull <spec>` hint if missing.

## Choose an interface

| Interface | Start | Notes |
|---|---|---|
| **WebUI** | `python main.py` | Default. Builds `webui/dist/` on first run (needs Node/npm), opens `http://127.0.0.1:8765` |
| **CLI menu** | `python main.py --menu` | Guided questionary flow; no extra deps |
| **CLI direct** | `python main.py --target <ip> --mode recon\|attack` | Flags below |
| **API only** | `python main.py --demon` | Daemon without the SPA |

WebUI: bearer token auto-generated into `.webui_secret_key` (gitignored) or
set `NETATTACKAI_API_TOKEN`. Loopback-only, one active run at a time (HTTP
409 on conflict). Docs at `http://127.0.0.1:8765/docs`. Full SPA reference in
[`docs/webui.md`](docs/webui.md) and [`docs/api.md`](docs/api.md).

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
`--skills-list`, `--eval`, `--resume <run_id>`, `--yes` (skip confirm gate).
Run `python main.py --help` for the full list.

### Legacy research CLI (Flow B, SQLite-backed)

```bash
python cli.py init-mission --config mission.yaml
python cli.py next-task
python cli.py run-task T-00001
python cli.py list-findings
python cli.py generate-report F-00001
python cli.py status
```

Flow B is the database-driven, scope-gated research loop. See
[`docs/runtime-flows.md`](docs/runtime-flows.md).

## Safety model

This is a **lab-only build**. The attack path is **unrestricted but
target-locked**.

| Context | Effective permission |
|---|---|
| `--mode recon` | Always `read_only` — gathers and proposes, no offensive execution |
| `--mode attack` | Uses `exploit.permission` from `config.yaml` |
| Shipped attack default | **`full_access`** — auto-approves every action, no content/scope inspection |
| Safer attack posture | `approve_only` — prints an approval banner per action |

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

All runtime behavior lives in **`config.yaml`**. Key sections:

| Key | Purpose |
|-----|---------|
| `ollama` | host, model (`glm-5.2:cloud`), `embed_host` (local embeddings) |
| `models` | registry (kimi/deepseek/deepseek_flash/glm/minimax), `default_alias` |
| `exploit` | permission, attack_mode, timeouts, `allowed_targets`, `require_explicit_allowlist`, AD/Kerberos suite, MSF recipes, listeners |
| `opsec` | target-aware OPSEC (pacing, UA rotation, DoH, `local_targets_off`) |
| `swarm` | agents, `parallel_enabled`, `per_phase_concurrency` |
| `autonomous` | persistence phase, checkpoint, `adaptive_replan`, `max_cycles` |
| `recon` | extended enumerators, UDP top-ports, Shodan, domain resolution |
| `skills` | selection, re-selection, feedback, semantic matching |
| `api` | WebUI daemon host/port/token/origins |
| `long_session` | multi-hour mode, request timeout, checkpoint |

Mission scope (allowed/disallowed assets, forbidden actions, risk profiles)
for Flow B lives in **`mission.yaml`**. Three risk profiles:
`low_noise_non_destructive`, `standard_authorized`, `high_authorized_testing`.

Hard-blocked actions regardless of config: `denial_of_service`,
`destructive_exploit`, `social_engineering`, `physical_attack`, `malware`,
`credential_theft` (see `scope_gate.py:_HARD_FORBIDDEN_ACTIONS`).

## Testing

```bash
python -m pytest tests/ -v                              # full suite (179 files)
python -m pytest tests/test_scope_gate.py -v            # single file
python -m pytest tests/test_recon_pipeline.py::TestClass::test_method  # one test
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

## Plugins

Out-of-tree extensions managed by `tools/plugins.py` (pure stdlib). A plugin
can contribute an attack module, MCP tools, a skills directory, and a config
section. Plugins are disabled by default — enable via `config plugins.enabled`.
A reference plugin lives at `plugins/example_recon_report/`. See
[`docs/plugin-development.md`](docs/plugin-development.md).

## Documentation

Engineering docs in [`docs/`](docs/):

**Operators**
- [Getting Started](docs/getting-started.md) — setup, common commands, dev loop
- [Safety Model](docs/safety-model.md) — scope, risk, permission, audit
- [WebUI](docs/webui.md) — the bundled React/Vite SPA
- [WebUI API](docs/api.md) — `/api/v1` REST + WebSocket reference

**Integrators**
- [Runtime Skills](docs/skills.md) — advisory skill pipeline
- [Plugin Development](docs/plugin-development.md) — out-of-tree plugins

**Contributors**
- [Architecture](docs/architecture.md) — system shape, entry points, persistence
- [Runtime Flows](docs/runtime-flows.md) — recon, execution, exploitation, swarm, MCP
- [Module Guide](docs/module-guide.md) — responsibilities of top-level modules
- [Extension Guide](docs/extension-guide.md) — exact edit points for in-tree changes
- [Testing Guide](docs/testing-guide.md) — test layout, focused commands
- [`AGENTS.md`](AGENTS.md) — compact agent guide with non-obvious rules
- [`CLAUDE.md`](CLAUDE.md) — architecture/safety depth for AI coding agents

## Contributing

1. Read [`AGENTS.md`](AGENTS.md) first — it lists the non-obvious rules you
   will otherwise break.
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