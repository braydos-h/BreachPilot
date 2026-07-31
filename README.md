<div align="center">

# NetAttackAI

**AI-driven, local-first platform for authorized security assessments**

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![Status](https://img.shields.io/badge/status-beta-6f42c1?style=flat-square)
![License](https://img.shields.io/badge/license-GPL--3.0--only-blue?style=flat-square)

[Quick Start](#quick-start) · [Feature Inventory](#feature-inventory) · [Safety](#authorized-use-only) · [Docs](#documentation)

</div>

NetAttackAI (also referred to in parts of the codebase as **AI Target Exploitation Engine**) is a Python application that combines recon, model-guided analysis, exploit orchestration, evidence tracking, and reporting into one local workspace for **authorized** testing.

> [!WARNING]
> This repository ships with a **lab-oriented profile**. Attack workflows can execute powerful tooling on your operator machine. Use only on systems you own or are explicitly authorized to assess.

---

## What this app includes

- Interactive assessment UI (`python main.py`) and direct CLI modes.
- Two MCP servers:
  - **Defensive MCP server** (`mcp_server.py`) for scope-gated recon/intel.
  - **Exploit MCP server** (`mcp_exploit_server.py`) for offensive tooling.
- Multi-agent exploitation runtime (`tools/exploit_agent/`) with optional swarm orchestration.
- Persistent autonomous campaigns (`tools/autonomous_orchestrator.py`) with adaptive retries.
- Structured legacy mission workflow (`cli.py`) backed by SQLite for mission/task/finding tracking.

---

## Quick start

### Prerequisites

- Python **3.10+** (3.11+ recommended)
- [Ollama](https://ollama.com/) running locally (default host: `http://localhost:11434`)
- [Nmap](https://nmap.org/) on `PATH`

Optional but supported: Metasploit, searchsploit, tmux, hashcat/john, Impacket, Nikto, Nuclei, Gobuster/Feroxbuster, sqlmap, WhatWeb, WPScan, Dirb/Dirbuster, and other security tools.

### Install

```bash
git clone https://github.com/braydos-h/NetAttackAi
cd NetAttackAi

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### Validate environment

```bash
python main.py --doctor
python main.py --self-test
```

### Run

```bash
python main.py
```

Recon-first example:

```bash
python main.py --target 10.0.0.50 --mode recon --recon-first
```

Attack example:

```bash
python main.py --target 10.0.0.50 --mode attack --goal initial_access
```

Domain target example:

```bash
python main.py --target example.com --mode attack --goal initial_access
```

---

| Command | Purpose |
| --- | --- |
| `python main.py --doctor` | Check Python, dependencies, Nmap, Ollama, models, configuration, workspaces, and ports. |
| `python main.py --self-test` | Run the localhost-only, read-only smoke test. |
| `python main.py --skills-list` | View the runtime-skill catalog. |
| `python main.py --list-plugins` | List discovered plugins (name/version/capabilities/loaded) and exit. |
| `python main.py --swarm --critic --reflection` | Enable specialist-agent coordination and review for a compatible run. |
| `python main.py --parallel-swarm` | Enable parallel sub-agents: `route_parallel` runs same-phase recon/vuln batches concurrently, and the main AI gains `spawn_subagent`/`await_subagent`/`list_subagents` MCP tools to delegate work. Off by default (recon-first); `swarm.exploit_parallel: true` in `config.yaml` also parallelizes exploit/post_exploit. |
| `python main.py --long-session --resume <RUN_OR_SESSION_ID>` | Run or resume a checkpointed session. |
| `python main.py --eval --target <AUTHORIZED_LAB_IP>` | Run the eval/benchmark harness against a target and write `reports/eval/<run_id>/`. |
| `python main.py --help` | Show the complete CLI reference. |

## Feature inventory

### 1) Reconnaissance and intelligence

- Nmap-based scanning and host/service discovery.
- Service enrichment and fingerprint helpers.
- CVE lookup and threat-intel enrichment.
- Web research integration with caching/ranking.
- Recon diffing between runs.
- Domain operations:
  - Domain-to-IP resolution
  - Subdomain enumeration
  - DNS recon (including transfer/security checks)
  - Virtual host enumeration
  - WHOIS lookups

### 2) Exploit runtime and orchestration

- Policy-driven exploit agent loop with tool-call planning and execution.
- Attack goals (`initial_access`, `privilege_escalation`, `persistence`, custom goals, etc.).
- Resume/checkpoint support for long sessions.
- Adaptive exploit generation and mutation.
- Autonomous multi-phase campaign engine with retries and chaining.

### 3) Multi-agent swarm mode

Optional specialist swarm with shared blackboard and orchestration:

- Recon agent
- Vulnerability agent
- Exploit agent
- Post-exploit agent
- Critic agent
- Reflection agent

Enable with CLI flags such as `--swarm --critic --reflection`.

### 4) MCP tooling surfaces

#### Defensive MCP server (`mcp_server.py`)

- Scope-aware scanning and vulnerability lookup tools.
- Safer integration surface for client-side recon workflows.

#### Exploit MCP server (`mcp_exploit_server.py`)

Exposes rich tool families used by the attack runtime:

- Terminal command execution
- Workspace file write/run/read/list helpers
- Recon helpers and service checks
- Web scanner wrappers
- Metasploit helpers and session utilities
- Payload generation helpers
- Credential/AD/Kerberos tooling
- Hash cracking helpers
- Research/search/exploit-intel helpers
- Runtime skills helpers
- Optional peer-model consultation
- Session/process/listener management

### 5) Built-in attack module ecosystem

The app ships with a large ranked module set across categories including:

- Web attack patterns (SQLi, XSS, SSTI, GraphQL, SSRF, XXE, LFI, request smuggling, race/timing)
- SMB/AD/Kerberos and credential attack workflows
- Privilege-escalation and post-exploitation checks
- Service-focused modules (SSH/SMB/FTP/Redis/etc.)
- ICS/SCADA/IoT reconnaissance-focused modules
- Supply-chain/CI exposure checks
- CVE-to-exploit synthesis helpers
- Detection-coverage posture checks

### 6) OPSEC and detection coverage

- Target-aware OPSEC behavior (different posture for local/private vs public targets).
- Pacing/jitter controls.
- User-Agent rotation and DNS-over-HTTPS options.
- Command noise scoring and quieter command suggestions.
- Detection-coverage planning and audit-footprint reporting surfaces.

### 7) Structured mission workflow (`cli.py`)

Deterministic, database-backed flow for repeatable assessment management:

- Mission initialization and scope/risk rules
- Task queue lifecycle
- Execution + observation + outcome judgment
- Evidence storage and target graph updates
- Finding verification and report generation

Core flow:

`Mission -> Scope/Risk Gate -> Planner -> TaskQueue -> Executor -> Observer -> OutcomeJudge -> Evidence/Memory/Graph -> FindingVerifier -> Report`

### 8) Memory, learning, and reasoning support

- Semantic memory and cross-mission learning surfaces.
- Experience scoring for adaptive decisions.
- Runtime skill selection/re-selection/feedback pipeline.
- Configurable observer/reasoning behavior.

### 9) Reporting and artifacts

- Per-run reports and logs under `reports/`.
- Exploit attempt artifacts in `exploit_workspace/`.
- SQLite-backed mission records in `research_workspace/`.
- Enhanced markdown/html reporting support.

### 10) Plugin system

Opt-in plugin model to extend the platform without core rewrites:

- Register custom attack modules
- Register MCP tools
- Provide skill directories
- Extend config schema/sections

Discover/list plugins with:

```bash
python main.py --list-plugins
```

---

## Primary run modes

### Interactive main app

```bash
python main.py
```

### Common flags

- `--target`
- `--mode recon|attack`
- `--goal` / `--custom-goal`
- `--recon-first`
- `--swarm --critic --reflection`
- `--adaptive-exploits`
- `--long-session`
- `--resume <id>`
- `--mcp-transport stdio|http`
- `--skills on|off|hints|lookup`
- `--skills-list`
- `--list-plugins`
- `--doctor`
- `--self-test`
- `--eval`

Use `python main.py --help` for full CLI details.

### Legacy structured workflow

```bash
python cli.py init-mission --config mission.yaml
python cli.py list-scope
python cli.py next-task
python cli.py run-task T-00001
python cli.py list-findings
python cli.py generate-report F-00001
```

---

## Configuration

### `config.yaml`

Main runtime configuration for:

- Ollama host/model aliases and routing
- MCP transport settings
- Nmap behavior
- Exploit settings and permission mode
- OPSEC behavior
- CVE/research settings
- Swarm/reasoning/memory/skills systems
- Long-session and adaptive exploit controls
- Plugin enablement/discovery

### `mission.yaml`

Structured mission configuration for `cli.py`:

- Objective and assessment scope
- Allowed/disallowed assets
- Forbidden actions
- Risk profile and testing modes
- Rate limits and account metadata

### API key setup

```bash
python main.py --setup-api-keys
```

---

## Generated workspace layout

- `reports/<run_id>/` — run outputs, summaries, findings, logs
- `reports/eval/<run_id>/` — eval harness outputs
- `research_workspace/<mission_id>/` — SQLite mission data, evidence, reports
- `exploit_workspace/<target>/<attempt_id>/` — exploit scripts/logs/audit artifacts
- `swarm_workspace/` — swarm-generated artifacts

---

## Authorized use only

This tool is for legal, authorized testing only.

- Do not run against systems you do not own or explicitly control under written authorization.
- Do not treat built-in controls as legal authorization.
- Review and constrain scope before every run.
- Prefer recon-first runs before offensive paths.

For detailed boundaries and safety behavior, read [docs/safety-model.md](docs/safety-model.md).

---

## Development

Install dev extras and run tests:

```bash
python -m pip install -e ".[dev]"
python -m pytest tests/ -v
```

Run one file:

```bash
python -m pytest tests/test_scope_gate.py -v
```

Makefile shortcuts (Unix-like):

```bash
make install
make install-dev
make doctor
make self-test
make test
make test-one F=tests/test_scope_gate.py
make run
make mcp-defensive
make mcp-exploit
```

---

## Documentation

- [docs/getting-started.md](docs/getting-started.md)
- [docs/architecture.md](docs/architecture.md)
- [docs/runtime-flows.md](docs/runtime-flows.md)
- [docs/module-guide.md](docs/module-guide.md)
- [docs/extension-guide.md](docs/extension-guide.md)
- [docs/plugin-development.md](docs/plugin-development.md)
- [docs/safety-model.md](docs/safety-model.md)
- [docs/testing-guide.md](docs/testing-guide.md)
- [docs/skills.md](docs/skills.md)

---

## License

GPL-3.0-only. See [LICENSE](LICENSE).
