# NetAttackAI

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![Status](https://img.shields.io/badge/status-beta-6f42c1?style=flat-square)
![License](https://img.shields.io/badge/license-GPL--3.0--only-blue?style=flat-square)

AI-driven, locally run penetration testing and bug bounty research engine with recon, exploit orchestration, reporting, and a WebUI API.

> [!WARNING]
> This project can run offensive tooling. Use it only against systems you own or have explicit written authorization to assess.

## Overview

NetAttackAI combines:

- **Flow A (modern runtime):** interactive menu + autonomous exploit orchestration via MCP tools
- **Flow B (legacy runtime):** SQLite-backed mission workflow (`cli.py`)
- **Target-aware execution:** IP/domain target handling with allowlist lock at the MCP tool layer
- **Extensible platform:** runtime skills, plugin support, and modular attack modules

Key capabilities:

- Reconnaissance (Nmap, enrichment, CVE intelligence)
- Exploit workflows (terminal tooling, payload generation, Metasploit helpers)
- Swarm mode (specialist parallel agents)
- Long-session autonomous campaigns with adaptive behavior
- WebUI API daemon with REST + WebSocket streams

## Quick Start

### Prerequisites

- Python **3.10+** (3.11+ recommended)
- Nmap installed and available on `PATH`
- Ollama access
  - Default host: `https://api.ollama.com`
  - Requires `OLLAMA_API_KEY` for cloud use

### Install

```bash
# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

```powershell
# Windows (PowerShell)
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### Verify

```bash
python main.py --doctor
python main.py --self-test
```

### Run

```bash
python main.py
```

## Common Usage

```bash
# Interactive menu (default)
python main.py --menu

# Recon-first workflow
python main.py --target 10.0.0.50 --mode recon --recon-first

# Direct attack mode
python main.py --target 10.0.0.50 --mode attack --goal initial_access

# Domain target
python main.py --target example.com --mode attack --goal initial_access

# Swarm mode
python main.py --target 10.0.0.50 --mode attack --swarm --critic --reflection --adaptive-exploits

# WebUI API
python main.py --demon
python main.py --web
```

> [!TIP]
> `--web` builds and serves the bundled WebUI and opens it in your browser.  
> API docs are available at `http://127.0.0.1:8765/docs`.

## Architecture at a Glance

- `main.py` / `app.py`: main runtime entry points
- `mcp_exploit_server.py`: exploit MCP surface
- `mcp_server.py`: defensive MCP surface
- `tools/exploit_agent/`: exploit loop, policy, prompt, context, tool-call handling
- `tools/swarm/`: specialist multi-agent orchestration
- `tools/api/`: WebUI API backend
- `cli.py`: legacy mission-driven workflow

For deeper technical details, see:

- `/home/runner/work/NetAttackAi/NetAttackAi/CLAUDE.md`
- `/home/runner/work/NetAttackAi/NetAttackAi/AGENTS.md`
- `/home/runner/work/NetAttackAi/NetAttackAi/docs/README.md`

## Configuration

Runtime behavior is driven by `/home/runner/work/NetAttackAi/NetAttackAi/config.yaml`.

Important sections:

- `ollama` / `models`: model host and aliases
- `mcp`: transport defaults
- `exploit`: exploit mode, permission, allowlist, workspaces
- `nmap`: scanner path and privilege behavior
- `swarm`, `autonomous`, `recon`, `skills`: advanced runtime behavior
- `opsec`: target-aware OPSEC guidance and pacing settings

> [!IMPORTANT]
> The active exploit posture is configured in `config.yaml`. Review it carefully before running attack workflows.

## Development

```bash
# Full tests
python -m pytest tests/ -v

# One test file
python -m pytest tests/test_scope_gate.py -v

# Lint (optional toolchain)
python -m pip install -e ".[dev]"
ruff check .
```

## Output & Workspace Directories

Generated runtime state (gitignored) is written under:

- `reports/`
- `exploit_workspace/`
- `research_workspace/`
- `swarm_workspace/`
- `webui/dist/` (when building WebUI)

## Documentation

- Project docs index: `/home/runner/work/NetAttackAi/NetAttackAi/docs/README.md`
- WebUI/API details: `/home/runner/work/NetAttackAi/NetAttackAi/docs/webui.md` and `/home/runner/work/NetAttackAi/NetAttackAi/docs/api.md`
- Plugin guide: `/home/runner/work/NetAttackAi/NetAttackAi/docs/plugin-development.md`
