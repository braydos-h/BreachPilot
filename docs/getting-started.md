# Getting Started

## Prerequisites

- Python 3.10 or newer. The project metadata targets Python 3.10 to 3.12 and tests are currently being run locally with Python 3.11/3.13 bytecode artifacts present.
- `nmap` installed and available on `PATH` for scan features.
- Ollama running at `http://localhost:11434` for AI-backed flows.
- Optional external tools depending on feature area: Metasploit, `searchsploit`, `tmux`/session tooling on Unix-like systems, and package managers used by install tools.

## Setup

From the repository root.

**Linux / macOS:**

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

**Windows (PowerShell):**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

For editable package metadata and dev extras (either shell):

```bash
python -m pip install -e ".[dev]"
```

`requirements.txt` and `pyproject.toml` are not perfectly identical. `requirements.txt` includes MCP, Starlette, websockets, numpy, and newer Textual/Pytest pins used by current code and tests. Prefer `requirements.txt` for local development unless packaging is the specific task.

## First Commands

Run environment checks:

```bash
python main.py --doctor
```

Run the safe localhost smoke test:

```bash
python main.py --self-test
```

Launch the interactive questionary menu (default with no arguments):

```bash
python main.py
```

The `--menu` flag is equivalent to the no-argument default:

```bash
python main.py --menu
```

Launch the full Textual TUI dashboard:

```bash
python -m tui
```

Run recon against an explicitly allowed target:

```bash
python main.py --target 127.0.0.1 --mode recon --goal initial_access --yes
```

Run the workflow CLI:

```bash
python cli.py init-mission --config mission.yaml
python cli.py status
python cli.py list-scope
python cli.py next-task
```

## Configuration Files

- `config.yaml`: runtime configuration for Ollama, model aliases, MCP transport, exploit behavior, stealth options, CVE lookup, research, swarm, reasoning, memory, adaptive exploit settings, and optional peer-model consultation.
- `mission.yaml`: sample mission definition. This is where allowed assets, disallowed assets, forbidden actions, testing modes, rate limits, accounts, and notes are defined.

Important defaults in `config.yaml`:

- `exploit.permission: full_access` (lab build; recon still resolves to `read_only`)
- `exploit.attack_mode: true`
- `exploit.require_explicit_allowlist: true`
- `exploit.allowed_targets: []` (the runtime `--target` is unioned in via `EXPLOIT_TARGET`)
- `swarm.enabled: true`
- `memory.semantic_enabled: true`

## Main Entry Points

- `python main.py`: launch the interactive questionary menu — the default with no arguments (same as `--menu`).
- `python main.py --menu`: force the interactive terminal menu.
- `python main.py --tui`: launch the Textual TUI dashboard through the main launcher.
- `python main.py --target <ip> --mode recon`: reconnaissance mode.
- `python main.py --target <ip> --mode attack`: exploitation mode, still subject to config and policy gates.
- `python main.py --mcp-transport stdio|http`: select exploit MCP transport.
- `python main.py --swarm --critic --reflection`: enable swarm orchestration helpers.
- `python mcp_server.py`: start the defensive MCP server.
- `python mcp_exploit_server.py`: start the exploit MCP server.

## Developer Loop

1. Read the relevant module guide entry before editing.
2. Add or update focused tests in `tests/`.
3. Run the smallest matching test file.
4. Run `python -m pytest` before handing off larger changes.
5. For safety-sensitive changes, also run `python main.py --doctor` and `python main.py --self-test`.
