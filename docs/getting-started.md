# Getting Started

## Prerequisites

- **Python 3.11+** (`pyproject.toml:11` `requires-python = ">=3.11"`; `tools/doctor.py:31` rejects <3.11, CI matrix 3.11–3.13).
- `nmap` on `PATH` (or set `nmap.path` in `config.yaml`).
- An Ollama endpoint: **cloud is the default** (`https://api.ollama.com`, needs `OLLAMA_API_KEY`) or a local daemon (`ollama.host: http://localhost:11434`). Embeddings stay local via `ollama.embed_host` (`http://localhost:11434`).
- Optional external tools depending on feature area: Metasploit, `searchsploit`, `tmux`/session tooling on Unix-like systems, and package managers used by install tools.

## Setup

From the repository root.

**Windows — one-click (recommended for new users):**

```powershell
# Double-click install.bat in Explorer, or from PowerShell:
.\install.bat          # checks/installs Python/Node/Nmap/Ollama, venv, WebUI, --doctor
.\START.bat            # after install: double-click to launch (WebUI at http://127.0.0.1:8765)
```

`install.bat` does everything: it checks for Python 3.11+, Node.js, Nmap and Ollama
(offering to install anything missing via `winget` when you approve), creates
`.venv`, installs `requirements.txt`, builds `webui/dist/` if Node is present,
starts Ollama, pulls the default model + embedding model, walks you through
`OLLAMA_API_KEY`, runs `python main.py --doctor`, and wires the `natai`
launcher. Safe to re-run; try `install.bat --check` for an audit-only pass
or `install.bat --help` for options.

**Windows — manual (PowerShell):**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

**Linux / macOS:**

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
# one-shot bootstraps (pick one):
./install.sh               # full bootstrap (OS prereqs + Ollama + venv + natai)
./scripts/setup-linux.sh   # lightweight: venv + deps + doctor
```

For editable package metadata and dev extras (either shell):

```bash
python -m pip install -e ".[dev]"
```

`requirements.txt` includes runtime dependencies plus Pytest for local development. `pyproject.toml` separates runtime and development dependencies for packaging. Prefer `requirements.txt` for a local checkout unless packaging is the specific task.

## First Commands

Run environment checks:

```bash
python main.py --doctor
```

Run the safe localhost smoke test:

```bash
python main.py --self-test
```

Launch the WebUI daemon (the default with no arguments — builds the SPA if
needed, serves it at http://127.0.0.1:8765, and opens a browser):

```bash
python main.py
```

Prefer the terminal? The legacy interactive questionary menu is still available:

```bash
python main.py --menu
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

- `config.yaml`: runtime configuration for Ollama, model aliases, MCP transport, exploit behavior, stealth options, CVE lookup, research, swarm, reasoning, memory, outcome judgment, adaptive exploit settings, and optional peer-model consultation.
- `mission.yaml`: sample mission definition. This is where allowed assets, disallowed assets, forbidden actions, testing modes, rate limits, accounts, and notes are defined.
- `plugins` block in `config.yaml`: controls plugin enablement (`enabled`/`disabled` name lists), `search_paths` (default `["plugins"]`), and `entry_points` (default `true`).

Important defaults in `config.yaml`:

- `exploit.permission: full_access` (lab build; set `read_only` for propose-only recon)
- `exploit.attack_mode: true`
- `exploit.require_explicit_allowlist: true`
- `exploit.allowed_targets: [127.0.0.1]` in the shipped lab config (a target entered in Start New Session is added here; the runtime `--target` is also unioned in via `EXPLOIT_TARGET`)
- `swarm.enabled: true`
- `memory.semantic_enabled: true`
- `outcome_judgment.max_inconclusive_attempts: 3`
- `outcome_judgment.confirmation_threshold: 0.75`
- `outcome_judgment.refutation_threshold: 0.75`
- `outcome_judgment.min_evidence_references: 1`

Only materially different inconclusive checks count toward the attempt cap, and
the configured minimum is two so one failed command cannot exhaust a
hypothesis. Thresholds must be between `0.5` and `1.0`; evidence references must
be at least one for a confirmed/refuted terminal judgment. These settings only
control interpretation and replanning—they do not grant execution authority.

## Main Entry Points

- `python main.py`: start the WebUI daemon — the default with no arguments (build + serve the SPA at http://127.0.0.1:8765 and open a browser).
- `python main.py --menu`: force the legacy interactive terminal menu.
- `python main.py --target <ip> --mode recon`: reconnaissance mode.
- `python main.py --target <ip> --mode attack`: exploitation mode, still subject to config and policy gates.
- `python main.py --demon` / `--web`: API-only daemon / daemon + SPA + browser.
- `python main.py --mcp-transport stdio|http`: select exploit MCP transport (ignored on the run path — always http).
- `python main.py --swarm --critic --reflection`: enable swarm orchestration helpers.
- `python main.py --list-plugins`: list discovered plugins.
- `python main.py --skills {on,off,hints,lookup}`: set runtime skill mode.
- `python main.py --skills-list`: list available skills.
- `python main.py --long-session`: opt-in multi-hour attack mode.
- `python mcp_server.py`: start the defensive MCP server.
- `python mcp_exploit_server.py`: start the exploit MCP server.
- `python mcp_engine_server.py`: start the engine advisory MCP server (skills/CVE/run history, read-only, for foreign AI assistants).

For plugin authoring see `docs/plugin-development.md`; for the runtime skills system see `docs/skills.md`.

## Developer Loop

1. Read the relevant module guide entry before editing.
2. Add or update focused tests in `tests/`.
3. Run the smallest matching test file.
4. Run `python -m pytest` before handing off larger changes.
5. For safety-sensitive changes, also run `python main.py --doctor` and `python main.py --self-test`.
