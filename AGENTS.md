# AGENTS.md

Compact guide for AI coding agents working in this repo. Read this first, then
`CLAUDE.md` for architecture/safety depth and `docs/` for topic guides.

## Primary sources (read before editing)

- **`CLAUDE.md`** — authoritative architecture, permission model, boot sequence,
  flow A/B split, and the "Things To Watch Out For" list. Treat it as canon.
- **`docs/`** — `architecture.md`, `runtime-flows.md`, `module-guide.md`,
  `extension-guide.md`, `safety-model.md`, `testing-guide.md`, `skills.md`,
  `plugin-development.md`, `getting-started.md`.
- **`README.md`** — canonical user-facing doc. Update it when you add a CLI
  flag, MCP tool, or config key.
- **`config.yaml`** — runtime source of truth for all behavior. Top-level keys
  documented in README §Configuration.

## Commands

```powershell
# Windows (this repo's primary dev platform — Makefile targets don't run here)
python -m venv .venv; .\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python main.py --doctor          # env check (Python/nmap/Ollama/config)
python main.py --self-test       # safe localhost smoke test
python main.py                   # interactive menu (default no-args)

# Tests (166 files in tests/, all mock subprocess/network — no live Nmap)
python -m pytest tests/ -v                                            # full suite
python -m pytest tests/test_scope_gate.py -v                          # one file
python -m pytest tests/test_recon_pipeline.py::TestClass::test_method # one test
python -m pytest tests/ -v -k "scope"                                 # by keyword
python -m pytest --cov=tools --cov=main.py --cov=cli.py               # coverage

# Lint (opt-in, no CI)
python -m pip install -e ".[dev]"   # ruff + pytest + coverage
ruff check .                        # line-length 120, select E/F/W/I, E501 ignored
```

On Linux/macOS `make install|test|test-one F=…|run|doctor|mcp-exploit` work.
`scripts/setup-linux.sh` is a one-shot bootstrap.

## Non-obvious rules an agent will otherwise break

1. **`except Exception` silently misses MCP subprocess death.** anyio task
   groups raise `BaseExceptionGroup` (not an `Exception` subclass). Any code
   wrapping `stdio_client` / `streamable_http_client` / `ClientSession.initialize()`
   must use `_EXC_GROUP_CATCH` + `_is_exception_group` / `_log_nested_exceptions`
   from `tools/exceptions.py`. Bare `except Exception` will hide the real error.

2. **Do not edit Flow B safety files.** `scope_gate.py`, `safety_reviewer.py`,
   and Flow B's `agent_loop.py`, `tool_router.py`, `risk_controller.py`,
   `mission.py`, `db.py` carry recon safety. Two flows coexist in one checkout:
   - **Flow A** (modern, what users run): `main.py` / `app.py` →
     `tools/exploit_agent/`, `tools/mcp_tools/`, `tools/swarm/`,
     `tools/autonomous_orchestrator.py`, `tools/run_service/`, `tools/api/`.
   - **Flow B** (legacy, SQLite-backed): `cli.py` + the root-level
     `agent_loop.py` / `db.py` / `mission.py` / `scope_gate.py` / etc.
   They share `db.py` and `mission.py` schemas only.

3. **The one attack-mode safety is the target-IP allowlist lock**, enforced in
   the MCP tool layer (`tools/mcp_shared._allowed_target_list` +
   `tools/mcp_tools/terminal._target_lock_block`), not in
   `tools/exploit_agent/policy.py`. `full_access` auto-approves everything with
   no command/scope/pivot inspection. Do not re-add the removed command-content
   / scope / pivot gates without first ensuring the allowlist covers the path
   you're de-restricting — the allowlist IS the lock. Recon stays `read_only`
   via `_resolve_exploit_permission`'s missing-key fallback.

4. **New exploit MCP tools must be registered twice**: `@audit_tool` decorator
   in `tools/mcp_tools/<family>.py`, then added to the tool list in
   `mcp_exploit_server.py`. `tools/mcp_tools/registry.py` is the central wiring
   point. Target-touching tools require a target IP and the
   `@require_allowlist()` gate.

5. **`opencode.json` is editor-local config** (gitignored) for the opencode.ai
   editor's own model provider — it is NOT application config. Don't treat it
   as app state. App config lives in `config.yaml`.

6. **`--target` accepts an IP or a domain** (Phase 4). Domains resolve via
   `tools/validation_utils.resolve_target_to_ip` and thread
   `EXPLOIT_TARGET`/`EXPLOIT_TARGET_IP`/`EXPLOIT_TARGET_DOMAIN`/`EXPLOIT_DISCOVERED_TARGETS`
   env vars into the MCP server. The allowlist matcher supports
   domains + `*.wildcard` + CIDR by design.

7. **Ollama Cloud is the default model path.** `ollama.host` defaults to
   `https://api.ollama.com`; the ollama Python client auto-attaches
   `Authorization: Bearer $OLLAMA_API_KEY` to every chat/generate request, so
   a host swap is the whole wiring (no probe, no local→cloud fallback).
   Override `ollama.host` in config.yaml to point at a local daemon and the
   same code path runs against it. Embeddings stay local by default via
   `ollama.embed_host` (falls back to `ollama.host` when absent) —
   `nomic-embed-text` is small enough to self-host. `OLLAMA_API_KEY` env is
   required for the cloud path; missing key surfaces as auth failure on the
   first chat.

8. **No CI is configured.** Before a PR: run `python -m pytest tests/ -v`,
   `ruff check .`, and verify README flags/config still match reality.

## Workspace dirs (all gitignored runtime state)

- `reports/<run_id>/` — per-run artifacts
- `exploit_workspace/<target_ip>/<attempt_id>/` — exploit attempts + audit JSONL
- `research_workspace/<mission_id>/` — Flow B mission data (SQLite)
- `swarm_workspace/` — swarm artifacts (created on demand)
- `webui/dist/` — built SPA (first `--web` run does `npm install && npm run build`)

## Toolchain notes

- Python 3.10+ (3.11+ recommended). `pytest asyncio_mode = "auto"`.
- `pyproject.toml` and `requirements.txt` overlap on runtime deps; `pyproject`
  adds dev extras (pytest, coverage, ruff). Keep both in sync when adding deps.
- `ruff` config: line-length 120, `select = ["E","F","W","I"]`, `ignore = ["E501"]`.
  Keep security-sensitive diffs readable — don't add heavy lint presets.
- Linux nmap `-O`/`-sS` need root: set `nmap.sudo: true` (uses `sudo -n`) or
  run as root, else `nmap.priv_fallback` (default true) auto-downgrades.
- Windows attacker = Python-only exploits; Linux attacker = full Kali arsenal
  (searchsploit/metasploit/hydra/crackmapexec/impacket). OS-aware instructions
  live in the exploit agent's system prompt.