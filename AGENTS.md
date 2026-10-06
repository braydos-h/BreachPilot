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

```bash
# Linux (primary dev platform)
python3 -m venv .venv; source .venv/bin/activate
python3 -m pip install -r requirements.txt
bp --doctor          # env check (Python/nmap/active provider/config)
bp --self-test       # safe localhost smoke test
bp                   # WebUI daemon + browser (default no-args); --menu for the terminal menu

# Tests (~250 files in tests/, all mock subprocess/network — no live Nmap)
python3 -m pytest tests/test_scope_gate.py -v -p no:cacheprovider -n 0   # one file (preferred)
python3 -m pytest tests/test_recon_pipeline.py::TestClass::test_method -n 0  # one test
# ── TEST-RUN RULES (operator laptop logs out on big runs — mandatory) ──
# NEVER `pytest tests/` bare. Slices only: one file at a time, ~30 files max.
# Always `-n 0` or `-n 2` max (never `-n auto`/4+); never override `-m`
# (integration/live_llm deselected on purpose); never run suites in parallel
# across sessions. Full-suite verification is CI's job. See CLAUDE.md §TEST-RUN RULES.

# Lint (repo-wide, CI honest: 0 errors, 0 format diffs)
python3 -m pip install -e ".[dev]"   # ruff + pytest + coverage + mypy + build + twine
ruff check .                         # must pass (0 errors; per-file-ignores document intentional patterns)
ruff format --check .                # must pass (0 diffs)
mypy --follow-imports=skip tools     # must pass (disables documented in pyproject.toml [tool.mypy])
```

`./install.sh` is the full bootstrap (OS prereqs + provider-aware optional
Ollama/model setup + venv + WebUI + `--doctor` + `breachpilot`/`bp` launchers
on `~/.local/bin`). The Linux installer keys Ollama setup and model pulls to
`models.provider`; the Windows `install.ps1` also checks `embeddings.provider`.
The checked-in config selects OpenCode Go and disables provider-aware Flow A
embeddings, so installer Ollama/model setup is skipped. Research is separate
and currently selects Ollama with SerpAPI fallback; Flow B also retains its
legacy Ollama semantic-memory path when enabled.
`make install|test|test-one F=…|run|doctor|mcp-exploit` are thin wrappers.
`scripts/setup-linux.sh` is the lightweight alternative (venv + deps + doctor).

<details>
<summary>Windows (legacy, secondary)</summary>

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python main.py --doctor
python main.py --self-test
```

`install.bat` wraps the provider-aware `install.ps1`; with the checked-in
OpenCode Go + `embeddings.provider: none` config it skips Ollama setup for
chat and embeddings. Research still selects Ollama with SerpAPI fallback.
Makefile targets don't run there — use the `python`/`python -m` equivalents above.

</details>

## Non-obvious rules an agent will otherwise break

1. **`except Exception` silently misses MCP subprocess death.** anyio task
   groups raise `BaseExceptionGroup` (not an `Exception` subclass). Any code
   wrapping `stdio_client` / `streamable_http_client` / `ClientSession.initialize()`
   must use `_EXC_GROUP_CATCH` + `_is_exception_group` / `_log_nested_exceptions`
   from `tools/exceptions.py`. Bare `except Exception` will hide the real error.

2. **Do not edit Flow B safety files.** `scope_gate.py`, `safety_reviewer.py`,
   and `legacy/` (`legacy/agent_loop.py`, `legacy/tool_router.py`, `legacy/risk_controller.py`,
   `legacy/mission.py`, `db.py` carry recon safety). Flow B is frozen in `legacy/` — root shims
   (`cli.py`, `agent_loop.py`, etc.) are `DeprecationWarning` shims for one release; new code must
   use Flow A or `legacy.*` for frozen reference. See `legacy/README.md`.
   - **Flow A** (modern, canonical): `main.py` / `app.py` →
     `tools/exploit_agent/`, `tools/mcp_tools/`, `tools/swarm/`,
     `tools/autonomous_orchestrator.py`, `tools/run_service/`, `tools/api/`.
   - **Flow B** (legacy, frozen `legacy/`): `legacy/cli.py` + `legacy/agent_loop.py` /
     `legacy/mission.py` / `db.py` / `scope_gate.py` / etc. Shares `db.py`/`mission.py` schemas only.

3. **Flow A attack execution has independent mission-scope and destination
   gates.** On the `full_access` path, `ExploitPolicy` consults its threaded
   `ScopeGate` for forbidden action categories and disallowed assets; a missing
   gate fails closed. The target-touching MCP tool layer separately enforces
   the target allowlist lock (`tools/mcp_shared._allowed_target_list` and the
   registered allowlist checks). Do not remove, bypass, or weaken either gate.
   `full_access` does not inspect command content or impose a pivot-depth gate;
   do not reintroduce those policies as a substitute for either existing
   boundary. Recon stays `read_only` via `_resolve_exploit_permission`'s
   missing-key fallback.

4. **New exploit MCP tools: single-source registration** — add `@audit_tool` (or `@require_allowlist()` for target-touching) in `tools/mcp_tools/<family>.py` only; `mcp_exploit_server.py` auto-discovers every `register_*_tools` via `tools/mcp_tools/registry.py:collect_tools()` (pkgutil + AST validation, fails CI if decorator missing). No manual list edit in `mcp_exploit_server.py`. `tools/mcp_tools/registry.py` is central wiring. Target-touching = `@require_allowlist()` + `validate_target_or_ip`.

4.5. **Attack execution runs inside the sandbox** (`tools/sandbox/`, default-on
   via `config.yaml sandbox.enabled: true`). `run_exploit_terminal`,
   `run_as_root`, `git_clone`, `run_python_file`, Metasploit, and the scanners
   funnel through `tools/mcp_tools/sandbox_exec.py` into a disposable worker
   container whose netns firewall authorizes only the effective allowlist (plus pinned research hosts only when `allow_research_hosts` is explicitly enabled; default off).
   NEVER run agent-generated commands via host `subprocess` on new paths, and
   NEVER add a host-execution fallback for sandbox failures — convert
   `SandboxError` into `SANDBOX_*` blocks (fail closed). The worker image must
   be built: `docker build -t breachpilot-sandbox:latest docker/sandbox`. See
   `docs/sandbox.md`.

5. **`opencode.jsonc` is editor-local config** (gitignored) for the opencode.ai
   editor's own model provider — it is NOT application config. Don't treat it
   as app state. App config lives in `config.yaml`. **Never copy `~/.codex/auth.json` OAuth tokens into `config.yaml` or logs** (provider `chatgpt` only).

6. **`--target` accepts an IP or a domain** (Phase 4). Domains resolve via
   `tools/validation_utils.resolve_target_to_ip` (`tools/mcp_session.py:255` threads `original_target`/`resolved_ip`) and thread
   `EXPLOIT_TARGET`/`EXPLOIT_TARGET_IP`/`EXPLOIT_TARGET_DOMAIN`/`EXPLOIT_DISCOVERED_TARGETS`
   (`tools/mcp_shared.py:494-534`) env vars into the MCP server. The allowlist matcher supports
   domains + `*.wildcard` + CIDR by design (`tools/validation_utils.py:380-420`).

7. **Ollama is ONE optional provider, not the internal protocol.** Chat/generate
   dispatches through the provider registry (`tools/providers/registry.py`;
   built-ins: `ollama` (default), `opencode_go`, `chatgpt`) to a
   `BaseProvider` adapter, and every consumer receives the canonical
   `ModelClient` (`tools/providers/types.py`) and calls `.chat()` over the
   **BreachPilot model response format** (`model` / `message` / `usage` dict).
   Provider config is `models.provider` + a `providers.<id>` block (legacy
   top-level blocks still resolve; ONE normalization layer:
   `tools.config.loader.get_provider_config`). The ollama Python package is
   an EXTRA (`pip install -e ".[ollama]"`) and its SDK import is isolated to
   `tools/providers/ollama_provider.py` (source-scan guard:
   `tests/test_no_ollama_regression.py`) — Flow A chat can run on another
   provider (`models.provider: opencode_go`, `embeddings.provider: none`);
   checked-in research still selects Ollama with SerpAPI fallback, and frozen
   Flow B's legacy agent loop still uses direct Ollama semantic memory when
   enabled. Embeddings are a separate abstraction
   (`tools/providers/embeddings.py`: `ollama` | `none`); Ollama is the schema
   fallback when omitted, while the checked-in config selects `none` (no
   requests from provider-aware Flow A consumers). `--doctor` probes
   ONLY the active provider (no Ollama endpoints for non-ollama
   selections). Adding provider #4 = adapter + registration + config
   metadata + tests — NO edits to agent/swarm/run-service/doctor/WebUI
   (see [docs/provider-development.md](docs/provider-development.md)).

   **Ollama Cloud is the chat-provider code fallback, not the checked-in
   selection.** If `models.provider` is omitted, the provider fallback is
   Ollama; the checked-in `config.yaml` selects OpenCode Go. When Ollama is
   selected, `ollama.host` defaults to `https://api.ollama.com` (`config.yaml:3`)
   and the Ollama client attaches `Authorization: Bearer $OLLAMA_API_KEY` to
   chat/generate requests. Point `ollama.host` at a local daemon to use that
   endpoint; there is no local-to-cloud probe or fallback.

   Embeddings are selected independently. The schema fallback is Ollama, but
   checked-in config selects `embeddings.provider: none`. Provider-aware Flow A
   memory and skill paths then make no embedding requests and use their
   documented keyword/tag fallbacks. Frozen Flow B's `legacy/agent_loop.py`
   still constructs the legacy Ollama semantic-memory provider when semantic
   memory is enabled; `embeddings.provider: none` does not disable that path.
   Explicit Ollama embeddings use `ollama.embed_host` (falling back to
   `ollama.host` when absent). `OLLAMA_API_KEY` is required for cloud chat;
   missing credentials surface as an auth failure on the first request.

   **ChatGPT is an opt-in provider** (`models.provider: chatgpt`, vendored
   `oauth/` loopback proxy at `127.0.0.1:10531/v1`, adapter
   `tools/providers/chatgpt_provider.py`). Auth is browser OAuth
   ("Sign in with ChatGPT") whose tokens live in `~/.codex/auth.json` —
   **never copy OAuth tokens into `config.yaml` or logs; check
   `is_authenticated()` by file existence only, never read it.** The proxy
   is loopback-only; lifecycle uses openai-oauth's own `--detach`/`stop`
   CLI (never Popen+kill `serve`, and never stop a proxy we didn't start —
   `_we_started`). See [docs/providers.md](docs/providers.md).

8. **CI runs on every push/PR** (`.github/workflows/ci.yml` + codeql +
   dependency-review, `.github/dependabot.yml`): mocked test suite on Python
   3.11-3.13, coverage, repo-wide `ruff check .` + `ruff format --check .` + `mypy --follow-imports=skip tools`, package build, WebUI build+tests. Before a PR run the local commands
   listed in README §CI and verify README flags/config still match reality.

## Workspace dirs (all gitignored runtime state)

- `reports/<run_id>/` — per-run artifacts
- `exploit_workspace/<target_ip>/<attempt_id>/` — exploit attempts + audit JSONL
- `research_workspace/<mission_id>/` — Flow B mission data (SQLite)
- `swarm_workspace/` — swarm artifacts (created on demand)
- `webui/dist/` — built SPA (first `--web` run does `npm install && npm run build`)

## Toolchain notes

- Python 3.11+ (`pyproject.toml` `requires-python = ">=3.11"`; CI matrix 3.11-3.13).
  `pytest asyncio_mode = "auto"`.
- `pyproject.toml` and `requirements.txt` are synced — both list runtime + dev (`pip install -e ".[dev]" == pip install -r requirements.txt`). `requirements.txt` header says “Synced from pyproject.toml”.
- `ruff` config: line-length 120, `select = ["E","F","W","I"]`, `ignore = ["E501"]`.
  Keep security-sensitive diffs readable — don't add heavy lint presets.
- Linux nmap `-O`/`-sS` need root: set `nmap.sudo: true` (uses `sudo -n`) or
  run as root, else `nmap.priv_fallback` (default true) auto-downgrades.
- Linux attacker = full Kali arsenal (searchsploit/metasploit/hydra/
  crackmapexec/impacket); Windows attacker = Python-only fallback.
  OS-aware instructions live in the exploit agent's system prompt.
