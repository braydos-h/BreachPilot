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

# Tests (248 files in tests/, all mock subprocess/network — no live Nmap)
python -m pytest tests/ -v                                            # full suite
python -m pytest tests/test_scope_gate.py -v                          # one file
python -m pytest tests/test_recon_pipeline.py::TestClass::test_method # one test
python -m pytest tests/ -v -k "scope"                                 # by keyword
python -m pytest --cov=tools --cov=main --cov=cli               # coverage

# Lint (repo-wide, CI honest: 0 errors, 0 format diffs)
python -m pip install -e ".[dev]"   # ruff + pytest + coverage + mypy + build + twine
ruff check .                        # must pass (0 errors; per-file-ignores document intentional patterns)
ruff format --check .               # must pass (0 diffs)
mypy --follow-imports=skip tools    # must pass (216 files; disables documented in pyproject.toml:136)
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
   and `legacy/` (`legacy/agent_loop.py`, `legacy/tool_router.py`, `legacy/risk_controller.py`,
   `legacy/mission.py`, `db.py` carry recon safety). Flow B is frozen in `legacy/` — root shims
   (`cli.py`, `agent_loop.py`, etc.) are `DeprecationWarning` shims for one release; new code must
   use Flow A or `legacy.*` for frozen reference. See `legacy/README.md`.
   - **Flow A** (modern, canonical): `main.py` / `app.py` →
     `tools/exploit_agent/`, `tools/mcp_tools/`, `tools/swarm/`,
     `tools/autonomous_orchestrator.py`, `tools/run_service/`, `tools/api/`.
   - **Flow B** (legacy, frozen `legacy/`): `legacy/cli.py` + `legacy/agent_loop.py` /
     `legacy/mission.py` / `db.py` / `scope_gate.py` / etc. Shares `db.py`/`mission.py` schemas only.

3. **The one attack-mode safety is the target-IP allowlist lock**, enforced in
   the MCP tool layer (`tools/mcp_shared._allowed_target_list` +
   `tools/mcp_tools/terminal._target_lock_block`), not in
   `tools/exploit_agent/policy.py`. `full_access` auto-approves everything with
   no command/scope/pivot inspection. Do not re-add the removed command-content
   / scope / pivot gates without first ensuring the allowlist covers the path
   you're de-restricting — the allowlist IS the lock. Recon stays `read_only`
   via `_resolve_exploit_permission`'s missing-key fallback.

4. **New exploit MCP tools: single-source registration** — add `@audit_tool` (or `@require_allowlist()` for target-touching) in `tools/mcp_tools/<family>.py` only; `mcp_exploit_server.py` auto-discovers every `register_*_tools` via `tools/mcp_tools/registry.py:collect_tools()` (pkgutil + AST validation, fails CI if decorator missing). No manual list edit in `mcp_exploit_server.py`. `tools/mcp_tools/registry.py` is central wiring. Target-touching = `@require_allowlist()` + `validate_target_or_ip`.

5. **`opencode.json` is editor-local config** (gitignored) for the opencode.ai
   editor's own model provider — it is NOT application config. Don't treat it
   as app state. App config lives in `config.yaml`. **Never copy `~/.codex/auth.json` OAuth tokens into `config.yaml` or logs** (provider `chatgpt` only).

6. **`--target` accepts an IP or a domain** (Phase 4). Domains resolve via
   `tools/validation_utils.resolve_target_to_ip` (`tools/mcp_session.py:255` threads `original_target`/`resolved_ip`) and thread
   `EXPLOIT_TARGET`/`EXPLOIT_TARGET_IP`/`EXPLOIT_TARGET_DOMAIN`/`EXPLOIT_DISCOVERED_TARGETS`
   (`tools/mcp_shared.py:494-534`) env vars into the MCP server. The allowlist matcher supports
   domains + `*.wildcard` + CIDR by design (`tools/validation_utils.py:380-420`).

7. **Ollama Cloud is the default model path.** `ollama.host` defaults to
   `https://api.ollama.com` (`config.yaml:3`); the ollama Python client auto-attaches
   `Authorization: Bearer $OLLAMA_API_KEY` to every chat/generate request, so
   a host swap is the whole wiring (no probe, no local→cloud fallback).
   Override `ollama.host` in config.yaml to point at a local daemon and the
   same code path runs against it. Embeddings stay local by default via
   `ollama.embed_host` (falls back to `ollama.host` when absent) —
   `nomic-embed-text` is small enough to self-host. `OLLAMA_API_KEY` env is
   required for the cloud path; missing key surfaces as auth failure on the
   first chat.

   **ChatGPT is an opt-in alternative provider** (`models.provider: chatgpt`,
   vendored `oauth/` loopback proxy at `127.0.0.1:10531/v1`). The single
   seam is `tools/model_router.py::_build_model_client` — it takes an injectable
   `raw_client`; `ollama` (default) builds `ollama.Client`, `chatgpt` injects a
   `ChatGptProxyClient` (`tools/providers/chatgpt_provider.py`). Consumers stay
   untouched (they already receive a `ModelClient`). Auth is browser OAuth
   ("Sign in with ChatGPT") whose tokens live in `~/.codex/auth.json` — **never
   copy OAuth tokens into `config.yaml` or logs; check `is_authenticated()` by
   file existence only, never read it.** The proxy is loopback-only; lifecycle
   uses openai-oauth's own `--detach`/`stop` CLI (never Popen+kill `serve`, and
   never stop a proxy we didn't start — `_we_started`). Embeddings stay on
   Ollama under either provider. `--doctor` runs `_check_chatgpt` only when
   `provider: chatgpt` (default Ollama doctor output unchanged). See
   [docs/providers.md](docs/providers.md).

8. **CI runs on every push/PR** (`.github/workflows/ci.yml` + codeql +
   dependency-review, `.github/dependabot.yml`): mocked test suite on Python
   3.11-3.13, coverage, repo-wide `ruff check .` + `ruff format --check .` + `mypy --follow-imports=skip tools`, package build, WebUI build+tests. Before a PR run the local commands
   listed in README §CI and verify README flags/config still match reality.

9. **Agents must NEVER push to GitHub or create new branches.** Do not run
   `git push`, `git push --force`, `git branch`, `git checkout -b`,
   `git switch -c`, `gh repo create`, or any `gh` command that creates/pushes
   a branch or PR. All work stays on the current local branch only. If a
   remote update is needed, tell the user what to push and let them do it
   manually. This is enforced by `permission.bash` deny rules in
   `opencode.json` / `~/.config/opencode/opencode.json` (`git push*` →
   `deny`, `git checkout -b*` → `deny`, etc.) and by the `pre-push` git hook
   — do not bypass or remove those guards.

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
- Windows attacker = Python-only exploits; Linux attacker = full Kali arsenal
  (searchsploit/metasploit/hydra/crackmapexec/impacket). OS-aware instructions
  live in the exploit agent's system prompt.