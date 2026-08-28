---
title: Secrets Management
description: How api_key_store, secr.json, .webui_secret_key, and ChatGPT OAuth tokens are handled — storage, permissions, rotation, and what never leaves the box.
source: [tools/api_key_store.py, tools/config_cli.py, tools/api/auth.py, app.py, tools/providers/chatgpt_provider.py, tools/doctor.py, config.yaml]
---

# Secrets Management

> Never copy tokens into `config.yaml` or logs. `config.yaml` holds **names** of env vars (`api_key_env` / `token_env`), not values. Secrets live in `secr.json`, process env, or `~/.codex/auth.json`, with file permissions `0o600` where supported.

## Stores

### `secr.json` — provider API keys (`tools/api_key_store.py`)

**File**: `secr.json` (`DEFAULT_API_KEY_FILE = Path("secr.json")`, `api_key_store.py:21`). Gitignored. Shape:

```json
{
  "version": 1,
  "updated_at": "2026-08-24T00:00:00+00:00",
  "api_keys": {
    "OLLAMA_API_KEY": "…",
    "NVD_API_KEY": "…",
    "GITHUB_TOKEN": "…",
    "SERPAPI_API_KEY": "…"
  }
}
```

Legacy files without `version/api_keys` are read as flat `{ENV: value}` for back-compat (`api_key_store.py:93`).

**Which keys** — `configured_api_key_env_names(config)` (`api_key_store.py:33`) collects (deduped):
- `ollama.api_key_env` (default `OLLAMA_API_KEY`) — top-level Ollama cloud fallback
- `research.ollama.api_key_env` (default `OLLAMA_API_KEY`)
- `research.serpapi.api_key_env` (default `SERPAPI_API_KEY`)
- `cve_lookup.api_key_env` (default `NVD_API_KEY`)
- `cve_lookup.github.token_env` (default `GITHUB_TOKEN`)

MCP research gating uses `research_api_key_env_names(config)` (`api_key_store.py:61`) — only `ollama` when `use_web_search/use_web_fetch` true plus `serpapi` when in `provider/fallback_provider`.

**Read path** — `load_api_key_file(path)` (`api_key_store.py:82`) swallows `OSError/JSONDecodeError/TypeError` and returns `{}` on unreadable file — refuses to crash startup. `load_api_keys_into_env(path, allowed_names)` (`api_key_store.py:105`) iterates the file but **skips when `os.environ.get(name)` already truthy** — shell-exported env beats file.

**Write path** — `save_api_keys(path, keys)` (`api_key_store.py:123`) cleans empty values, refuses to overwrite unreadable/invalid store (`raise ValueError`), merges over `load_api_key_file(path)`, writes `{version:1, updated_at: iso, api_keys: merged}` via `NamedTemporaryFile` in `path.parent` with `json.dump(sort_keys=True, indent=2)`, `flush()+os.fsync`, `chmod 0o600` (best-effort on Windows), `os.replace(temp, path)`. Returns sorted saved names.

**Bootstrap** — `bootstrap_api_keys(config, store_path, prompt, force_prompt)` (`api_key_store.py:201`):

1. `allowed = configured_api_key_env_names(config)`
2. `loaded = load_api_keys_into_env(store_path, allowed)` — env-populated keys
3. `missing = [n for n in allowed if not os.environ.get(n)]`
4. If `(prompt or force_prompt) and missing and _can_prompt(force_prompt)` — `_can_prompt` is `force_prompt or sys.stdin.isatty()` (`api_key_store.py:273`)
5. `_prompt_for_api_keys(missing, force_prompt)` — confirms via `questionary.confirm` (or `input y/N` fallback) unless `force_prompt`, then `questionary.password` / `getpass.getpass` per key (leave blank to skip)
6. `saved = save_api_keys(store_path, entered)`; inject entered into `os.environ` when not already set
7. Recompute `missing`; return `ApiKeyBootstrapResult(loaded, saved, missing, store_path)`

CLI wiring: `bootstrap_startup_api_keys(args, prompt=False)` (`tools/config_cli.py`) wraps the above with `config = load_config(args.config)`, `store_path = Path(getattr(args, "api_key_file", DEFAULT_API_KEY_FILE))`, `prompt = prompt and not no_api_key_prompt`, `force_prompt = setup_api_keys`. The interactive prompt fires only in `--menu` mode (`main.py` sets `interactive_startup = bool(args.menu)`) or via `--setup-api-keys` (force).

**When MCP research is gated** — `research_api_keys_available(config)` (`api_key_store.py:177`) returns `True` when `research.enabled==False` or `require_api_key_for_mcp_tools==False` or any `research_api_key_env_names` is in env. Else `disabled_mcp_tools_without_api_key(config)` (`api_key_store.py:186`) returns `{"search_web_exploit","fetch_webpage","deep_research"}`. Disabled tools cleanly return `RESEARCH_API_KEY_MISSING: ... Set one of: {names}; run python main.py --setup-api-keys; or save keys to secr.json.` (`disabled_research_tools_message`, `api_key_store.py:192`).

**Tests** — see `tests/test_config_cli.py` / `test_api_key_store*` style (prompt mocking, file-not-exists, invalid JSON).

### `.webui_secret_key` — WebUI API bearer token (`tools/api/auth.py`)

**File**: `api.token_file: .webui_secret_key` (`config.yaml:390`). Gitignored. Single line token.

**Create/load** — `load_or_create_token(token_file, env_override)` (`api/auth.py:46`):

1. `env_override` (`NETATTACKAI_API_TOKEN` or `os.environ["NETATTACKAI_API_TOKEN"]`) **wins** — returned verbatim, file ignored.
2. If file exists, `read_text().strip()` returned when non-empty.
3. Else `secrets.token_urlsafe(32)` (256-bit) generated, `parent.mkdir(parents=True)`, `write_text(token)`, `chmod 0o600` best-effort, returned.

Called at `app.create_app(config_path)` (`app.py:71`) and again at `main._run_daemon` token reveal (`main.py:870`) — same file, one extra read.

**Auth** — `BearerAuth(token)` (`api/auth.py:72`) is `HTTPBearer(auto_error=False)` with `hmac.compare_digest` (`api/auth.py:88`). Every route except `/health` depends on it. Never logged/returned by API; disclosure only at daemon startup's gated Enter presses (`main.py:874`).

**WebSocket** — `authenticate_websocket(ws, token, allowed_origins)` (`api/auth.py:128`) checks `is_loopback_origin(origin, allowed_origins)` (null/non-loopback always rejected, `api.allowed_origins` only loopback HTTP(S) origins, `port` 1–65535), then `await ws.receive_json()` must be `{"auth": "<token>"}` within 5s, else `4401`.

**Rotation** — delete file + restart daemon. Or set `NETATTACKAI_API_TOKEN` env. Token is per-host, not per-user; multi-operator (`api.multi_operator: true`, `config.yaml:404`) adds user accounts but not a permissions system.

### ChatGPT OAuth (`oauth/` + `~/.codex/auth.json`)

Vendored `oauth/` checkout (`EvanZhouDev/openai-oauth`) + loopback proxy `127.0.0.1:10531/v1` (`config.yaml` `chatgpt.base_url`). Tokens are browser-OAuth only:

- `ChatGptProxyManager.is_authenticated()` (`tools/providers/chatgpt_provider.py`) checks **existence only** of `~/.codex/auth.json` / `$CODEX_HOME/auth.json` — never opens/reads/prints.
- `login` shells out to `bun ./packages/openai-oauth/src/cli.ts login` (or `node dist/cli.js`) — prints `OpenAI OAuth login URL:` + serves callback on `localhost:1455`; tokens written by `openai-oauth` directly to `~/.codex/auth.json`. **No token ever copied into `config.yaml`, Python memory as configured secret, or logs.**
- `ensure_running()` — unauthenticated → `not_authenticated`, never spawns. Health `GET /health` (2s) → reuse (`_we_started=False`). If down & `auto_start`, runs `serve --host --port --detach` then polls `/health` until `start_timeout_seconds`. Idempotent with thread lock.
- `shutdown()` runs `stop` CLI only when `_we_started`; never kills a proxy we didn't start. `doctor._check_chatgpt` (`tools/doctor.py:257`) subchecks provider/source/runtime/oauth_login/proxy_running/models_reachable without reading token.

`config.yaml:chatgpt.enabled` etc. are advisory; `models.provider: chatgpt` is the real selector. `oauth_file: ""` auto-resolves; set only to point at nonstandard location.

### Credential vault (attack-found creds, not provider keys)

`tools/credential_store.py` — encrypted at-rest creds discovered during attack, keyed by `AI_NMAP_VAULT_KEY` env or auto-generated. Access via MCP `cred_store_add/get/list/confirm`. Separate from `secr.json`.

## Permissions

| File | Mode | Where | Windows fallback |
|------|------|-------|------------------|
| `secr.json` | `0o600` | `api_key_store.save_api_keys:160` | `try: chmod` except `OSError: pass` |
| `.webui_secret_key` | `0o600` | `api/auth.load_or_create_token:65` | same best-effort |
| `~/.codex/auth.json` | set by `openai-oauth` | — | — |

All three are gitignored. Verify `.gitignore` covers `secr.json`, `.webui_secret_key`, `.env`, `exploit_workspace/`, `reports/`.

## Rotation and revocation

| Secret | Rotate | Revoke remote |
|--------|--------|---------------|
| `OLLAMA_API_KEY` / `SERPAPI_API_KEY` / `NVD_API_KEY` / `GITHUB_TOKEN` | Edit `secr.json`, delete + `export NEW=…`, or `python main.py --setup-api-keys` then restart; next `load_api_keys_into_env` on boot picks new value (or env override immediately) | Ollama Cloud dashboard / SerpAPI / NVD / GitHub token settings |
| `.webui_secret_key` | `rm .webui_secret_key` + restart daemon, or `export NETATTACKAI_API_TOKEN=new` | — (local daemon only; old WS connections drop at `run_manager.shutdown()`) |
| `~/.codex/auth.json` | Re-run `Sign in with ChatGPT` from menu / `python main.py --doctor` then login | ChatGPT account settings |
| `AI_NMAP_VAULT_KEY` | `export AI_NMAP_VAULT_KEY=new` + migrate store | — |

No migration tool — old `secr.json` entries not yet overlaid by new env remain until overwritten.

## Dos and don'ts

- ✅ `secr.json` is the interactive path; `.env` is the template path. Pick one; env wins if both set.
- ✅ Keep `.webui_secret_key` and `secr.json` out of backups that leave the box.
- âŒ Never `cat` / `echo` tokens into `config.yaml`; never `git add secr.json`; never log `Authorization`.
- âŒ Never read `~/.codex/auth.json`; check `is_authenticated()` by existence only.
- âŒ Never `NETATTACKAI_API_TOKEN` in shell history — use `read -s` or `.env` + export.

## Related

- `docs/configuration/overview.md` — file locations & precedence.
- `docs/configuration/environment.md` — full env var directory.
- `docs/providers.md` — Ollama vs ChatGPT wiring, why embeddings stay Ollama.
