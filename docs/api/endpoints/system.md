---
title: System Endpoints — Health, Capabilities, Config, Secrets, Models, Providers, Skills, Diagnostics, Goals
sources:
  - tools/api/routes/system.py
  - app.py
  - tools/api/auth.py
  - tools/api/errors.py
tests:
  - tests/test_api_auth.py
  - tests/test_api_frontend.py
subsystem: api
---

# System Endpoints

`tools/api/routes/system.py:1` — `APIRouter(prefix="/api/v1", tags=["system"])`. All routes below are mounted at `/api/v1/*` via `app.py:148`. Every route except `GET /health` depends on `_require_auth` (`tools/api/routes/system.py:49`) → `BearerAuth.__call__` 401 when missing/invalid. Module wiring: `configure(auth, config, config_path)` + `configure_run_manager(run_manager)` (`tools/api/routes/system.py:27`).

## `GET /api/v1/health` — `health`

`tools/api/routes/system.py:56` — **no auth**. Response `200` `{version:"v1", ready:true}`.

## `GET /api/v1/capabilities` — `capabilities`

`tools/api/routes/system.py:62` — requires bearer. Reads live `api.max_concurrent_runs` from config. Returns `api_version`, `features` (advisory MCP families + surfaces like `graph_route`, `poc_verification`, etc.), `constraints` (`max_concurrent_runs`, `loopback_only:true`, `manual_tool_calls:true`), `run_options` (modes `recon|attack|fast`, kinds `agent`, flags). The WebUI gates panels on `features`.

## `GET /api/v1/config` — `get_config`

`tools/api/routes/system.py:136` — bearer. Returns redacted config via `sanitize(_CONFIG)` (`tools/api/errors.py:62`).

## `PATCH /api/v1/config` — `patch_config`

`tools/api/routes/system.py:190` — bearer. Body must be `dict`. Deep-merge via `_merge_config` (`tools/api/routes/system.py:39`), validate with `_write_config` (`tools/api/routes/system.py:142`): rejects `api.allowed_origins` containing non-loopback (`is_loopback_origin`), runs `ConfigValidator.validate()`, atomic `tmp.write + os.replace`. On success `{status:"ok", config: sanitize(merged)}` (`tools/api/routes/system.py:202`). Errors `400 invalid_body`, `400 config_invalid`.

Internal helpers: `_write_config(merged)` and `_apply_config_patch(patch)` (`tools/api/routes/system.py:142`, `:185`).

## `GET /api/v1/secrets` — `get_secrets`

`tools/api/routes/system.py:205` — bearer. Returns `{keys: {ENV:"configured"|"missing"}}` derived from `configured_api_key_env_names(_CONFIG)` + `load_api_key_file` + `os.environ` (`tools/api_key_store.py`). Never returns values.

## `PUT /api/v1/secrets` — `put_secrets`

`tools/api/routes/system.py:227` — bearer. Body `{secrets:{name:value}}`. Validates names in `configured_api_key_env_names`, values non-empty strings else `400 invalid_secrets`. Writes via `save_api_keys` + injects into `os.environ`. Response `200 {status:"ok", written:[...]}`.

## `GET /api/v1/models` — `list_models`

`tools/api/routes/system.py:261` — bearer. Returns `{provider, default_alias, registry, info, chatgpt?}` via `get_ai_provider` / `get_chatgpt_config` (`tools/config_manager.py`).

## `POST /api/v1/models` — `add_model`

`tools/api/routes/system.py:284` — bearer. Body `{alias, model}` stripped, both non-empty, len guards 64/256. `_apply_config_patch({"models":{"registry":{alias:model}}})` + `ConfigValidator`. Returns `{status:"ok", alias, model, registry}`.

## `DELETE /api/v1/models/{alias}` — `remove_model`

`tools/api/routes/system.py:302` — bearer. `copy.deepcopy(_CONFIG)`, refuse unknown `404`, refuse deleting `default_alias` `400 invalid_model`, remove from `registry` + `info`, `_write_config`. Response `{status:"ok", alias, deleted:true}`.

## `POST /api/v1/models/provider` — `set_model_provider`

`tools/api/routes/system.py:323` — bearer. Body `{provider}` must be `ollama|chatgpt` else `400 invalid_provider`. Patches `models.provider`, returns `{status:"ok", provider}`.

## `GET /api/v1/system/info` — `get_system_info`

`tools/api/routes/system.py:338` — bearer. `hostname`, `platform`, `os`, `python`, `local_ips` (`socket.getaddrinfo`), `public_ip` via `urllib.request https://api.ipify.org` 3 s timeout degraded to `null` offline (`tools/api/routes/system.py:368` off-thread).

## `GET /api/v1/system/telemetry` — `get_telemetry`

`tools/api/routes/system.py:380` — bearer. Off-thread `workspace_root_from_sources(_CONFIG_PATH)` → `usage_summary` + `read_usage_records(..., limit=50)` (`tools/model_telemetry.py`). Numeric/categorical only, no prompts.

## `GET /api/v1/system/memory` — `get_memory`

`tools/api/routes/system.py:520` — bearer. Off-thread `_load_memory_sync` (`tools/api/routes/system.py:445`): Flow B `lessons` table (no embeddings) + confidence Beta(1,1) aggregation + `attack_memory.db` `attack_memory_items` under `reports_dir` (`_read_attack_memory_db` `reports/**/*.attack_memory.db`). Best-effort empty on error.

## `POST /api/v1/system/reset` — `reset_system`

`tools/api/routes/system.py:526` — bearer. Refuses `409 conflict` if `run_manager.has_active`. Else `persistence.reset_all()` (keep file), `shutil.rmtree(reports_dir, exploit_workspace, swarm_workspace)` and recreate `reports_dir` + `_init_db()`, wipe `research_workspace` tables in-place (file locked) and delete children. Response `{status:"ok", runs_deleted, removed:[...], research_cleared}`.

## `GET /api/v1/plugins` — `list_plugins`

`tools/api/routes/system.py:611` — bearer. `tools.plugins.list_discovered_plugins()` else `[]`.

## `GET /api/v1/skills` — `list_skills`

`tools/api/routes/system.py:622` — bearer. `get_registry(_CONFIG).list_skills()` → `{name, description, tags}` each; on error `{skills:[], error}`.

## `GET /api/v1/skills/search` — `search_skills`

`tools/api/routes/system.py:638` — bearer. Query `q=""`. `reg.search(q) if q else list_skills()` capped 20 → `{results:[{name,description}]}`.

## `POST /api/v1/diagnostics/doctor` — `run_doctor`

`tools/api/routes/system.py:664` — bearer. Off-thread `_run_doctor_sync(config_path)` (`tools/api/routes/system.py:651`) which `redirect_stdout` → `tools.doctor.run_doctor`. Response `{exit_code:int, output:str}`.

## `POST /api/v1/diagnostics/self-test` — `run_self_test`

`tools/api/routes/system.py:671` — bearer. `redirect_stdout` → `await tools.self_test.run_self_test(None)` (`self_test` is async). Response `{exit_code, output}`.

## `GET /api/v1/attack/modules` — `list_attack_modules`

`tools/api/routes/system.py:688` — bearer. `tools.attack_modules.registry.list_modules()` → per-module `{name, description, family, target_services, target_ports, required_cves, destructive_ics}`.

## `GET /api/v1/goals` — `list_goals`

`tools/api/routes/system.py:713` — bearer. `GoalEngine().presets` → `{name, description, risk, compatible=engine.is_compatible(name,"standard_authorized")}` (`safe|gated` compatible baseline; `high` requires `high_authorized_testing`).

## `GET /api/v1/config/schema` — `get_config_schema`

`tools/api/routes/system.py:743` — bearer. Returns `{schema: CONFIG_SCHEMA}` (`tools/config_manager.CONFIG_SCHEMA`) for typed WebUI forms.

## `GET /api/v1/models/live` — `list_live_models`

`tools/api/routes/system.py:753` — bearer. Provider-aware live probe:

- ChatGPT (`get_ai_provider=="chatgpt"`): `ChatGptProxyManager.get().ensure_running(chatgpt_cfg)` off-thread (idempotent, respects `auto_start` and `is_authenticated`), then `httpx.AsyncClient GET {base_url}/models` 5 s. On any failure (not authenticated, proxy won't start, unreachable) returns `503` JSON `{models: fallback registry or [default_model], source:"registry", error: msg}` (`tools/api/routes/system.py:779`).
- Ollama else: `httpx GET {ollama_host}/api/tags` with `Authorization: Bearer OLLAMA_API_KEY` if present; on success `{models, source:"ollama"}`; on failure `503 {models: registry.values, source:"registry", error}` (`tools/api/routes/system.py:835`).

## `GET /api/v1/providers` — `get_providers`

`tools/api/routes/system.py:857` — bearer. `get_ai_provider` + `get_chatgpt_config` + off-thread `_chatgpt_status_sync` (`is_authenticated` file-existence only + `_health_ok`). Returns `{provider, chatgpt:{enabled, authenticated, proxy_running, host, port, default_model, we_started}}`.

## `POST /api/v1/providers/chatgpt/login` — `chatgpt_login`

`tools/api/routes/system.py:881` — bearer. `ChatGptProxyManager.get().run_login(chatgpt_cfg)` off-thread; returns `{ok, url?, reason?}`. Tokens stay in `~/.codex/auth.json`, never in request/response/config.

## `POST /api/v1/providers/chatgpt/proxy/start` — `chatgpt_proxy_start`

`tools/api/routes/system.py:895` — bearer. `ensure_running(chatgpt_cfg)` off-thread.

## `POST /api/v1/providers/chatgpt/proxy/stop` — `chatgpt_proxy_stop`

`tools/api/routes/system.py:903` — bearer. `manager.shutdown(chatgpt_cfg)` off-thread; returns `{ok:true, stopped: we_started}` — never stops a proxy the daemon didn't start.

## `GET /api/v1/skills/{name}` — `get_skill`

`tools/api/routes/system.py:922` — bearer. `get_registry(_CONFIG).get(name)` → `404` if missing else `{name, description, body, sections, tags, references, nist_csf, mitre_attack, domain, subdomain, version}` (`skill_registry_cache`).

## `POST /api/v1/skills` — `install_skill`

`tools/api/routes/system.py:1023` — bearer. Body `{name, markdown}`. Validates name `^[a-z0-9][a-z0-9-]{1,63}$` (`_SKILL_NAME_RE` `tools/api/routes/system.py:960`), `markdown` non-empty. `_skill_writable_root()` is `skills.roots[0]` (`_CONFIG["skills"]["roots"]` default `["skills"]`) resolved via `_CONFIG_PATH` (`tools/api/routes/system.py:963`), must be directory. `target_dir = resolve(skill_dir)` under root containment check (`_resolve_skill_dir` `tools/api/routes/system.py:1001`). Reject if exists `409`, refuse plugin dirs (`tools/api/routes/system.py:1012`). Write `tmp → SKILL.md` atomic, `parse_skill_file` validate, enforce `parsed.name==name`, `clear_cache()`. Returns `{name, description, tags}`.

## `DELETE /api/v1/skills/{name}` — `remove_skill`

`tools/api/routes/system.py:1101` — bearer. Same name validation + root resolution; `404` if missing; refuse plugin-contributed dirs `400 skill_not_writable`; `shutil.rmtree` + `clear_cache()`; response `{name, deleted:true}`.

All system routes include bearer; error envelope is `tools/api/errors.py:42` and handlers at `tools/api/errors.py:71`.
