---
title: System Endpoints — Health, Capabilities, Config, Secrets, Models, Providers, Skills, Diagnostics, Goals
sources:
  - tools/api/routes/system/
  - app.py
  - tools/api/auth.py
  - tools/api/errors.py
tests:
  - tests/test_api_auth.py
  - tests/test_api_frontend.py
subsystem: api
---

# System Endpoints

`tools/api/routes/system/__init__.py::create_router` builds the `/api/v1` router and registers the core, config, models, diagnostics, goals, and skills route modules. `app.py` mounts the router. Every route except `GET /health` uses `SystemContext.require_auth` (`tools/api/routes/system/_shared.py`), which delegates to `BearerAuth` and returns 401 for a missing or invalid token.

## `GET /api/v1/health` — `health`

`tools/api/routes/system/core.py` — **no auth**. Response `200` `{version:"v1", ready:true}`.

## `GET /api/v1/capabilities` — `capabilities`

`tools/api/routes/system/core.py` — requires bearer. Reads live `api.max_concurrent_runs` from config. Returns `api_version`, `features` (advisory MCP families + surfaces like `graph_route`, `poc_verification`, etc.), `constraints` (`max_concurrent_runs`, `loopback_only:true`, `manual_tool_calls:true`), `run_options` (modes `recon|attack|fast`, kinds `agent`, flags). The WebUI gates panels on `features`.

## `GET /api/v1/config` — `get_config`

`tools/api/routes/system/config.py` — bearer. Returns the redacted router config via `sanitize(ctx.config)` (`tools/api/errors.py:62`).

## `PATCH /api/v1/config` — `patch_config`

`tools/api/routes/system/config.py` — bearer. Body must be a dict. `SystemContext.apply_config_patch` deep-merges with the current config, then `SystemContext.write_config` validates `api.allowed_origins` and the full config before atomically replacing the file. On success it returns `{status:"ok", config:<sanitized merged config>}`. Errors include `400 invalid_body` and `400 config_invalid`.

The shared write methods are `SystemContext.write_config` and `SystemContext.apply_config_patch` in `tools/api/routes/system/_shared.py`.

## `GET /api/v1/secrets` — `get_secrets`

`tools/api/routes/system/config.py` — bearer. Returns `{keys: {ENV:"configured"|"missing"}}` derived from `configured_api_key_env_names(ctx.config)`, the configured API-key file, and `os.environ` (`tools/api_key_store.py`). Never returns values.

## `PUT /api/v1/secrets` — `put_secrets`

`tools/api/routes/system/config.py` — bearer. Body `{secrets:{name:value}}`. Validates names in `configured_api_key_env_names`, values non-empty strings else `400 invalid_secrets`. Writes via `save_api_keys` + injects into `os.environ`. Response `200 {status:"ok", written:[...]}`.

## `GET /api/v1/models` — `list_models`

`tools/api/routes/system/models.py` — bearer. Returns active `provider`, `default_alias`, `registry`, `info`, and `active_provider` metadata. It also returns a provider-specific block for ChatGPT or OpenCode Go when either is active.

## `POST /api/v1/models` — `add_model`

`tools/api/routes/system/models.py` — bearer. Body `{alias, model}` is stripped; both must be non-empty and are limited to 64 and 256 characters. The route applies the update through `SystemContext.apply_config_patch`, which validates and writes the config. Returns `{status:"ok", alias, model, registry}`.

## `DELETE /api/v1/models/{alias}` — `remove_model`

`tools/api/routes/system/models.py` — bearer. Refuses an unknown alias with `404` and refuses deleting `default_alias` with `400 invalid_model`; otherwise removes the alias from `registry` and `info`, then writes through `SystemContext.write_config`. Response `{status:"ok", alias, deleted:true}`.

## `POST /api/v1/models/provider` — `set_model_provider`

`tools/api/routes/system/models.py` — bearer. Body `{provider}` must be a registered provider id; otherwise the route returns `400 invalid_provider`. It updates `models.provider` and enables that provider's config block. Returns `{status:"ok", provider, registered_providers}`.

## `POST /api/v1/models/refresh` — `refresh_models`

`tools/api/routes/system/models.py` — bearer, Ollama provider only (`400 invalid_provider`). Calls `tools/ollama_models.refresh_model_registry` off-thread; newer same-family model versions are written through the validated config path. The route returns the refresh result and marks it persisted when it applies updates; an unreachable Ollama API returns `503`. The same refresh helper may also run at daemon boot when `models.auto_update` is true.

## `GET /api/v1/system/info` — `get_system_info`

`tools/api/routes/system/diagnostics.py` — bearer. `hostname`, `platform`, `os`, `python`, `local_ips` (`socket.getaddrinfo`), `public_ip` via `urllib.request https://api.ipify.org` 3 s timeout degraded to `null` offline (`tools/api/routes/system/diagnostics.py` off-thread).

## `GET /api/v1/system/telemetry` — `get_telemetry`

`tools/api/routes/system/diagnostics.py` — bearer. Off-thread `workspace_root_from_sources(ctx.config_path)` → `usage_summary` + `read_usage_records(..., limit=50)` (`tools/model_telemetry.py`). Numeric/categorical only, no prompts.

## `GET /api/v1/system/memory` — `get_memory`

`tools/api/routes/system/diagnostics.py` — bearer. Off-thread `_load_memory_sync` (`tools/api/routes/system/_shared.py::_load_memory_sync`): Flow B `lessons` table (no embeddings) + confidence Beta(1,1) aggregation + `attack_memory.db` `attack_memory_items` under `reports_dir` (`_read_attack_memory_db` `reports/**/*.attack_memory.db`). Best-effort empty on error.

## Sandbox and browser status

All routes below are bearer-authenticated in `tools/api/routes/system/diagnostics.py`:

- `GET /api/v1/system/sandbox` returns the current sandbox status and policy;
  invalid sandbox configuration returns `400`.
- `GET /api/v1/system/browser` returns browser configuration, runtime
  availability, health probes, and capabilities. It does not launch a browser.
- `GET /api/v1/system/sandbox/fix/plan` returns a read-only remediation plan.
- `POST /api/v1/system/sandbox/fix` starts one remediation job and returns its
  record. It rejects invalid sandbox configuration with `400` and a concurrent
  active remediation job with `409`.
- `GET /api/v1/system/sandbox/fix/{job_id}` returns the job record; malformed
  or unknown ids return `404`.

## `POST /api/v1/system/reset` — `reset_system`

`tools/api/routes/system/core.py` — bearer. Refuses `409 conflict` if a run is active. Otherwise deletes persisted run rows, removes and recreates the reports directory, exploit workspace, and swarm workspace, and clears research-workspace tables in place while preserving the open database file. Response `{status:"ok", runs_deleted, removed:[...], research_cleared}`.

## `GET /api/v1/plugins` — `list_plugins`

`tools/api/routes/system/core.py` — bearer. `tools.plugins.list_discovered_plugins()` else `[]`.

## `GET /api/v1/skills` — `list_skills`

`tools/api/routes/system/skills.py` — bearer. Lists skills from the runtime registry as `{name, description, tags}`; on error returns `{skills:[], error}`.

## `GET /api/v1/skills/search` — `search_skills`

`tools/api/routes/system/skills.py` — bearer. Query `q` defaults to empty; the route returns matching skills capped at 20 as `{results:[{name,description}]}`.

## `POST /api/v1/diagnostics/doctor` — `run_doctor`

`tools/api/routes/system/diagnostics.py` — bearer. Off-thread `_run_doctor_sync(config_path)` (`tools/api/routes/system/_shared.py::_run_doctor_sync`) which `redirect_stdout` → `tools.doctor.run_doctor`. Response `{exit_code:int, output:str}`.

## `POST /api/v1/diagnostics/self-test` — `run_self_test`

`tools/api/routes/system/diagnostics.py` — bearer. `redirect_stdout` → `await tools.self_test.run_self_test(None)` (`self_test` is async). Response `{exit_code, output}`.

## `GET /api/v1/attack/modules` — `list_attack_modules`

`tools/api/routes/system/core.py` — bearer. `tools.attack_modules.registry.list_modules()` → per-module `{name, description, family, target_services, target_ports, required_cves, destructive_ics}`.

## `GET /api/v1/goals` — `list_goals`

`tools/api/routes/system/goals.py` — bearer. Returns preset goals with `{name, description, risk, compatible, source:"preset"}` and persisted custom goals separately in `custom_goals`. Compatibility is evaluated against `standard_authorized`; high-risk presets require `high_authorized_testing`.

## Custom goals

All routes below are bearer-authenticated in `tools/api/routes/system/goals.py`.

- `POST /api/v1/goals` accepts `{name, objective}`, creates a persisted custom
  goal, and returns `201` with its id and timestamps. Invalid input returns
  `400`; duplicate names return `409`.
- `PATCH /api/v1/goals/{goal_id}` accepts at least one of `name` or
  `objective` and returns the updated goal. Invalid input returns `400`, a
  missing id returns `404`, and duplicate names return `409`.
- `DELETE /api/v1/goals/{goal_id}` returns `{deleted:true, id}`. A missing id
  returns `404`.

## `GET /api/v1/config/schema` — `get_config_schema`

`tools/api/routes/system/config.py` — bearer. Returns `{schema: CONFIG_SCHEMA}` (`tools/config_manager.CONFIG_SCHEMA`) for typed WebUI forms.

## `GET /api/v1/models/live` — `list_live_models`

`tools/api/routes/system/models.py` — bearer. Dispatches live model discovery through the active provider adapter off-thread. Success returns `{models, source:<provider id>}`. Discovery failures return `503` with provider-specific fallback models, `source:"registry"`, and an error message; adding a provider uses the registry and does not require another route branch.

## `GET /api/v1/providers` — `get_providers`

`tools/api/routes/system/models.py` — bearer. Returns active provider id, a registry-driven `providers` list with metadata, and legacy `chatgpt` / `opencode_go` status blocks for the WebUI. No secrets are returned.

## `POST /api/v1/providers/chatgpt/login` — `chatgpt_login`

`tools/api/routes/system/models.py` — bearer. `ChatGptProxyManager.get().run_login(chatgpt_cfg)` off-thread; returns `{ok, url?, reason?}`. Tokens stay in `~/.codex/auth.json`, never in request/response/config.

## `POST /api/v1/providers/chatgpt/proxy/start` — `chatgpt_proxy_start`

`tools/api/routes/system/models.py` — bearer. `ensure_running(chatgpt_cfg)` off-thread.

## `POST /api/v1/providers/chatgpt/proxy/stop` — `chatgpt_proxy_stop`

`tools/api/routes/system/models.py` — bearer. `manager.shutdown(chatgpt_cfg)` off-thread; returns `{ok:true, stopped: we_started}` — never stops a proxy the daemon didn't start.

## `GET /api/v1/skills/{name}` — `get_skill`

`tools/api/routes/system/skills.py` — bearer. `get_registry(ctx.config).get(name)` → `404` if missing else `{name, description, body, sections, tags, references, nist_csf, mitre_attack, domain, subdomain, version}` (`skill_registry_cache`).

## `POST /api/v1/skills` — `install_skill`

`tools/api/routes/system/skills.py` — bearer. Body `{name, markdown}`. Validates name `^[a-z0-9][a-z0-9-]{1,63}$` (`_SKILL_NAME_RE` in `tools/api/routes/system/_shared.py`) and requires non-empty markdown. `_skill_writable_root()` uses the first `skills.roots` entry from `ctx.config`, resolved relative to `ctx.config_path`; it must be a directory. The target must remain under that root (`_resolve_skill_dir` in `_shared.py`). Existing paths return `409`; plugin-contributed directories cannot be written. The route atomically writes `SKILL.md`, validates it with `parse_skill_file`, checks `parsed.name==name`, clears the cache, and returns `{name, description, tags}`.

## `DELETE /api/v1/skills/{name}` — `remove_skill`

`tools/api/routes/system/skills.py` — bearer. Same name validation + root resolution; `404` if missing; refuse plugin-contributed dirs `400 skill_not_writable`; `shutil.rmtree` + `clear_cache()`; response `{name, deleted:true}`.

All system routes include bearer; error envelope is `tools/api/errors.py:42` and handlers at `tools/api/errors.py:71`.
