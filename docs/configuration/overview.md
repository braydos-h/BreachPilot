---
title: Configuration Overview
description: Loading, precedence, validation, file locations, and env overrides for config.yaml.
source: [config.yaml, tools/config_manager.py, tools/kernel/config.py, tools/config_cli.py, tools/cli_exploit_settings.py, tools/validation_utils.py]
---

# Configuration Overview

Runtime source of truth is `config.yaml` at the repo root. `tools/config_manager.py::CONFIG_SCHEMA` mirrors the same defaults for when the file is missing or a key is absent. `tools/kernel/config.py::load_config` is the pure loader re-exported by `tools/config_cli` and `tools/mcp_shared`.

> `opencode.json` is editor-local (gitignored) for the opencode.ai editor — never application config. App config lives only in `config.yaml` (AGENTS.md rule 5). `mission.yaml` is Flow B scope; the exploit engine reads `config.yaml:exploit` instead.

## File locations

| Path | Purpose | Default | Override | Gitignored |
|------|---------|---------|----------|------------|
| `config.yaml` | Operator defaults (35 top-level blocks, 495 lines). Checked-in lab defaults. | `config.yaml` | `--config <path>` (`main.py:371`) | no |
| `secr.json` | Persisted provider API keys `{version, updated_at, api_keys: {ENV: value}}`, `0o600`. | `secr.json` (`tools/api_key_store.py:21`) | `--api-key-file <path>` (`main.py:398`) | yes |
| `.env` / `.env.example` | Template env file; `.env` never committed. Documents NVD/GITHUB/OLLAMA/SERPAPI + runtime locks. | `.env.example` at root | `python -m dotenv` or manual export | `.env` yes |
| `.webui_secret_key` | WebUI API bearer token (256-bit `secrets.token_urlsafe(32)`, `0o600` best-effort). | `.webui_secret_key` (`config.yaml:390`, `tools/api/auth.py:46`) | `BREACHPILOT_API_TOKEN` env or `api.token_file` | yes |
| `~/.codex/auth.json` / `$CODEX_HOME/auth.json` | ChatGPT OAuth tokens (openai-oauth). Existence-only check; never read/logged. | `~/.codex/auth.json` | `chatgpt.oauth_file` when set (`tools/providers/chatgpt_provider.py`) | n/a (outside repo) |
| `exploit_workspace/` | Per-target attempt artifacts + threat-intel cache | `exploit_workspace` (`exploit.workspace_dir`) | `EXPLOIT_WORKSPACE` env | yes |
| `reports/<run_id>/` | Per-run audit, nmap, session logs | `reports` (`--reports-dir`) | `--reports-dir` | yes |
| `webui/dist/` | Built SPA | `webui/dist/index.html` | n/a (built via `npm run build`) | yes (dist) |

All workspace/run dirs are gitignored. First `--web` run does `npm install && npm run build` (`main.py:565`).

## Loading pipeline

```
cli flag  --config <path>  (default Path("config.yaml"))
        │
        ▼
tools/kernel/config.load_config(path)          # tools/kernel/config.py:11
  ├─ path missing → return {} (no raise)
  ├─ yaml.safe_load(...) or {}                  # yaml parsing
  └─ non-dict root → raise ValueError           # must be mapping
        │
        ▼
tools/config_manager.ConfigValidator(path)      # config_manager.py:703
  ├─ .load()        # loads into self._config
  ├─ .validate()    # errors / warnings / unknown_keys
  ├─ .apply_defaults()  # deep-merge CONFIG_SCHEMA defaults under loaded keys
  └─ .save()        # yaml.safe_dump back to disk
        │
        ▼
load_validated_config(path)                    # config_manager.py:1281
  ├─ raises ValueError on result.is_valid==False
  ├─ logs warnings + unknown_keys
  └─ returns merged config (with defaults)
        │
        ▼
consumers
  ├─ main.py async_main: load_config(config_path) then apply_skills_cli_overrides
  ├─ app.py create_app: load_config or in-memory override (--web sets api.serve_webui in-memory)
  ├─ mcp_exploit_server._create_server / mcp_server / mcp_engine_server
  └─ tools/doctor.run_doctor(config_path) — loads raw yaml separately
```

Two loaders coexist:

- **Validated path** — `load_validated_config` (`config_manager.py:1281`) — raises on errors, used by doctor/self-test and `MCP_BOOT_TIMEOUT_SECONDS` flow. Deep-merges defaults.
- **Light path** — `tools/kernel/config.load_config` (`tools/config_cli.load_config` re-export, `tools/mcp_shared.load_config`) — pure, no defaults, no validation, returns `{}` on missing. Used by `main.py:593`, `mcp_*_server.py`, and `tools/mcp_session.py` where defaults are applied defensively per-consumer (`cfg.get("agent", {}).get(key, default)`).

`ConfigValidator._build_defaults()` (`config_manager.py:1194`) is `copy.deepcopy(CONFIG_SCHEMA)`. `apply_defaults()` (`config_manager.py:1200`) deep-merges `self._config` over `copy.deepcopy(CONFIG_SCHEMA)` — file wins over schema.

Live PATCH: `PATCH /api/v1/system/config` (`tools/api/routes/system.py:110`) atomic deep-merge + re-validation via `ConfigValidator`; loopback `allowed_origins` enforced; writes through `validator.save()`.

Interactive allowlist write: `tools/config_cli.add_target_to_allowlist` (`tools/config_cli.py:21`) normalizes IP via `ipaddress.ip_address` or domain via `tools/validation_utils.is_fqdn`, de-duplicates case-insensitively, and does atomic comment-preserving YAML edit (`_add_allowed_target_to_yaml`, `_yaml_block_end`) — fallback to `yaml.safe_dump` for unusual layouts.

## Precedence (highest wins)

1. **Explicit CLI flag** — e.g. `--model glm`, `--long-session`, `--parallel-swarm`, `--mcp-transport`, `--api-host/--api-port`, `--swarm`, `--adaptive-exploits`, `--multi-model-consult`, `--skills*`, `--target`.
2. **Process env var** — API keys (`OLLAMA_API_KEY`, `NVD_API_KEY`, `GITHUB_TOKEN`, `SERPAPI_API_KEY`, `SHODAN_API_KEY`, `CALDERA_API_KEY`, `TICKETING_TOKEN`), runtime locks (`EXPLOIT_TARGET*`, `EXPLOIT_WORKSPACE`, `BREACHPILOT_API_TOKEN`, `MCP_ALLOW_PUBLIC_BIND`, `AI_NMAP_DEBUG`), embeddings host fallback.
3. **File `config.yaml`** — checked-in operator defaults.
4. **Schema defaults `CONFIG_SCHEMA`** (`tools/config_manager.py:23`) — used when file missing or key absent.

Per-key precedence examples:

| Config key | CLI override | Env override | Notes |
|------------|--------------|--------------|-------|
| `models.default_alias` | `--model <alias>` (`main.py:374`) | — | `run_service/service.py:349` resolves final alias |
| `models.provider` | — | — | `get_ai_provider()` reads `models.provider`; absent → `ollama` |
| `mcp.default_transport` | `--mcp-transport` (`main.py:382`) | — | Ignored on run path — always forced to `http` so target-IP lock reaches server |
| `mcp.http_port` | `--http-port` (`main.py:389`) | — | Also `doctor.py` probes `mcp.http_port` + 8080 |
| `exploit.permission` | — | — | Resolved via `cli_exploit_settings._resolve_exploit_permission` — missing/unknown → `read_only` (recon stays `READ_ONLY` regardless) |
| `exploit.allowed_targets` | `--target` (unioned) | `EXPLOIT_TARGET*` + `EXPLOIT_DISCOVERED_TARGETS` | `_allowed_target_list` (`tools/kernel/allowlist.py`) unions file + env |
| `exploit.attack_max_commands` etc. | `--max-commands/--max-rounds` style via exploit settings builder | — | `long_session` overrides when `ls_active` |
| `long_session.enabled` | `--long-session` (`main.py:426`) | — | `cli_exploit_settings._compute_swarm_timeout:43` checks both |
| `swarm.parallel_enabled` | `--parallel-swarm` (`main.py:410`) | — | Flips `parallel_enabled` to true; gates `route_parallel` + `spawn_subagent` |
| `multi_model.enabled` | `--multi-model-consult` / `--no-multi-model-consult` (`main.py:433`) | `AI_NMAP_MULTI_MODEL_ENABLED` | Tri-state `default=None` → falls back to config |
| `skills.*` | `--skills`, `--skills-include/--skills-exclude`, `--no-skills-reselect` (`main.py:509`) | — | Mutates in-memory `config["skills"]` only (advisory) |
| `api.host` / `api.port` | `--api-host` / `--api-port` (`main.py:559`) | — | Loopback-only; non-loopback exits 2 |
| `api.token_file` | — | `BREACHPILOT_API_TOKEN` | Env wins over file; never logged |
| `ollama.host` / `ollama.embed_host` | — | — | `embed_host` falls back to `host` when absent |
| `ollama.api_key_env` etc. | — | `OLLAMA_API_KEY`, `NVD_API_KEY`, `GITHUB_TOKEN`, `SERPAPI_API_KEY` | Named by `api_key_env` / `token_env` keys; loaded via `api_key_store` |
| `recon.shodan_api_key` | — | `SHODAN_API_KEY` | File value wins; env is fallback (`recon_pipeline.py:287`) |

Plugins (`plugins.enabled/disabled/search_paths/entry_points`) are merged via `tools/plugins.load_plugins(config)` (`main.py:939`) before MCP boot.

## Validation model

`ConfigValidator.validate()` (`config_manager.py:736`) returns `ConfigValidationResult` (`config_manager.py:678`):

- `errors: list[str]` → `is_valid == False` → `load_validated_config` raises `ValueError`; also causes `PATCH /config` 400 and `api.host` non-loopback hard error.
- `warnings: list[str]` → logged, not fatal. Unknown top-level keys → `unknown_keys` (warn) unless plugin-registered (`tools/plugins.PLUGIN_REGISTRY.config_sections`).
- Required sections warning (not error): `ollama`, `models`, `mcp`, `exploit` missing → warning, defaults apply (`config_manager.py:758`).

Per-section rules (warn-not-reject unless noted **ERROR**):

- `ollama`: `host` missing → warning; `host` wrong type → warning.
- `models`: `registry`/`default_alias` missing → warning; `provider` not `ollama|chatgpt` → warning; `roles.<role>` non-string or alias not in `registry` → warning (`config_manager.py:787`).
- `chatgpt`: `port` 1–65535 else warning; `enabled/auto_start` bool; `runtime` ∈ {auto,bun,node}; timeouts non-negative; `models` must be list.
- `mcp`: `default_transport` ∈ {stdio,http,""} else warning; `http_port` 1–65535 else warning.
- `exploit`: mapping check only; allowlist/target lock validated at tool layer (`terminal._target_lock_block`).
- `cve_lookup`: `circuit_failure_threshold` positive int; `circuit_recovery_timeout` positive number; `search_rate_limit_per_minute` non-negative.
- `research`: `provider` ∈ {ollama,serpapi,stdlib}; `fallback_provider` + quality checks; cache/timeout ints; `require_api_key_for_mcp_tools` bool; assistant sub-block bools/ints + alias existence.
- `memory`: `experience_min_samples` positive int; `experience_time_decay_days` number; `attack_memory_enabled` bool; `attack_memory_max_context_chars` ≥1000.
- `outcome_judgment`: `max_inconclusive_attempts` ≥2; thresholds 0.5–1.0; `min_evidence_references` ≥1; `flow_a` bool.
- `reasoning`: `ultrathink` bool; `ultrathink_reflection_interval` positive int; `llm_reflection` bool; `peer_consult_on_failure_threshold` int ≥0.
- `multi_model`: `enabled` bool; `consult_aliases` list of non-empty strings; budget ints ≥1.
- `skills`: `enabled/maybe_enabled/allow_model_lookup/inject_startup_context/reselect_mid_run...` bools; weight ints; `semantic_min_similarity` 0–1; `roots/default_enabled/include_tags/exclude_names` list of non-empty strings; caps positive int.
- `orchestrator`: `semantic_memory` bool (`config_manager.py:1102`).
- `agent`: toggles bool; budgets non-negative int (`max_retries_per_task`, `max_actions`, `generated_code_repair_attempts`) — bools rejected for int keys.
- `eval`: `enabled` bool **ERROR** on type; `output_dir` non-empty **ERROR**; `max_rounds` non-negative **ERROR**; `write_markdown/html` bool **ERROR**.
- `api`: `host` loopback **ERROR** (`127.0.0.1/localhost/::1` else hard error); `port` 1–65535 **ERROR**; `token_file` non-empty **ERROR**; `allowed_origins` list of strings **ERROR**; `event_buffer_size/shutdown_timeout_seconds` non-negative **ERROR**; `serve_webui` bool **ERROR**.

Validation is lenient by design — unknown/invalid values warn rather than crash the run, except `api` and `eval` hard errors and `load()` non-mapping `ValueError`.

## Env overrides in detail

Keys never hold secrets — they hold **env var names**:

| Config key | Names env var | Read at |
|------------|---------------|---------|
| `ollama.api_key_env` | `OLLAMA_API_KEY` | `api_key_store.py:49`, `model_router.py:301`, `doctor.py:160` |
| `research.ollama.api_key_env` | `OLLAMA_API_KEY` | same |
| `research.serpapi.api_key_env` | `SERPAPI_API_KEY` | `mcp_shared.py:160`, `web_researcher.py:182` |
| `cve_lookup.api_key_env` | `NVD_API_KEY` | `mcp_shared:109`, `cve_lookup.py:62` |
| `cve_lookup.github.token_env` | `GITHUB_TOKEN` | `exploit_search.py:190`, `api_key_store.py:53` |
| `threat_intel.github_token_env` | `GITHUB_TOKEN` | `threat_intel.py:65` |
| `recon.shodan_api_key` | `SHODAN_API_KEY` (fallback) | `recon_pipeline:287` |
| `caldera.api_key_env` | `CALDERA_API_KEY` | `plugins/caldera/plugin.py:42` |
| `ticketing.token_env` | `TICKETING_TOKEN` | `ticketing.py:33` |
| `api.token_file` | `BREACHPILOT_API_TOKEN` | `app.py:71`, `api/auth.py:46` |

Runtime target-lock env (threaded by `tools/mcp_session.py:255`):

- `EXPLOIT_TARGET` — literal `--target` (IP or domain) — primary allowlist identity.
- `EXPLOIT_TARGET_IP` — resolved IP for domain target.
- `EXPLOIT_TARGET_DOMAIN` — original domain string.
- `EXPLOIT_DISCOVERED_TARGETS` — CSV of subdomain / IP discovered mid-run (`mcp_shared.add_discovered_target`).
- `EXPLOIT_WORKSPACE` — workspace root override; also influences KEV cache path (`cve_lookup.py:171`).

Other: `MCP_ALLOW_PUBLIC_BIND=1` + `--allow-public-bind` two-person rule; `MCP_HTTP_TOKEN` optional bearer for MCP HTTP; `AI_NMAP_DEBUG=1` (`--debug`); `AI_NMAP_ACTIVE_MODEL_ALIAS`, `AI_NMAP_MULTI_MODEL_ENABLED` threaded into MCP server.

See `docs/configuration/environment.md` for full `.env.example` mapping and `docs/configuration/secrets.md` for `secr.json` + provider auth.

## Restart vs live

| Change | Requires restart | Why |
|--------|------------------|-----|
| `ollama.host` / `embed_host` / `model` | yes | `ModelClient` built at boot (`model_router._build_model_client`) |
| `models.*` (registry, default_alias, provider, roles, info.context_window) | yes | Router + context compactor read at `build_router` / loop start |
| `mcp.default_transport` / `http_host` / `http_port` / `engine_mcp.*` | yes | Server bind; `doctor.py` port probes |
| `nmap.*` | no — next recon | Read per `recon_pipeline` / `mcp_server` call |
| `exploit.*` (permission, budgets, allowlist, shell, workspace, stealth, pivot) | no — next `build_cli_exploit_settings` / MCP check | Allowlist also live via `add_target_to_allowlist` atomic edit |
| `cve_lookup.*`, `research.*`, `threat_intel.*` | no — next `build_*` | Factories build per-request clients with fresh settings |
| `swarm.*`, `reasoning.*`, `memory.*`, `skills.*`, `agent.*` | no — next orchestration | Read defensively via `.get(..., default)`; `skills` CLI overrides are in-memory only |
| `api.*` | yes (daemon) | `app.create_app` / `uvicorn.run`; `--api-host/port` override is per-invocation |
| Secrets (`OLLAMA_API_KEY` etc.) | no — env load at `bootstrap_startup_api_keys` | `load_api_keys_into_env` only sets when `os.environ[name]` absent; re-export needed for MCP subprocess |

`PATCH /api/v1/system/config` is the live path for `api`-safe keys; a malformed patch is rejected before write. Verify with `python main.py --doctor` (Python/nmap/Ollama/config/ports/workspace) and `python main.py --self-test` (localhost smoke) before sessions (see `docs/configuration/validation.md`).

## Related

- `docs/configuration/config-reference-generated.md` — machine-readable table for every key.
- `docs/configuration/validation.md` — validator error modes.
- `docs/configuration/environment.md` — `.env` + env var reference.
- `docs/configuration/secrets.md` — `secr.json` / `.webui_secret_key` / ChatGPT OAuth.
- `docs/reference/cli-generated.md` — every CLI flag from `main.parse_args`.
