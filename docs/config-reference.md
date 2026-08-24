# Config Reference (`config.yaml`)

Runtime source of truth for all engine behavior. This file documents every
top-level section and key, where each is consumed, and which CLI flags / env
vars can override it.

> **`opencode.json` is NOT app config.** It is editor-local config (gitignored)
> for the opencode.ai editor's own model provider. Application config lives
> only in `config.yaml` (AGENTS.md rule 5). `mission.yaml` is Flow B's mission
> scope file — the exploit engine reads its scope rules from
> `config.yaml`'s `exploit` block instead (config.yaml:112-125).

## Purpose

- `config.yaml` is the checked-in operator defaults; `tools/config_manager.py::CONFIG_SCHEMA` mirrors the same defaults for when the file is missing or a key is absent (config_manager.py:22-476).
- Every top-level key is consumed somewhere; a missing key almost always falls back to a schema default rather than failing.
- Secrets never live here — they are env vars (or `secr.json` via `--setup-api-keys`), named by `api_key_env` / `token_env` keys.

## Load & validation flow

| Step | Where | Behavior |
|------|-------|----------|
| Load YAML | `ConfigValidator.load` (config_manager.py:528-542) | Missing file → defaults; non-mapping → `ValueError` |
| Validate | `ConfigValidator.validate` (config_manager.py:544-948) | Unknown top-level keys → warnings (plugin-registered sections exempt, :553-562); type/range checks per section; **errors** for hard violations (e.g. `api.host` non-loopback, :921-926) |
| Merge defaults | `apply_defaults` (config_manager.py:963-979) | Deep-merge loaded config over `CONFIG_SCHEMA` defaults |
| Entry points | `load_validated_config` (config_manager.py:1043-1058) raises on errors, logs warnings; `main.py:596` and `mcp_*_server.py` use the lighter `tools/config_cli.load_config` |
| Live PATCH | `PATCH /config` (tools/api/routes/system.py:110) | Atomic deep-merge, re-validated through `ConfigValidator`; loopback-only `allowed_origins` enforced |

Required sections (warned if absent, defaults apply): `ollama`, `models`,
`mcp`, `exploit` (config_manager.py:565-569).

## Config CLI

There is no dedicated `config` subcommand; config interaction is via flags on
`main.py` and helpers in `tools/config_cli.py`:

| Command / flag | What it does | Source |
|----------------|--------------|--------|
| `--config <path>` | Path to the YAML file (default `config.yaml`) | main.py:349 |
| `--setup-api-keys` / `--api-key-file` / `--no-api-key-prompt` | Prompt for provider keys, persist to `secr.json`, load into env at boot | main.py:357-359; `bootstrap_startup_api_keys` config_cli.py:175-194; `tools/api_key_store.py` |
| Start New Session (target entry) | Persists target into `exploit.allowed_targets` via atomic, comment-preserving YAML edit | `add_target_to_allowlist` config_cli.py:30-93, `_add_allowed_target_to_yaml` :96-148 |
| `--skills*` flags | Mutate the in-memory `config["skills"]` dict only (advisory) | `apply_skills_cli_overrides` tools/skills_cli.py:23-80 |
| `--doctor` | Loads config, checks ollama host/models/nmap/ports/workspace | tools/doctor.py:305-419 |
| `--self-test` | Same config reads as doctor, localhost smoke test | tools/self_test.py:101-115 |

**Change config → verify with `python main.py --doctor`** (env, nmap, Ollama
reachability, model registry, port conflicts) and `python main.py --self-test`
(a safe localhost smoke test) before running sessions.

## Env var reference

| Env var | Default | Purpose | Set by config key | Read at |
|---------|---------|---------|-------------------|---------|
| `OLLAMA_API_KEY` | — | Bearer token for Ollama Cloud; missing → 401 on first chat | `ollama.api_key_env` (also `research.ollama.api_key_env`) | model_router.py:301-304, doctor.py:154, api_key_store.py:49-50 |
| `NVD_API_KEY` | — | NVD API key (raises rate limit) | `cve_lookup.api_key_env` | mcp_shared.py:109, cve_lookup.py:62 |
| `GITHUB_TOKEN` | — | GitHub Search token for `cve_to_poc` (60/hr unauth limit) | `cve_lookup.github.token_env` | api_key_store.py:53, exploit_search.py:190-237 |
| `SERPAPI_API_KEY` | — | SerpAPI key for web research | `research.serpapi.api_key_env` | mcp_shared.py:160, web_researcher.py:182 |
| `SHODAN_API_KEY` | — | Shodan key for passive OSINT (config key wins) | `recon.shodan_api_key` | recon_pipeline.py:287 |
| `EXPLOIT_TARGET` | — | Operator's literal `--target` (IP or domain); the allowlist lock's primary identity, unioned at check time | set by `tools/mcp_session.py:255` from `--target` | mcp_shared.py:523 |
| `EXPLOIT_TARGET_IP` | — | Resolved IP for a domain `--target` | mcp_session.py:265 | mcp_shared.py:523 |
| `EXPLOIT_TARGET_DOMAIN` | — | Domain string for a domain `--target` | mcp_session.py:266 | mcp_shared.py:523 |
| `EXPLOIT_DISCOVERED_TARGETS` | — | Comma-separated subdomains/IPs auto-authorized mid-run | `add_discovered_target` mcp_shared.py:537-555 | mcp_shared.py:528-533 |
| `EXPLOIT_WORKSPACE` | `exploit_workspace` | Exploit workspace root override | set by mcp_session.py:256 | cve_lookup.py:171 (KEV cache), mcp_tools/workspace.py:139 |
| `NETATTACKAI_API_TOKEN` | token file | WebUI daemon bearer token override (never logged) | `api.token_file` | app.py:71, tools/api/auth.py:46 |
| `MCP_HTTP_TOKEN` | — | Optional bearer auth for MCP HTTP transport | — | mcp_shared.run_mcp_http_server, mcp_engine_server.py:27 |
| `MCP_ALLOW_PUBLIC_BIND` | — | Second half of the two-person rule for non-loopback MCP binds | — | mcp_shared.run_mcp_http_server |
| `AI_NMAP_ACTIVE_MODEL_ALIAS` | — | Active model alias threaded into the MCP server subprocess | set by mcp_session.py:270 | mcp_tools/registry.py:201, peer_models.py:80 |
| `AI_NMAP_DEBUG` | — | Debug logging switch | set by main.py:590 from `--debug` | exploit_agent |
| `RESEARCH_WORKSPACE` | `research_workspace` | Flow B research workspace | — | db.py:806, model_telemetry.py:111 |

## Top-level sections

### `ollama:` (config.yaml:1-14) — model backend

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `host` | str | `https://api.ollama.com` | Ollama endpoint for chat/generate (cloud default; point at a local daemon to go local) | config_manager.py:996, model_router.py:287-316, doctor.py:320 |
| `model` | str | `glm-5.2:cloud` | Default concrete model id | config_manager.py:31, interactive_menu.py:452 (menu default write) |
| `api_key_env` | str | `OLLAMA_API_KEY` | Env var holding the bearer token | api_key_store.py:49 |
| `embed_host` | str | `http://localhost:11434` | Embedding host (falls back to `host`) | config_manager.py:998-1006, exploit_agent/loop.py:478, skill_embeddings.py:180-186 |

### `models:` (config.yaml:15-44) — model registry

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `provider` | enum | `ollama` | Active chat/generate provider (`ollama`\|`chatgpt`); absent = `ollama` (today's behavior). Warn-only validated. | config_manager.py `get_ai_provider`, model_router.py `build_router`/`build_model_client_for_provider`, run_service/service.py, doctor.py, api/routes/system.py |
| `registry` | map[alias→model id] | kimi/deepseek/deepseek_flash/glm/minimax | Alias → concrete cloud model mapping (Ollama path) | config_manager.py:1011, doctor.py:321, run_service/service.py:345, mcp_tools/registry.py:158-200 |
| `default_alias` | str | `glm` | Active model alias (Ollama path; ChatGPT path uses `chatgpt.default_model`) | config_manager.py:1008, run_service/service.py:349, eval_harness.py:399, agent_loop.py:253 |
| `info.<alias>.context_window` | int | per-model | Source of truth for the adaptive context compactor | model_router.py:202-221, exploit_agent/context.py:63-104 |
| `info.<alias>.label/description` | str | per-model | Display metadata | model_router.py:130, api routes/system.py:193-194 |

### `chatgpt:` (top-level; absent from config.yaml by default) — ChatGPT provider (opt-in)

Opt-in alternative chat/generate provider backed by the vendored
`openai-oauth/` loopback proxy. Active only when `models.provider: chatgpt`.
Embeddings stay on Ollama regardless. See
[docs/providers.md § ChatGPT provider](providers.md#chatgpt-provider-openai-oauth).

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `false` | Master switch (advisory; `models.provider` is the real selector) | config_manager.py `get_chatgpt_config` |
| `host` | str | `127.0.0.1` | Proxy bind — **loopback-only; do not point at a non-loopback interface** | chatgpt_provider.py `ensure_running` |
| `port` | int | `10531` | Proxy port | chatgpt_provider.py `ensure_running` |
| `base_url` | str | `http://127.0.0.1:10531/v1` | OpenAI-compatible endpoint the adapter POSTs to | chatgpt_provider.py `ChatGptProxyClient`, `discover_models` |
| `auto_start` | bool | `true` | Start the vendored proxy if `/health` is down | chatgpt_provider.py `ensure_running` |
| `local_repo` | str | `./oauth` | Path to the vendored checkout (cwd for CLI subprocess) | chatgpt_provider.py `_resolve_runtime`/`ensure_running`/`run_login`/`shutdown` |
| `runtime` | str | `auto` | `auto`\|`bun`\|`node` — how to run the openai-oauth CLI | chatgpt_provider.py `_resolve_runtime` |
| `request_timeout_seconds` | int | `300` | httpx timeout for `/v1/chat/completions` | chatgpt_provider.py `ChatGptProxyClient`, model_router.py |
| `default_model` | str | `gpt-5.2` | Fallback model id when `/v1/models` discovery fails; also the session-titler model | model_router.py `_build_chatgpt_router`, session_titler.py |
| `models` | list[str] | `[]` | Override model list; `[]` = discover from `/v1/models` | model_router.py `_build_chatgpt_router` |
| `context_window` | int | `128000` | Conservative context window (`/v1/models` returns no metadata) | model_router.py, exploit_agent/context.py |
| `login_timeout_seconds` | int | `300` | `login` CLI subprocess timeout | chatgpt_provider.py `run_login` |
| `start_timeout_seconds` | int | `30` | `/health` poll budget when auto-starting | chatgpt_provider.py `ensure_running` |
| `discover_cache_seconds` | int | `300` | `/v1/models` discovery cache TTL | chatgpt_provider.py `discover_models` |
| `oauth_file` | str | `""` | `""` = auto-resolve `~/.codex/auth.json` \| `$CODEX_HOME/auth.json` (existence only — never read) | chatgpt_provider.py `is_authenticated` |

### `mcp:` (config.yaml:45-46) — exploit MCP transport

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `default_transport` | str | `stdio` | Default exploit-server transport (`stdio`\|`http`) | config_manager.py:1014; CLI `--mcp-transport` (main.py:353) is **ignored on the run path** — always forced to `http` so the target-IP lock reaches the server |
| `http_host` / `http_port` | str / int | `127.0.0.1` / `8001` | HTTP transport bind (schema default; absent from config.yaml) | doctor.py:326, self_test.py:106, eval_harness.py:409, run_service/service.py:446 |

### `engine_mcp:` (config.yaml:54-57) — advisory MCP server for foreign AI assistants

Read-only surface (skill search, NVD CVE lookup, run history); no target
touching. CLI-runnable regardless; block supplies entrypoint defaults.

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `true` | Advertise/enable the engine server | mcp_engine_server.py:201-211 (config loaded for CLI defaults) |
| `host` | str | `127.0.0.1` | Loopback-only bind | mcp_engine_server.py:22-27 |
| `port` | int | `8002` | HTTP port | mcp_engine_server.py:22 |

### `nmap:` (config.yaml:62-65) — Linux-friendly nmap invocation

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `path` | str | `nmap` | Binary override when not on PATH | recon_pipeline.py:289, mcp_server.py:178, doctor.py:331 |
| `sudo` | bool | `false` | Run nmap via `sudo -n` for root-only `-O`/`-sS` | recon_pipeline.py:290, tools/nmap_priv |
| `priv_fallback` | bool | `true` | Auto-downgrade `-sS`/`-O` → `-sT` instead of failing | recon_pipeline.py:291, tools/nmap_priv |

### `exploit:` (config.yaml:66-155) — attack path

**The target-IP allowlist lock is THE safety gate** — `require_explicit_allowlist`
+ `allowed_targets` unioned with the `EXPLOIT_TARGET*` env vars
(`_allowed_target_list` mcp_shared.py:494-534, `_check_allowlist` :558-571).
`permission: full_access` auto-approves every action; recon is **always**
`READ_ONLY` regardless of config (cli_exploit_settings.py:157-159).

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `true` | Master switch for exploit path | mcp_shared.py:77 |
| `mode` | str | `standalone` | Run mode | cli_exploit_settings.py:128 |
| `permission` | enum | `full_access` | `full_access`/`approve_only`/`read_only`; unknown or **missing** → `read_only` (safe baseline) | cli_exploit_settings.py:12-30, mcp-tools.md:171 |
| `attack_mode` | bool | `true` | Live attack posture | cli_exploit_settings.py:131 |
| `terminal` | str | `visible` | Terminal echo mode | cli_exploit_settings.py:131 |
| `command_timeout_seconds` | int | `300` | Per-command timeout | cli_exploit_settings.py:132 |
| `max_commands_per_session` | int | `9999` | Command budget | cli_exploit_settings.py:133 |
| `max_rounds` | int | `200` | Round cap (recon/analysis) | cli_exploit_settings.py:134 |
| `attack_max_commands` | int | `150` | Attack-mode command budget | cli_exploit_settings.py:123 (long-session overrides, :119) |
| `attack_max_rounds` | int | `50` | Attack-mode round cap | cli_exploit_settings.py:124 |
| `attack_max_duration_minutes` | int | `360` | Attack-mode wall clock | cli_exploit_settings.py:125 |
| `context_summarize_every` | int | `50` | Min gap between context compactions | cli_exploit_settings.py:140, exploit_agent/context.py:596 |
| `auto_post_exploit` | bool | `true` | Auto-run post-exploit phase | cli_exploit_settings.py:141 |
| `max_pivot_depth` | int | `2` | Pivot recursion cap | cli_exploit_settings.py:142, autonomous_orchestrator.py:1091,1638 |
| `workspace_dir` | str | `exploit_workspace` | Workspace root | cli_exploit_settings.py:148, interactive_menu.py:417 |
| `loot_workspace` | str | `exploit_workspace/loot` | Loot dir | cli_exploit_settings.py:144 |
| `attacker_os` | str | `auto` | OS-aware instructions/tools | exploit_agent/loop.py:378 |
| `searchsploit_path` | str | `searchsploit` | Searchsploit binary | mcp_shared.py:78, doctor.py:123 |
| `shell` | str | `bash` | Shell for `run_exploit_terminal` (cmd.exe on Windows) | cli_exploit_settings.py:146 |
| `msfconsole_path` | str | `msfconsole` | Metasploit console binary | cli_exploit_settings.py:147, mcp_tools/metasploit.py:83 |
| `web_search` | bool | `true` | Web search for exploit intel | mcp_shared.py:73-87 (via `search` block) |
| `max_query_chars` / `cache_ttl_seconds` / `cache_max_entries` | int | `200` / `3600` / `50` | ExploitSearch cache limits | mcp_shared.py:85-87 |
| `require_explicit_allowlist` | bool | `true` | **The target-IP lock** — when true every target-touching tool checks the allowlist | mcp_shared.py:561,635; mcp_exploit_server.py:141 |
| `allowed_targets` | list[str] | `[127.0.0.1]` | Operator-authorized hosts (IP, domain, `*.wildcard`, CIDR); Start New Session persists here | mcp_shared.py:521, config_cli.py:30-93, exploit_agent/loop.py:267 |
| `disallowed_assets` / `forbidden_actions` | list[str] | `[]` | Flow A scope opt-outs (matched against `_TOOL_ACTION_CATEGORY`); hard-forbidden actions are always blocked by `scope_gate._HARD_FORBIDDEN_ACTIONS` | exploit_session.py:59-60, config.yaml:112-125 |
| `ad_kerberos.enabled` + per-tool flags | bool | `false` (all; `smb_signing_check: true`) | AD/Kerberos post-exploit suite — master + per-tool must both be true | mcp_tools/ad.py:36, tests/test_ad_mcp_tools.py |
| `msf.recipes_enabled` / `auto_local_exploit_suggester` | bool | `false` | MSF recipe dispatch + advisory LES task | mcp_tools/metasploit.py, autonomous_orchestrator.py:1114-1115 |
| `listeners.tls/dns/https_beacon/socks_pivot` | bool | `false` | Extended C2 listener types (legacy nc/socat/http ungated) | persistent_session_manager.py:399-524, tests/test_listeners_extended.py |

### `stealth:` (config.yaml:156-159) — legacy stealth flags

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `rotate_ua` | bool | `false` | Rotate User-Agent across HTTP egress | interactive_menu.py:387 (superseded by `opsec.ua_rotation`) |
| `dns_over_https` | bool | `false` | Resolve via DoH | interactive_menu.py:387 (superseded by `opsec.doh`) |
| `doh_provider` | str | `cloudflare` | `cloudflare`\|`google` | opsec.py:63,95 |

### `cve_lookup:` (config.yaml:160-179) — NVD / vuln-intel

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `true` | NVD lookup master switch | mcp_shared.py:103 |
| `max_results` | int | `5` | Results per lookup | mcp_shared.py:105 |
| `rate_limit_seconds` | float | `6.0` | Per-instance NVD gap (fallback when no shared limiter) | mcp_shared.py:108, cve_lookup.py:61 |
| `timeout_seconds` | int | `30` | HTTP timeout | mcp_shared.py:104 |
| `cache_ttl_seconds` / `cache_max_entries` | int | `3600` / `100` | Cache bounds | mcp_shared.py:106-107 |
| `api_key_env` | str | `NVD_API_KEY` | Key env name | mcp_shared.py:109, api_key_store.py:52 |
| `circuit_failure_threshold` | int | `5` | Breaker opens after N consecutive failures | mcp_shared.py:110, cve_lookup.py:69 |
| `circuit_recovery_timeout` | float | `60.0` | Half-open probe wait | mcp_shared.py:111, cve_lookup.py:70 |
| `search_rate_limit_per_minute` | number | `10` | Process-wide shared NVD budget (0 disables) | mcp_shared.py:113-114 |
| `epss_enabled` / `kev_enabled` | bool | `true` | EPSS/KEV enrichment (lab default ON, live out of the box) | cve_lookup.py:73-74,246-247 |
| `kev_cache_ttl_seconds` | int | `86400` | KEV catalog refresh TTL | cve_lookup.py:75,182 |
| `kev_cache_path` | str | `""` | `""` = `exploit_workspace/.kev_catalog.json` | cve_lookup.py:76,170-171 |
| `github.token_env` | str | `GITHUB_TOKEN` | GitHub token for `cve_to_poc` (optional; unauth 60/hr fallback) | api_key_store.py:53, exploit_search.py:190-237 |

### `research:` (config.yaml:180-213) — web research

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `true` | Research subsystem | mcp_shared.py:129, api_key_store.py:177 |
| `provider` / `fallback_provider` | str | `ollama` / `serpapi` | Provider and fallback (`ollama`\|`serpapi`\|`stdlib`) | mcp_shared.py:130-131 |
| `timeout_seconds` | int | `15` | HTTP timeout | mcp_shared.py:132 |
| `max_results` | int | `8` | Result cap | mcp_shared.py:133 |
| `max_fetch_depth` | int | `5` | Page-fetch depth | mcp_shared.py:134, web_researcher.py:677-681 |
| `max_content_chars` | int | `12000` | Fetched-content cap | mcp_shared.py:135 |
| `cache_ttl_seconds` / `cache_max_entries` | int | `1800` / `250` | Cache bounds | mcp_shared.py:136-137 |
| `min_source_quality` | str | `medium` | `low`\|`medium`\|`high` source ranking | mcp_shared.py:138, web_researcher.py:889 |
| `require_api_key_for_mcp_tools` | bool | `true` | Gate MCP research tools on provider keys | api_key_store.py:179 |
| `allow_local_fetch` | bool | `false` | Permit localhost/private fetches | mcp_shared.py:139 |
| `ollama.api_key_env` / `max_results` / `use_web_search` / `use_web_fetch` | — | `OLLAMA_API_KEY` / `8` / `true` / `true` | Ollama research provider | mcp_shared.py:153-158, web_researcher.py:319-369 |
| `serpapi.api_key_env` / `endpoint` / `engine` / `region` | — | `SERPAPI_API_KEY` / serpapi.com / `duckduckgo` / `us-en` | SerpAPI provider | mcp_shared.py:159-164 |
| `assistant.*` | see research_assistant.py:97-140 | enabled, `automatic: true`, `failure_trigger: 2`, budgets | Read-only in-loop research assistant (advisory) | exploit_agent/research_assistant.py:111-140, exploit_agent/loop.py:638-657 |

### `swarm:` (config.yaml:214-233) — multi-agent swarm

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `true` | Swarm mode | cli_exploit_settings.py:105, run_service/service.py:437 |
| `agents` | list[str] | recon/vuln/exploit/post_exploit/critic/reflection | Agent roster | swarm/orchestrator.py:564 |
| `max_parallel_agents` | int | `3` | Flow B parallel cap | agent_loop.py:267-272 |
| `parallel_enabled` | bool | `false` | Gates `route_parallel` + `spawn_subagent` MCP tool; CLI `--parallel-swarm` flips it (main.py:365-370) | mcp_tools/parallel_agents.py:268, prompt.py:386-390 |
| `per_phase_concurrency` | int | `3` | Semaphore for same-phase parallel dispatch | prompt.py |
| `exploit_parallel` | bool | `false` | Parallelize exploit/post_exploit phases | swarm/orchestrator.py:60-73, prompt.py:387 |
| `subagent_timeout_seconds` | int | `600` | Ceiling for `await_subagent` | prompt.py:386 |
| `session_timeout_seconds` | float | — (300s default) | Plain-run swarm wall clock (schema-only override; long-session raises it via `long_session.swarm_session_timeout_minutes`) | cli_exploit_settings.py:33-49 |
| `critic_enabled` / `reflection_enabled` | bool | `true` | Agent enablement | cli_exploit_settings.py:106-107 |

### `autonomous:` (config.yaml:239-244) — orchestrator Phase 2 (opt-in)

Read by the orchestrator from mission_config (merged from `config["autonomous"]`).

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `persistence_phase` | bool | `false` | Run PERSISTENCE phase after access | autonomous_orchestrator.py:1104 |
| `checkpoint_every` | int | `0` | Save `attack_states.json` every N targets (0=off) | autonomous_orchestrator.py:1105 |
| `adaptive_replan` | bool | `false` | Per-target replan + vuln-chaining | autonomous_orchestrator.py:1106 |
| `max_cycles` | int | `100` | Round cap when adaptive_replan is on | autonomous_orchestrator.py:1077 |
| `max_pivot_depth` | int | `0` | Single-IP lock default | autonomous_orchestrator.py:1091 |

### `orchestrator:` (config.yaml) — cross-mission learning consumer

Semantic-memory consumer for the autonomous orchestrator. When true, the orchestrator builds a `SemanticMemoryManager` (from the `memory` config block's `embed_host`/`embedding_model`) and calls `store_lesson` on every confirmed module win so the campaign learns across missions, not just within the exploit loop. Advisory-only — read-only memory store consumer, no execution authority change. Distinct `action_type='orchestrator:module_success'` isolates these rows from the exploit-loop and swarm-reflection lessons. Lab default ON (matches `memory.semantic_enabled: true` — the orchestrator is the missing consumer of an already-on capability, not a new attack-path opt-in).

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `semantic_memory` | bool | `true` | Build a SemanticMemoryManager + store cross-mission lessons on confirmed wins | autonomous_orchestrator.py:1095-1116 |

### `recon:` (config.yaml:251-274) — recon coverage & depth

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `extended_enumerators` | bool | `true` | TLS/SMTP/DB/spider/OSINT additive enumerators | recon_pipeline.py:294,1102 |
| `udp_top_ports` | int | `100` | `nmap -sU --top-ports N` | recon_pipeline.py:251,2246 |
| `shodan_api_key` | str | `""` | Passive OSINT key; `""` = disabled (falls back to `$SHODAN_API_KEY`) | recon_pipeline.py:287,1853 |
| `max_retries` | int | `2` | Nmap retry count on timeout/crash; set `0` to skip straight to native socket fallback (faster on Windows Npcap hangs) | recon_pipeline.py:234,589 |
| `retry_delay` | float | `5.0` | Initial retry delay (s); multiplied by 1.5 each retry | recon_pipeline.py:235,590 |
| `timeout_seconds` | int | `300` | Per-attempt nmap command timeout (s) | recon_pipeline.py:233,588 |
| `domain_resolution.enabled` | bool | `true` | Accept domain `--target`, resolve at boot | tools/validation_utils.resolve_target_to_ip, main.py target threading |
| `domain_resolution.max_subdomains` | int | `500` | Cap on `enumerate_subdomains` results | mcp_tools/domain.py:361 (tool default) |
| `domain_resolution.subdomain_sources` | list | crt_sh/dns_bruteforce/subfinder/amass | Discovery sources | mcp_tools/domain.py:360,393-448 |
| `domain_resolution.dns_zone_transfer` | bool | `false` | AXFR attempt opt-in | mcp_tools/domain.py:587-588 |
| `domain_resolution.whois_enabled` | bool | `true` | `domain_whois` tool | mcp_tools/domain.py |
| `subdomain_enum` / `vhost_discovery` / `waf_fingerprint` / `asn_whois` / `cloud_metadata_probe` / `snmp_enum` / `dns_zone_transfer` | bool | `false` | Extended depth enumerators (individually gated) | recon_pipeline.py:298-302,1158 |

### `opsec:` (config.yaml:283-300) — agent's own detection-evasion (opt-in, advisory)

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `false` | Master switch (opt-in) | opsec.py:92 |
| `ua_rotation` / `doh` | bool | `false` | UA rotation / DNS-over-HTTPS | opsec.py:93-94 |
| `doh_provider` | str | `cloudflare` | `cloudflare`\|`google` | opsec.py:95 |
| `min_gap_seconds` / `jitter_seconds` | float | `0.0` | Pacing base + jitter | opsec.py:96-97 |
| `rate_per_minute` | int | `0` | Token-bucket cap (0=unlimited) | opsec.py:98 |
| `quiet_command_patterns` | list[str] | `[]` | Substrings refused when enabled (advisory) | opsec.py:99 |
| `noise_budget` | int | `0` | Max noisy commands (0=unlimited; dormant, not a gate) | opsec.py:100, safety-model.md:181 |
| `local_targets_off` | bool | `true` | Local/private target → OPSEC forced OFF; public → ON | opsec.py:101,124-159 |
| `local_cidrs` | list[str] | `[]` | Extra CIDRs treated as local | opsec.py:102,150 |
| `public_autonomy` | bool | `true` | Public target → AI chooses its own attacks (documentary) | opsec.py:103 |

### `eval:` (config.yaml:305-310) — eval/benchmark harness

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `true` | Gates harness defaults (the `--eval` flag still works when false) | eval_harness.py:376 |
| `output_dir` | str | `reports/eval` | Where `reports/eval/<run_id>/` trees go | eval_harness.py:377 |
| `max_rounds` | int | `30` | `attack_max_rounds` for an eval run | eval_harness.py:378,421 |
| `write_markdown` / `write_html` | bool | `true` | Emit markdown/HTML reports | eval_harness.py:379-380 |

### `long_session:` (config.yaml:319-326) — multi-hour mode

Enabled by `--long-session` (main.py:374-376) or `enabled: true`.

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `true` (config.yaml) / `false` (schema) | Master switch | cli_exploit_settings.py:43,75 |
| `request_timeout_seconds` | int | `600` | Per-LLM-call httpx timeout | run_service/service.py:337-341, model_router.py:313-316 |
| `swarm_session_timeout_minutes` | int | `30` | Raises the 300s swarm cap | cli_exploit_settings.py:42-49 |
| `attack_max_rounds` | int | `200` | Budget override | cli_exploit_settings.py:120 |
| `attack_max_commands` | int | `1000` | Budget override | cli_exploit_settings.py:119 |
| `attack_max_duration_minutes` | int | `720` | 12h wall clock | cli_exploit_settings.py:121 |
| `persist_messages` | bool | `true` | Checkpoint compacted messages to `session_state.json` for crash-safe resume | cli_exploit_settings.py:139, session_manager.py:71-99, exploit_agent/context.py:616-623 |

### `reasoning:` (config.yaml:327-345) — agent reasoning

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `chain_of_thought` | bool | `true` | CoT mode | cli_exploit_settings.py:89 |
| `reflection_every_n_actions` | int | `10` | Reflection cadence | cli_exploit_settings.py:93, exploit_agent/loop.py:1685 |
| `critic_enabled` | bool | `true` | Critic agent (swarm) | cli_exploit_settings.py:106 |
| `observer_mode` | str | `hybrid` | `heuristic`\|`llm`\|`hybrid` fact extraction | cli_exploit_settings.py:98, main.py:641 |
| `ultrathink` | bool | `true` (config.yaml) / `false` (schema) | Deep-reasoning mode; CLI `--ultrathink` overrides | cli_exploit_settings.py:90 |
| `ultrathink_reflection_interval` | int | `3` | Ultrathink reflection cadence | cli_exploit_settings.py:92 |
| `llm_reflection` | bool | `true` (config.yaml) / `false` (schema) | LLM-driven reflection in the hot loop (extra LLM calls) | cli_exploit_settings.py:94, exploit_agent/reflection.py:135 |
| `peer_consult_on_failure_threshold` | int | `3` | Auto-consult peers after N consecutive exploit failures (0 disables) | cli_exploit_settings.py:97, exploit_agent/loop.py:1756 |

### `memory:` (config.yaml:346-352) — learning stores

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `semantic_enabled` | bool | `true` | Semantic memory / embeddings | agent_loop.py:173, skill_embeddings.py:167, exploit_agent/loop.py:477 |
| `embedding_model` | str | `nomic-embed-text` | Embedding model | skill_embeddings.py:174, semantic_memory.py:29 |
| `cross_mission_learning` | bool | `true` | Learn across missions | eval_benchmark.py:176 |
| `attack_memory_enabled` | bool | `true` | AttackMemoryStore in the exploit loop | exploit_agent/loop.py:278-290,560-577 |
| `attack_memory_max_context_chars` | int | `6000` | Attack-memory advisory size | exploit_agent/loop.py:287, context.py:260 |
| `experience_min_samples` | int | `3` | ExperienceStore soundness gate | agent_loop.py:192, exploit_agent/loop.py:438, skill_feedback.py:127 |
| `experience_time_decay_days` | float | `90` | Experience decay (≤0 disables) | agent_loop.py:193, skill_feedback.py:128 |

### `outcome_judgment:` (config.yaml:354-365) — evidence-grounded verdicts

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `max_inconclusive_attempts` | int | `3` | ≥2 prevents one failed command exhausting a hypothesis | config_manager.py:735-743 (validation) |
| `confirmation_threshold` / `refutation_threshold` | float | `0.75` | Evidence thresholds (0.5-1.0) | config_manager.py:744-753 |
| `min_evidence_references` | int | `1` | Min evidence refs for a verdict | config_manager.py:754-762 |
| `flow_a` | bool | `true` (config.yaml) / `false` (schema) | Wire OutcomeJudge into Flow A exploit loop (overrides shallow exit-code success) | cli_exploit_settings.py:154, eval_benchmark.py:231 |
| `peer_review` | bool | `false` | D3: cross-model outcome grading (`peer_review_outcome` MCP tool — one alias plans, a different alias grades evidence; advisory-only, deterministic judge stays authority) | mcp_tools/peer_models.py:162 |

### `poc_verification:` (config.yaml:264-271) — self-healing PoC verification (Killer Feature #3)

When `enabled`, `cve_to_exploit_synth` syntax-checks its synthesized PoC inline
(`py_compile`, no exec) and the `verify_poc` MCP tool compile-tests the PoC
inside a fully-isolated Docker container. The PoC is NEVER executed on the
operator box — this is a compile/import gate, not a sandbox guarantee.

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `false` | Master toggle (inline synth check + Docker compile path) | mcp_tools/attack_modules.py (cve_to_exploit_synth), mcp_tools/poc_verifier.py |
| `docker_image` | str | `python:3.11-slim` | Image for the compile/import container | tools/poc_verifier.py:docker_check |
| `compile_timeout_seconds` | int | `30` | Container run timeout | tools/poc_verifier.py:docker_check |
| `max_retries` | int | `3` | Self-heal loop cap (synth → verify → LLM fix → re-verify) | mcp_tools/attack_modules.py (agent-driven) |
| `docker_network` | str | `none` | Container network mode (always `none` — PoC must never reach target/network) | tools/poc_verifier.py:docker_check |
| `docker_read_only` | bool | `true` | Mount container filesystem read-only | tools/poc_verifier.py:docker_check |
| `docker_memory` | str | `256m` | Container memory cap | tools/poc_verifier.py:docker_check |

### `replay_simulator:` (config.yaml:273) — pre-commit attack-plan critique (D2)

When `enabled`, registers the `replay_simulate` MCP tool — a local-only
`@audit_tool` (no target touch) that dry-runs an attack plan against a saved
`ReconAssessment` JSON. The LLM critiques its own plan (confidence, branches);
if the LLM is unavailable, degrades to rule-based scoring. Zero target touch.

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `false` | Registers the `replay_simulate` MCP tool | mcp_tools/replay_simulator.py |

### `adaptive_exploits:` (config.yaml:366-373) — exploit mutation

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `true` | Mutation engine | cli_exploit_settings.py:99, mcp_tools/attack_modules.py:1325,1420 |
| `max_mutations` | int | `5` | Mutation cap | cli_exploit_settings.py:100 |
| `mutation_strategies` | list[str] | parameter_tweak/encoding_change/delivery_swap/context_aware | Strategy roster | cli_exploit_settings.py:101-104 |

### `multi_model:` (config.yaml:374-384) — peer-model consultation (advisory)

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `true` (config.yaml) / `false` (schema) | Exposes `consult_peer_models`; CLI `--multi-model-consult`/`--no-multi-model-consult` override | main.py:607-609, mcp_tools/registry.py:223 |
| `consult_aliases` | list[str] | all five aliases | Peer roster (intersected with registered models) | cli_exploit_settings.py:109, mcp_tools/registry.py:190-201 |
| `max_consultations` | int | `10` | Shared per-run budget (single counter) | exploit_agent/reflection.py:325, peer_models.py:55 |
| `max_question_chars` / `max_answer_chars` | int | `4000` / `8000` | Truncation bounds | reflection.py:326-327, peer_models.py:56-57 |

### `skills:` (config.yaml:385-422) — runtime skill pipeline

Advisory prompt context only — never permission/scope/audit (docs/skills.md:162-168).

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `true` | Master toggle | skill_pipeline.py:63,196, exploit_agent/skills.py:65 |
| `roots` | list[str] | `["skills"]` | Skill directories | mcp_engine_server.py:70, skill_registry_cache.py:27 |
| `default_enabled` | list[str] | 6 skills (nmap, pentest, red-team, mcp-audit, agentic-ai, domains) | Always-active skills | skill_selector.py:164,321 |
| `include_tags` / `exclude_names` | list[str] | `[]` | Tag include / name exclude filters | skill_selector.py |
| `maybe_enabled` | bool | `false` | Include `skills/maybe/` skills | skill_selector.py:130 |
| `allow_model_lookup` | bool | `true` | Enable read-only skill MCP tools | mcp_tools/registry.py:266 |
| `inject_startup_context` | bool | `false` | Eager body injection into initial prompt | skill_pipeline.py (CLI `--skills on` sets it: skills_cli.py:37-39) |
| `max_active_skills` / `min_contextual_skills` | int | `6` / `3` | Selection bounds | skill_selector.py:124 |
| `max_chars_per_skill` / `max_total_chars` | int | `2500` / `9000` | Prompt budget caps | skill_pipeline.py |
| `default_skill_weight` / `context_skill_weight` | int | `12` / `24` | Score weights | skill_selector.py |
| `reselect_mid_run` / `reselect_max_per_run` / `reselect_min_interval_actions` / `reselect_sticky_defaults` | — | `true` / `3` / `5` / `true` | Mid-run re-selection; `--no-skills-reselect` disables | skill_selector.py, exploit_agent/skills.py:44 |
| `swarm_inject` / `swarm_phase_hints_only` | bool | `true` | Swarm skill sharing (hints only for non-exploit agents) | skill_pipeline.py:198 |
| `feedback_enabled` / `feedback_skill_weight` / `feedback_min_observations` | — | `true` / `8` / `3` | Cross-mission feedback boost | skill_selector.py:300, skill_feedback.py |
| `semantic_matching` / `semantic_skill_weight` / `semantic_min_similarity` / `semantic_model` | — | `true` / `16` / `0.35` / `nomic-embed-text` | Embedding-based ranking | skill_selector.py:265 |
| `diversity_penalty` | int | `12` | Penalize tag-overlapping skills | skill_selector.py:316 |
| `include_metadata` | bool | `false` | Append references in rendered context | skills.md:127 |
| `allow_reference_listing` | bool | `true` | `list_skill_references` MCP tool | skills.md:153 |

### `plugins:` (schema default, config_manager.py:454-459; absent from config.yaml)

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | list[str] | `[]` | Explicitly loaded plugins (OFF by default — trusted Python, full operator-box privileges) | tools/plugins.py:638,650 |
| `disabled` | list[str] | `[]` | Hard-blocked regardless of manifest | plugins.py:639,651 |
| `search_paths` | list[str] | `["plugins"]` | Filesystem dirs scanned for `plugin.yaml` | plugins.py:640-646 |
| `entry_points` | bool | `true` | `netattackai.plugins` entry-point discovery | plugins.py:647,656 |

### `threat_intel:` (config.yaml:126-137) — threat-feed ingestion (OSV.dev + GHSA + KEV)

Advisory-only, never touches the target. Lab build ON so the feed is live out-of-the-box. Reuses `cve_lookup` KEV catalog (shared disk cache). GHSA needs `GITHUB_TOKEN` (shared with `cve_lookup.github.token_env`); when absent, GHSA is silently dropped and `osv`+`kev` still answer.

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `true` | Threat-feed master switch | tools/threat_intel.py:45, mcp_tools/research.py:210 |
| `cache_dir` | str | `exploit_workspace/.threat_intel` | Feed cache directory | tools/threat_intel.py:50 |
| `cache_ttl_seconds` | int | `86400` | Cache TTL | tools/threat_intel.py:52 |
| `sources.osv` / `ghsa` / `kev` / `exploitdb_rss` | bool | `true`/`true`/`true`/`false` | Source toggles | tools/threat_intel.py:55-60 |
| `max_results` | int | `20` | Results per query | tools/threat_intel.py:62 |
| `github_token_env` | str | `GITHUB_TOKEN` | GHSA token env | tools/threat_intel.py:65, api_key_store.py:53 |
| `timeout_seconds` | int | `30` | HTTP timeout | tools/threat_intel.py:66 |

### `witness:` (config.yaml:187-194) — advisory audit-stream watcher (agent-on-agent safety)

Library default OFF (conservative for downstream re-use); `config.yaml` lab default ON so a lab run streams anomaly telemetry by default. Polls `exploit_audit.jsonl`/`activity.jsonl` mid-run and flags anomalies (allowlist breach, PoC escape, perm escalation, prompt injection, DoS drift) to `witness.log` + event broker. Advisory ONLY: flags, never blocks.

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `false` (schema) / `true` (config.yaml lab) | Master switch | config_manager.py:353-361, tools/swarm/agents/witness_agent.py:42 |
| `log_path` | str | `reports/witness.jsonl` | Witness log | witness_agent.py:50 |
| `poll_interval_seconds` | int | `5` | Poll interval | witness_agent.py:51 |
| `escalate_to_event_broker` | bool | `true` | Escalate flags to WS/event broker | witness_agent.py:52 |
| `max_flags_per_signal_per_minute` | int | `10` | Per-signal rate cap | witness_agent.py:53 |
| `dos_failure_window_seconds` | float | `60.0` | DoS drift window | witness_agent.py:54 |
| `dos_failure_threshold` | int | `8` | DoS drift threshold | witness_agent.py:55 |

### `ics:` (config.yaml:416-418) — D8 ICS write-side modules

`ModbusWriteCoil`/`ModbusWriteRegister`/`S7PlcStop`/`S7PlcStart` are DESTRUCTIVE — they change physical process state. Dual-gated: `@require_allowlist` on `run_attack_module` AND `ics.allow_write: true` AND `ics.destructive_ics: true` (both must be true). Default `false` so checked-in config is safe; set true only for authorized PLC testing. PHYSICAL-DAMAGE RISK.

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `allow_write` | bool | `false` | ICS write gate (read-only enum when false) | tools/attack_modules/modules/ics_iot.py:40, config_manager.py |
| `destructive_ics` | bool | `false` | Second physical-damage gate (both must be true) | tools/attack_modules/modules/ics_iot.py:42 |

### `webhook_notify:` (config.yaml:438-449) — outbound Slack/Discord run-status notifications

Lab build `enabled: true`. No-op without a `url` — logs once then drops events. Set `url` to a Slack/Discord incoming webhook to actually receive pings.

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `true` | Master switch | tools/plugins/webhook_notify.py:30, config_manager.py:589 |
| `url` | str | `""` | Webhook URL (secret, never logged) | webhook_notify.py:35 |
| `events` | list[str] | `["finding","state"]` | Event-type filter | webhook_notify.py:36 |
| `timeout_seconds` | int | `5` | HTTP timeout | webhook_notify.py:37 |
| `max_retries` | int | `3` | Retry count | webhook_notify.py:38 |
| `backoff_seconds` | float | `2.0` | Backoff | webhook_notify.py:39 |
| `max_payload_chars` | int | `8192` | Payload cap | webhook_notify.py:40 |

### `mitre:` (config.yaml:450-456) — MITRE ATT&CK Navigator export

Lab build `enabled: true`. `export_attack_navigator` MCP tool writes Navigator layer JSON to `navigator_output_dir` for SOC handoff.

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `true` | Master switch | tools/mitre_export.py:30, config_manager.py:598 |
| `technique_map` | str | `tools/mitre_technique_map.json` | ATT&CK technique map | mitre_export.py:31 |
| `navigator_output_dir` | str | `reports/mitre` | Output dir | mitre_export.py:32 |
| `include_skill_tags` | bool | `true` | Include skill tags | mitre_export.py:33 |

### `ticketing:` (config.yaml:457-467) — remediation ticket generation (Jira/GitHub)

Lab build `enabled: true`. No-op without `provider`/`base_url`/`token` — logs once then drops. Set `provider` (`jira`|`github`), `base_url`, and the named `token_env` env var to actually create tickets.

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `true` | Master switch | tools/ticketing.py:30, config_manager.py:610 |
| `provider` | str | `""` | `jira` \| `github` | ticketing.py:31 |
| `base_url` | str | `""` | Ticketing base URL | ticketing.py:32 |
| `token_env` | str | `TICKETING_TOKEN` | Token env var | ticketing.py:33, api_key_store.py |
| `project_key` | str | `""` | Project key | ticketing.py:34 |
| `max_retries` | int | `3` | Retry count | ticketing.py:35 |
| `backoff_seconds` | float | `2.0` | Backoff | ticketing.py:36 |

### `caldera:` (config.yaml:476-480) — D6 Caldera adversary emulation plugin

Lab build `enabled: true`. The Caldera server is target-side — operator adds its IP to `exploit.allowed_targets`. Plugin MCP tools (`caldera_list_abilities`, `caldera_run_ability`) are `@require_allowlist`-gated on the target IP.

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `true` | Master switch | plugins/caldera/plugin.py:40, config_manager.py |
| `url` | str | `""` | Caldera server base URL | caldera/plugin.py:41 |
| `api_key_env` | str | `CALDERA_API_KEY` | Caldera API key env | caldera/plugin.py:42 |

### `agent:` (config.yaml:486-494) — capability-upgrade agent block (design §23)

Toggles + budgets for the task graph, capability discovery, AI-facing state tools, planner hints, decision logging, reflection, and retry/repair budgets. Defaults preserve today's behavior. `config_cli.load_config` merges NO defaults, so every consumer reads defensively via `cfg.get("agent", {}).get(key, default)`.

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `task_graph_enabled` | bool | `true` | Gate task-graph/DAG planner | tools/attack_planner.py:45, tools/config_manager.py:648 |
| `capability_discovery_enabled` | bool | `true` | Gate capability discovery (`find_producers`) | tools/attack_modules/registry.py:120 |
| `state_tools_enabled` | bool | `true` | Gate AI-facing state MCP tools | tools/mcp_tools/assessment_state.py:40 |
| `planner_hints_enabled` | bool | `true` | Inject planner hints into system prompt | tools/exploit_agent/prompt.py:210 |
| `decision_log_enabled` | bool | `true` | Append to `decision_log.jsonl` | tools/decision_log.py:30 |
| `reflection_enabled` | bool | `true` | Gate post-step reflection | tools/exploit_agent/reflection.py:45 |
| `max_retries_per_task` | int | `2` | Per-task retry ceiling | tools/failure_taxonomy.py:80 |
| `max_actions` | int | `0` | Total action cap (0 = legacy exploit budgets) | tools/exploit_agent/loop.py:520 |
| `generated_code_repair_attempts` | int | `3` | Max self-repair iterations on PoC | tools/poc_verifier.py:60 |

### `api:` (config.yaml:386-407) — WebUI daemon (`--demon` / `--daemon` / `--web`)

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `true` | Daemon enablement | app.py:64 |
| `host` | str | `127.0.0.1` | **Loopback-only in v1; any other value is a validation ERROR**; CLI `--api-host` overrides | main.py:513-518, config_manager.py:918-926 |
| `port` | int | `8765` | Daemon port; CLI `--api-port` overrides | main.py:514 |
| `token_file` | str | `.webui_secret_key` | Auto-generated bearer token file (gitignored); `NETATTACKAI_API_TOKEN` env overrides | app.py:70, tools/api/auth.py:42-46 |
| `allowed_origins` | list[str] | `[]` | Extra loopback origins for CORS/WS; `null` and non-loopback always rejected | app.py:108 |
| `event_buffer_size` | int | `256` | In-memory ring buffer per run for WS subscribers | app.py:81 |
| `shutdown_timeout_seconds` | int | `15` | Graceful shutdown wait | tools/api/run_manager.py:320 |
| `serve_webui` | bool | `false` | Mount `webui/dist/` at `/`; `--web` sets this **in memory only** | app.py:145, main.py:542 |
| `max_concurrent_runs` | int | `3` | D3: N concurrent runs (1 = legacy 409) | tools/api/run_manager.py:22, config_manager.py |
| `multi_operator` | bool | `true` | D4: user accounts + annotations (loopback-only) | tools/api/auth.py:60 |
| `graph_route` | bool | `true` | Attack-path DAG API route | tools/api/routes/graph_explorer.py:30 |

## Other consumed keys

- `reports_dir` (not in schema): `Path(config.get("reports_dir", "reports"))` — app.py:76; also `mcp_engine_server.py:74` defaults to `reports`.

## `agent` — capability-upgrade agent block (design §23)

Source of truth: `tools/config_manager.py::CONFIG_SCHEMA` (`"agent"` key, auto-whitelisted via `KNOWN_TOP_KEYS`). Mirrored into `config.yaml` under the `agent:` mapping. Validation: `ConfigValidator.validate` checks bools for the toggles and non-negative integers for the budgets (warn-not-reject — see `chatgpt` / `skills` precedent).

All defaults preserve today's behavior. **`config_cli.load_config` merges no defaults**, so every consumer reads defensively: `cfg.get("agent", {}).get(key, default)`.

| Key | Default | Type | Purpose |
|-----|---------|------|---------|
| `task_graph_enabled` | `true` | bool | Gate the live task-graph/DAG planner (AttackPlan/AttackStep). On = the agent drives the graph; off = legacy sequential planning. |
| `capability_discovery_enabled` | `true` | bool | Gate AI-facing capability discovery (module `capability_record()` / `find_producers` / `missing_prerequisites`). |
| `state_tools_enabled` | `true` | bool | Gate AI-facing state MCP tools (assessment state store + decision log surface). |
| `planner_hints_enabled` | `true` | bool | Inject planner hints (hypothesis, expected_evidence, capability) into the agent system prompt. |
| `decision_log_enabled` | `true` | bool | Append structured decisions to `decision_log.jsonl` via `tools/decision_log.py::log_decision`. |
| `reflection_enabled` | `true` | bool | Gate post-step reflection / retry-with-modified-parameters behavior. |
| `max_retries_per_task` | `2` | int | Per-task retry ceiling on retryable failure classes (see `tools/failure_taxonomy.py::is_retryable`). |
| `max_actions` | `0` | int | Total action cap. **`0` is the legacy-budget sentinel** — consumption sites treat 0 as "use the existing exploit budgets" (`exploit.attack_max_commands` / `max_rounds`), not a hard zero cap. |
| `generated_code_repair_attempts` | `3` | int | Max self-repair iterations on a generated PoC that fails `py_compile` (compile-only, never executed on the operator box). |

## `models.roles` — model-role routing (design §23)

Nested under the existing `models` key in `CONFIG_SCHEMA` (`tools/config_manager.py::CONFIG_SCHEMA["models"]["roles"]`). Mirrored into `config.yaml` under `models.roles`. Validation: `ConfigValidator.validate` warns when a value is not a string or when a non-empty alias is not in `models.registry` (warn-not-reject).

Each role maps to a model alias; **an empty string means "use `models.default_alias`"** so first-run behavior is unchanged. Consumed by `tools/model_router.py::ModelRouter.get_client_for_role`, which falls back to `models.default_alias` when the role's alias is empty.

| Role | Default | Purpose |
|------|---------|---------|
| `planner` | `""` | Task-graph / attack-plan generation. |
| `executor` | `""` | Tool-call driving / terminal + MSF execution. |
| `interpreter` | `""` | Recon / output parsing / evidence interpretation. |
| `code_generator` | `""` | PoC synthesis + repair. |
| `critic` | `""` | Pre-action risk critique. |
| `summarizer` | `""` | Run reporting / outcome summarization. |

Precedents for per-role model overrides: `research.assistant.model_alias`, `multi_model.consult_aliases`. Keep `models.registry` / `models.info` synchronized (context-window metadata feeds `tools/exploit_agent` adaptive context handling).

## CLI vs config precedence

Explicit CLI flags win over config values; config wins over schema defaults:

| Config key | CLI override |
|------------|--------------|
| `models.default_alias` | `--model <alias>` (main.py:631) |
| `long_session.enabled` | `--long-session` (cli_exploit_settings.py:43,75) |
| `swarm.parallel_enabled` | `--parallel-swarm` (main.py:365-370) |
| `multi_model.enabled` | `--multi-model-consult` / `--no-multi-model-consult` (main.py:607-609) |
| `exploit.attack_max_commands/rounds` | `--max-commands` / `--max-rounds` (cli_exploit_settings.py:119-124,167-168) |
| `skills.*` | `--skills on\|off\|hints\|lookup`, `--skills-include`, `--skills-exclude`, `--no-skills-reselect` (skills_cli.py:23-80) |
| `api.host` / `api.port` | `--api-host` / `--api-port` (main.py:513-514) |
| `mcp.default_transport` | `--mcp-transport` (main.py:353; ignored on the run path — always `http`) |
| `api.serve_webui` | `--web` (in-memory only, never persisted; main.py:541-542) |
| `reasoning.ultrathink` | `--ultrathink` (main.py:405-406) |
