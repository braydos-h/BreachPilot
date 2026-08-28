---
title: Environment Variables
description: .env.example, every env var, secrets vs runtime locks, provider auth, and precedence.
source: [.env.example, config.yaml, tools/config_manager.py, tools/api_key_store.py, tools/mcp_session.py, tools/mcp_shared.py, tools/doctor.py, app.py, tools/api/auth.py]
---

# Environment Variables

All secrets are env vars (or `secr.json`), never `config.yaml`. Config keys like `ollama.api_key_env` / `cve_lookup.github.token_env` only **name** the env var; the value lives in the env.

## `.env.example` (template, 33 lines)

Copy to `.env` and fill in — `.env` is gitignored, never committed. `secr.json` is the interactive alternative (`python main.py --setup-api-keys`).

```ini
# NVD CVE lookup (optional but recommended — raises NVD rate limit)
NVD_API_KEY=

# GitHub token for cve_to_poc (optional — raises GitHub Search API rate limit 60/hr → 5000/hr)
GITHUB_TOKEN=

# Ollama cloud / remote host API key (only if using a remote Ollama endpoint that requires one)
OLLAMA_API_KEY=

# SerpAPI key for web research (optional)
SERPAPI_API_KEY=

# Runtime target lock — the single target IP the exploit path is locked to.
# Usually set automatically from --target; export here for the MCP server subprocess.
# EXPLOIT_TARGET=10.0.0.50

# Exploit workspace root (optional override; defaults to ./exploit_workspace)
# EXPLOIT_WORKSPACE=./exploit_workspace

# Gate for binding the MCP HTTP server to non-loopback interfaces.
# Both must be set to allow a public bind; otherwise it refuses non-loopback.
# MCP_ALLOW_PUBLIC_BIND=1

# WebUI API daemon bearer token override (--demon mode). When set, this
# value is used instead of the auto-generated token in api.token_file
# (default .webui_secret_key, gitignored). Never logged or returned by the API.
# NETATTACKAI_API_TOKEN=
```

Plus `SHODAN_API_KEY`, `CALDERA_API_KEY`, `TICKETING_TOKEN` etc. when the optional integrations are used.

## Full variable directory

### Secrets (provider auth) — named by config

| Env var | Default config key | Purpose | When needed | Read at | Env-over-file |
|---------|-------------------|---------|-------------|---------|---------------|
| `OLLAMA_API_KEY` | `ollama.api_key_env` (`config.yaml:5`) and `research.ollama.api_key_env` (`config.yaml:152`) | Bearer for Ollama Cloud (`https://api.ollama.com`); auto-attached by `ollama.Client` | Cloud host (default `ollama.host`) or research `ollama` provider | `model_router.py:301`, `doctor.py:154`, `api_key_store.py:49` | File value overridden only if env already set (`load_api_keys_into_env` skips when `os.environ[name]` present) |
| `NVD_API_KEY` | `cve_lookup.api_key_env` (`config.yaml:116`) | NVD API key — raises NVD rate limit for `search_cve_intel` | Any `cve_lookup` use; optional | `mcp_shared.py:109`, `cve_lookup.py:62` | same |
| `GITHUB_TOKEN` | `cve_lookup.github.token_env` (`config.yaml:125`) and `threat_intel.github_token_env` (`config.yaml:136`) | GitHub Search token for `cve_to_poc` (60/hr unauth → 5000/hr); GHSA threat intel | `cve_to_poc` / `threat_intel.ghsa`; optional | `exploit_search.py:190`, `threat_intel.py:65` | same |
| `SERPAPI_API_KEY` | `research.serpapi.api_key_env` (`config.yaml:157`) | SerpAPI key for web research | `research.provider` or `fallback_provider == serpapi` | `mcp_shared.py:160`, `web_researcher.py:182` | same |
| `SHODAN_API_KEY` | — (file `recon.shodan_api_key` wins; env is fallback) | Shodan passive OSINT | `recon.extended_enumerators` / OSINT | `recon_pipeline.py:287`, `tools/doctrine` | File wins over env |
| `CALDERA_API_KEY` | `caldera.api_key_env` (`config.yaml:480`) | Caldera server API key | `caldera.enabled` | `plugins/caldera/plugin.py:42` | env is value |
| `TICKETING_TOKEN` | `ticketing.token_env` (`config.yaml:464`) | Jira/GitHub ticketing token | `ticketing.enabled` | `ticketing.py:33` | env is value |
| `GITHUB_TOKEN` (dup) | — | Also GHSA feed | `threat_intel.sources.ghsa` | same | — |

All four primary keys are seeded at boot by `tools/api_key_store.bootstrap_api_keys` (`tools/config_cli.py:160`) from `secr.json` when `os.environ[name]` is empty. Missing keys are surfaced as `result.missing` and via `tools/doctor._check_ollama` 401 hint.

### Runtime target locks (threaded by `tools/mcp_session.py:255`)

Set automatically from `--target`; do not set by hand unless debugging the MCP server.

| Env var | Config counterpart | Purpose | Set by | Consumed by |
|---------|-------------------|---------|--------|-------------|
| `EXPLOIT_TARGET` | `exploit.allowed_targets` union | Literal `--target` (IP or domain) — primary allowlist identity | `mcp_session.py:255` | `mcp_shared._allowed_target_list` (`tools/kernel/allowlist.py`) — unioned with `exploit.allowed_targets` and discovered targets |
| `EXPLOIT_TARGET_IP` | — | Resolved IP for domain `--target` | `mcp_session.py:265` (`resolve_target_to_ip`) | same union |
| `EXPLOIT_TARGET_DOMAIN` | — | Original domain string | `mcp_session.py:266` | same union; also prompt domain briefing |
| `EXPLOIT_DISCOVERED_TARGETS` | — | CSV of subdomain/IP auto-authorized mid-run | `mcp_shared.add_discovered_target` | same union |
| `EXPLOIT_WORKSPACE` | `exploit.workspace_dir` | Workspace root override | `mcp_session.py:256` or manual export | `cve_lookup.py:171` (KEV cache), `tools/kernel/workspace.py:139` |

Allowlist check is `tools/validation_utils.is_target_in_allowlist` — supports exact IP, CIDR, domain, `*.wildcard`.

### WebUI / API daemon

| Env var | Purpose | Default | Read at |
|---------|---------|---------|---------|
| `NETATTACKAI_API_TOKEN` | Bearer token override for `--demon/--daemon/--web` (`app.py` / `tools/api/auth.py`) | `api.token_file` (`.webui_secret_key`) | `app.py:71`, `tools/api/auth.py:46`, `load_or_create_token` |
| `MCP_HTTP_TOKEN` | Optional bearer for MCP HTTP transport (`streamable_http`) | — (loopback-only, no auth) | `mcp_shared.run_mcp_http_server` — wraps ASGI with `_wrap_http_auth` |
| `MCP_ALLOW_PUBLIC_BIND` | Second half of two-person rule for non-loopback MCP bind (`1/true/yes/on`) | — | `mcp_shared.assert_loopback_bind` — requires CLI `--allow-public-bind` AND env `1` |

### Behavior / debug

| Env var | Purpose | Set by | Consumed at |
|---------|---------|--------|-------------|
| `AI_NMAP_DEBUG` | Verbose nmap/exploit loop logging | `main.py:593` from `--debug` | `tools/exploit_agent/runner/_impl.py:182`, `exploit_agent/*` |
| `AI_NMAP_ACTIVE_MODEL_ALIAS` | Active model alias threaded into MCP server | `mcp_session.py:270` | `tools/mcp_tools/registry.py:201`, `peer_models.py:80` |
| `AI_NMAP_MULTI_MODEL_ENABLED` | Force multi-model enablement in MCP server | — | `tools/mcp_tools/registry.py:220` |
| `AI_NMAP_AUDIT_VERIFY_VERBOSE` | Verbose audit verification | — | `exploit_agent/policy.py:340` |
| `AI_NMAP_VAULT_KEY` | Credential-store vault key (else auto-generated) | — | `credential_store.py:149` |
| `RESEARCH_WORKSPACE` | Flow B workspace root | — | `cli.py:39`, `logging_setup.py:18` |
| `CODEX_HOME` | ChatGPT auth file dir override (`$CODEX_HOME/auth.json`) | user | `chatgpt_provider.py is_authenticated`, `doctor._check_chatgpt` |

### System auth (ChatGPT provider)

OAuth tokens are **not env vars**. They live in `~/.codex/auth.json` (or `$CODEX_HOME/auth.json`). The code only checks existence via `is_authenticated()` — never reads or copies. See `docs/configuration/secrets.md`.

## Precedence (env vs file)

1. **Env wins once set** — `load_api_keys_into_env(path, allowed_names)` (`api_key_store.py:105`) iterates `load_api_key_file(path)` but skips when `os.environ.get(name)` already truthy. So shell-exported env before `python main.py` beats `secr.json`.
2. **File-to-env bootstrap** — at startup `bootstrap_startup_api_keys(args, prompt=…)` (`config_cli.py:160`) calls `bootstrap_api_keys(config, store_path, prompt, force_prompt)` which loads `secr.json` into env, optionally prompts for missing keys, saves, and re-checks. `prompt=True` only in `main.py:1047` interactive menu (`--menu`); `--setup-api-keys` uses `force_prompt=True`.
3. **Config-to-env mapping** — `configured_api_key_env_names(config)` (`api_key_store.py:33`) collects `ollama.api_key_env`, `research.ollama.api_key_env`, `research.serpapi.api_key_env`, `cve_lookup.api_key_env`, `cve_lookup.github.token_env` deduped. `research_api_key_env_names` (`api_key_store.py:61`) collects only provider-relevant ones (`use_web_search/use_web_fetch` + `provider/fallback_provider`). Missing keys come from `missing_api_key_env_names`.

Interactive prompt is via `questionary` or `getpass.getpass` (`api_key_store.py:243`); entered values saved via `save_api_keys` (atomic `NamedTemporaryFile` + `os.fsync` + `chmod 0o600` + `os.replace`).

## Provider auth specifics

### Ollama Cloud (default, `config.yaml:3` `ollama.host: https://api.ollama.com`)

`OLLAMA_API_KEY` must be set for any cloud chat/generate call. The `ollama` Python client auto-attaches `Authorization: Bearer $OLLAMA_API_KEY` — app code attaches manually only on raw `urllib` paths (embeddings, doctor, live-models). Missing key surfaces as 401 on first chat (`doctor.py _check_ollama` reports unreachable). Embeddings default to `ollama.embed_host: http://localhost:11434` (`nomic-embed-text` self-hosted) with fallback to `ollama.host`.

Override `ollama.host` in `config.yaml` to point at a local daemon — same code path, no probe, no fallback, `OLLAMA_API_KEY` ignored locally.

### ChatGPT (opt-in, `models.provider: chatgpt`, vendored `oauth/` loopback `127.0.0.1:10531/v1`)

OAuth browser flow — never env. The single seam is `tools/model_router.py::_build_model_client(raw_client=ChatGptProxyClient)`. Embeddings stay on Ollama under either provider. `--doctor` runs `_check_chatgpt` only when `provider: chatgpt` (subchecks: provider, source exists, `bun`/`node` runtime, oauth login existence, proxy `/health`, `/v1/models`).

### SerpAPI / NVD / GitHub / Shodan / Caldera / Ticketing

Each is opt-in, env-guarded, and absent → feature silently disabled (or GHSA dropped while OSV+KEV still answer).

## Diagnostics

```powershell
python main.py --doctor    # checks #4 Ollama reachable + #5 models + #7 config + warns on missing keys
python -m pytest tests/test_api_key_store.py -v  # (if present) — apikey bootstrap
$env:OLLAMA_API_KEY        # PowerShell: verify env present
Get-Content secr.json | ConvertFrom-Json | Select-Object api_keys  # inspect saved keys (file is 0o600)
```

Verify `.gitignore` covers `.env`, `secr.json`, `.webui_secret_key` before committing.

## Related

- `docs/configuration/overview.md` — loading and precedence.
- `docs/configuration/secrets.md` — `secr.json` / `.webui_secret_key` / ChatGPT tokens.
- `docs/configuration/validation.md` — validator error modes.
- `docs/providers.md` — full provider wiring (ollama vs chatgpt), embeddings split.
