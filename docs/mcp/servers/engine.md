---
title: Engine MCP Server (mcp_engine_server.py)
sources:
  - mcp_engine_server.py
  - tools/mcp_shared.py
  - tools/cve_lookup.py
  - tools/skill_registry.py
  - tools/api/persistence.py
tests:
  - tests/test_mcp_tool_registration.py
subsystem: mcp
---

# Engine MCP Server

Read-only advisory surface at `mcp_engine_server.py:1-223` for foreign AI assistants (Claude Desktop, Cursor). No target touching, no terminal, no exploit surface — v1 is strictly advisory + history (`mcp_engine_server.py:1-11`).

## Server Identity

- FastMCP name: `netattackai-engine` (`mcp_engine_server.py:77`)
- Instructions: "NetAttackAI engine advisory surface. Tools are read-only..." (`mcp_engine_server.py:78-84`)
- `json_response=True` (`mcp_engine_server.py:85`)
- Transports: `stdio` (default) or `http` (`mcp_engine_server.py:200-218`)
- Default HTTP port: `8002` (`mcp_engine_server.py:203`)

## Factory

`create_mcp_server(*, nvd, config, reports_dir, skill_roots)` (`mcp_engine_server.py:51-190`):

- Reads `config["skills"]["roots"]` default `["skills"]` (`mcp_engine_server.py:69-71`) → `load_skill_registry(skill_roots)`
- `reports_dir` default `Path("reports")` → `ApiPersistence(Path(reports_dir))` (`mcp_engine_server.py:73-75`)
- Builds `FastMCP` and registers 5 tools as closures over `registry`, `nvd`, `persistence`.

No allowlist or audit wiring — out of scope because no tool touches the network or operator filesystem beyond `reports/`/`skills/` (`mcp_engine_server.py:9-11`).

## Tools (5)

| Tool | Signature | What it does | Source |
|------|-----------|--------------|--------|
| `search_skills` | `(query: str, limit: int=10) -> {count, skills}` | Lexical + field-weighted search over ~140 `SKILL.md` files; caps 1..50, returns `name, description, tags, domain` per match | `mcp_engine_server.py:89-112` |
| `get_skill` | `(name: str) -> {ok, name, description, tags, domain, subdomain, version, nist_csf, mitre_attack, sections, body} or {ok:False}` | Exact lookup by name via `registry.get(name)` | `mcp_engine_server.py:114-137` |
| `cve_lookup` | `(query: str) -> str` | NVD CVE lookup (`NVDClient.search_sync` + `format_cve_results`); rate-limited, cached, circuit-breakered | `mcp_engine_server.py:139-147` |
| `list_runs` | `(limit: int=20) -> {count, runs}` | Recent assessment runs newest-first via `ApiPersistence.list_runs(limit, sort="created_desc")`; caps 1..100; trims to `id, state, created_at, target, mode, goal_name, model_alias, title` | `mcp_engine_server.py:149-175` |
| `get_run` | `(run_id: str) -> {ok, run} or {ok:False}` | One run's details via `persistence.get_run(run_id)` — state, request, preview, result, error | `mcp_engine_server.py:177-188` |

All tools are synchronous except the server itself; no `@require_allowlist` / `@audit_tool` gates.

## CLI Entrypoint

`main(argv)` (`mcp_engine_server.py:196-220`):

- `--transport stdio|http`, `--config config.yaml`, `--host 127.0.0.1`, `--port 8002`, `--allow-public-bind`
- Loads config (`load_config`), builds NVD client (`build_cve_search`), calls `create_mcp_server`, then `server.run(transport="stdio")` or `run_mcp_http_server(server, host, port, allow_public_bind)`.

## Config Keys

- `skills.roots: list[str]` — skill search roots (default `["skills"]`)
- `reports_dir: str` — overridden by `reports_dir` param, else `Path("reports")`
- `cve_lookup.*` — `enabled, timeout_seconds, max_results, cache_ttl_seconds, cache_max_entries, rate_limit_seconds, api_key_env, circuit_failure_threshold, circuit_recovery_timeout, epss_enabled, kev_enabled, search_rate_limit_per_minute` (shared with other servers via `build_cve_search`)

## HTTP Hardening

Delegates to `tools.mcp_shared.run_mcp_http_server` (`mcp_engine_server.py:218`) — same loopback gate (`assert_loopback_bind`) and optional `MCP_HTTP_TOKEN` bearer auth as the other two servers. Non-loopback bind needs both `--allow-public-bind` and `MCP_ALLOW_PUBLIC_BIND=1`.

## Foreign Assistant Usage

No in-repo client. Example for Claude Desktop `mcp.json`:

```json
{
  "mcpServers": {
    "netattackai-engine": {
      "command": "python",
      "args": ["mcp_engine_server.py", "--transport", "stdio"]
    }
  }
}
```

Or HTTP: `python mcp_engine_server.py --transport http --port 8002` then point the assistant's streamable-HTTP client at `http://127.0.0.1:8002/mcp`.

## Related Docs

- `docs/mcp/overview.md`
- `docs/mcp/lifecycle.md` — shared HTTP serving and bearer auth detail
- `tools/skill_registry.py` — registry search implementation
