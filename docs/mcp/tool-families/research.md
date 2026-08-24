---
title: "Tool Family: research"
sources:
  - tools/mcp_tools/research.py
  - tools/exploit_search.py
  - tools/cve_lookup.py
  - tools/web_researcher.py
  - tools/threat_intel.py
  - tools/mcp_shared.py
tests:
  - tests/test_mcp_tool_registration.py
subsystem: mcp
---

# Tool Family: research

- **Registration source:** `tools/mcp_tools/research.py:10 register_research_tools(mcp, *, ctx)` — auto-discovered.
- **Gate:** all `@audit_tool` (no target touch — read-only local/intel; never executes exploits). No allowlist gate by design.
- **API-key gating:** web tools check `research_api_keys_available(config)` → `disabled_research_tools_message(config)` when keys missing.

## Tools Exported (7)

| Tool | Params | Result Shape | Notes |
|------|--------|--------------|-------|
| `search_exploit_db` | `query: str` | `ExploitSearch.search_exploit_db(query)` raw text — exploit IDs, titles, paths, CVEs via local `searchsploit` | Built by `tools/mcp_shared.build_search(config)` (`ExploitSearchSettings` from `exploit`/`search`/`research.serpapi` blocks). No validation beyond non-empty. |
| `search_web_exploit` | `query: str` | Read-only candidate sources: titles, URLs, snippets, source quality, provider metadata, warnings; no full page fetch, no execution | Requires research API keys (`research_api_keys_available` → checks `~/.codex`/`SERPAPI_API_KEY` etc.); when missing returns disabled message, does not call provider. |
| `fetch_webpage` | `url: str` | `title, source URL, readable content, links, provider metadata, warnings`; private/localhost URLs blocked by default (`research.allow_local_fetch` when true) | Same API-key gate; `researcher.fetch_webpage(url)` — never executes exploit code. |
| `deep_research` | `query: str` | Structured JSON with `citations, key facts, reliability notes, relevant CVEs, warnings, suggested next queries` — de-duplicated, ranked | Same API-key gate; `researcher.deep_research(query, search.search_web_exploit)` — multi-source search + fetch loop. |
| `search_cve_intel` | `query: str` | `format_cve_results(entries, query)` — CVSS, description, references | Calls `nvd.search_sync(query)`; on exception degrades to `NO_CVE_RESULTS: NVD lookup for ... failed (exc). Treat as no CVEs found; try search_web_exploit...` so agent moves on (`research.py:52-64`). NVD built by `build_cve_search` with shared `RateLimiter` + circuit breaker. |
| `cve_to_poc` | `cve_id: str` | `CVE_TO_POC_RESULTS` with verified URLs or `NO_VERIFIED_POC_FOUND` | Gathers NVD refs (`nvd.search_sync(cve_id)` → `references[]`) and calls `search.cve_to_poc(cve_id, nvd_refs)` — HTTP-existence-checked GitHub Search + `searchsploit --cve` + NVD refs; never fabricates URLs. System prompt: `ALWAYS call cve_to_poc first` (`mcp_exploit_server.py:97-101`). |
| `search_threat_intel` | `query: str`, `sources: str="osv,ghsa,kev"` | JSON `{cve lists per source + KEV membership}` pretty-printed via `json.dumps` | Uses `ThreatIntelClient.from_config(config).search(query, sources)` — OSV.dev / GHSA / CISA KEV; `ValueError` → `BLOCKED: ...`; feed text control-char-stripped and capped 200 chars (prompt-injection guard), never fetched as URL (SSRF guard). |

## Dependencies

- `tools/exploit_search.ExploitSearch` (local DB + web), `tools/cve_lookup.NVDClient` + `format_cve_results`, `tools/web_researcher.WebResearcher`, `tools/threat_intel.ThreatIntelClient`
- `tools/mcp_shared.build_search`, `build_cve_search`, `build_researcher`
- `tools/api_key_store.research_api_keys_available`, `disabled_research_tools_message`, `load_api_keys_into_env`

## Config

- `exploit.enabled`, `exploit.searchsploit_path`, `exploit.cache_ttl_seconds`, `exploit.cache_max_entries`, `exploit.max_query_chars`
- `search.*` / `research.serpapi.*` — `endpoint, engine, region, api_key_env, timeout_seconds, max_results`
- `research.*` — `enabled, provider, fallback_provider, timeout_seconds, max_results, max_fetch_depth, max_content_chars, cache_ttl_seconds, cache_max_entries, min_source_quality, allow_local_fetch, allowed_domains, blocked_domains, ollama.*, serpapi.*`
- `cve_lookup.*` — `enabled, timeout_seconds, max_results, cache_ttl_seconds, cache_max_entries, rate_limit_seconds, search_rate_limit_per_minute, api_key_env, circuit_failure_threshold, circuit_recovery_timeout, epss_enabled, kev_enabled, kev_cache_ttl, kev_cache_path`

## Auditing

- All via `@audit_tool` — `started`/`completed|blocked` records even though no target; `_extract_audit_target` finds nothing so `target_ip=""` for these entries (intentionally remote-intel, not target touch).
- No secrets in args for this family, but `search_threat_intel` query capped and stripped; researcher warnings de-duplicated.

## Validation

- No IP validation — not target tools.
- `search_threat_intel` raises on invalid `sources`; `search_cve_intel` swallows NVD exceptions; `cve_to_poc` nvd refs best-effort try/except.

## Tests

- `tests/test_mcp_tool_registration.py` expects `search_exploit_db`, `search_web_exploit`, `fetch_webpage`, `deep_research`, `search_cve_intel` (cve_to_poc + search_threat_intel are additive and not in the legacy expected set)
- Manual: mock `ExploitSearch`/`NVDClient`/`WebResearcher` without live Nmap/HTTP.

## Related Docs

- `docs/mcp/tool-families/attack-modules.md` — `cve_to_exploit_synth` consumes `cve_to_poc` verified URLs
- `docs/research.md` — research flow detail
