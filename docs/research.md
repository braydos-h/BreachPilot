# Research Subsystem

The research subsystem is the read-only intelligence layer of the exploit
engine (Flow A). It searches public sources, fetches and summarizes pages,
looks up CVEs, resolves CVEs to verified PoC URLs, and feeds source-backed
advisories into the exploit agent and the recon phase. Nothing in this
subsystem executes commands or payloads; all network I/O is read-only and
target-safe (private/internal hosts are blocked by default).

## Component Table

| Component | Purpose | Input | Output |
|---|---|---|---|
| `tools/web_researcher.py` — `WebResearcher` (tools/web_researcher.py:545) | Provider-backed web search/fetch facade; ranks, dedupes, caches, and summarizes sources | query string or URL | `WEB_SEARCH_RESULTS:` text, `FETCHED:` text, or `ResearchBrief` JSON (tools/web_researcher.py:147) |
| `tools/web_researcher.py` — `OllamaResearchProvider` (tools/web_researcher.py:309) | Primary search/fetch via Ollama's `web_search`/`web_fetch` (needs `OLLAMA_API_KEY`) | query / URL | `SearchResult` / `FetchResult` |
| `tools/web_researcher.py` — `SerpAPIResearchProvider` (tools/web_researcher.py:398) | Fallback search via SerpAPI (DuckDuckGo engine); fetch unsupported | query | `SearchResult` list |
| `tools/web_researcher.py` — `StdlibFetchProvider` (tools/web_researcher.py:459) | Last-resort URL fetch with stdlib HTML→text extraction | URL | `FetchResult` |
| `tools/web_researcher.py` — `validate_url` (tools/web_researcher.py:1252) | URL allow/block-list gate; blocks private/internal hosts | URL | normalized URL or `BLOCKED:` string |
| `tools/web_researcher.py` — `source_quality_score` (tools/web_researcher.py:1328) | Ranks sources (primary hosts like nvd.nist.gov, github.com, exploit-db.com score higher) | url/title/content | int score + label |
| `tools/exploit_search.py` — `ExploitSearch` (tools/exploit_search.py:105) | Local exploit-db search (`searchsploit --json`) + web-search delegation + CVE→verified-PoC resolution | query / CVE ID | `SEARCHSPLOIT_RESULTS:` / `CVE_TO_POC_RESULTS:` / `NO_VERIFIED_POC_FOUND:` text |
| `tools/cve_lookup.py` — `NVDClient` (tools/cve_lookup.py:217) | NVD API 2.0 keyword/CPE lookup with rate limiting, LRU cache, circuit breaker | query or CPE name | `list[CVEEntry]` |
| `tools/cve_lookup.py` — `EPSSClient` (tools/cve_lookup.py:114) | Opt-in EPSS exploit-likelihood enrichment (first.org API) | CVE IDs | `{cve: {epss, percentile}}` |
| `tools/cve_lookup.py` — `KEVCatalog` (tools/cve_lookup.py:156) | Opt-in CISA KEV membership with 24h on-disk catalog cache | CVE ID | `is_known_exploited(cve) -> bool` |
| `tools/recon_enrichers.py` | Pure parsers + bounded single-target web spider for the recon pipeline | nmap output / banners / target IP:port | structured dicts (see Enricher Inventory) |
| `tools/mcp_tools/research.py` | MCP tool registration for the six research tools | MCP call args | MCP tool result text |
| `tools/exploit_agent/research_assistant.py` — `ResearchAssistant` (tools/exploit_agent/research_assistant.py:184) | Bounded read-only sidecar LLM that consults the research MCP tools and returns advisories | research question + target evidence | normalized advisory dict, persisted to `research_advisories.jsonl` |
| `tools/session_manager.py` — `SessionManager` (tools/session_manager.py:104) | Session/context persistence and resume | target + actions | `session_state.json` + resume messages |

## Research Flow

```text
exploit agent (tools/exploit_agent/loop.py)
  |  consult_research_assistant (explicit)  /  automatic triggers
  v
ResearchAssistant.consult (research_assistant.py:257)
  |  short model conversation, only RESEARCH_ASSISTANT_TOOLS allowed
  |  (search_cve_intel, search_exploit_db, search_web_exploit,
  |   fetch_webpage, deep_research, cve_to_poc)  (research_assistant.py:32)
  v
MCP session -> tools/mcp_tools/research.py
  |  search_web_exploit / fetch_webpage / deep_research
  |    -> WebResearcher (web_researcher.py:545)
  |       search chain: ollama -> serpapi (web_researcher.py:824)
  |       fetch chain:  ollama -> serpapi -> stdlib (web_researcher.py:828)
  |       validate_url gate -> dedupe/rank -> cache -> format
  |  search_cve_intel -> NVDClient.search_sync (cve_lookup.py:308)
  |  search_exploit_db -> ExploitSearch.search_exploit_db (exploit_search.py:118)
  |  cve_to_poc -> ExploitSearch.cve_to_poc (exploit_search.py:190)
  v
advisory normalized + persisted (research_assistant.py:540, :663)
  v
format_for_main -> "[RESEARCH ASSISTANT ADVISORY]" message appended
  to the main agent's conversation (loop.py:738-746)
```

Deep research (`deep_research`) internally runs: search → dedupe/rank →
select fetch candidates by quality threshold → fetch up to `max_fetch_depth`
pages → extract key facts (CVE/exploit/patch sentences, web_researcher.py:947)
→ confidence scoring (web_researcher.py:969) → `ResearchBrief` JSON
(web_researcher.py:605).

## Web Research

- **Providers**: `ollama` (default, uses the Ollama client's `web_search` /
  `web_fetch`, web_researcher.py:357-395), `serpapi` (search only,
  web_researcher.py:408), `stdlib` (fetch only, web_researcher.py:475).
  Chains are built from `provider` + `fallback_provider` (+ `stdlib` for
  fetch) in web_researcher.py:824-844; the first provider that returns
  results wins, and `fallback_used` is reported.
- **Fetching**: `StdlibFetchProvider` uses `urllib` with a browser
  User-Agent, extracts title/text via the stdlib `_TextExtractor` HTMLParser
  (web_researcher.py:1144, skips script/style/nav/footer/etc.), collects
  links, and truncates content to `max_content_chars`.
- **Summarization**: search results are formatted as
  `WEB_SEARCH_RESULTS:` blocks with per-result quality labels
  (web_researcher.py:1023); fetched pages as `FETCHED:` blocks
  (web_researcher.py:1055). `deep_research` produces the structured
  `ResearchBrief` with `key_facts`, `confidence`, `reliability_notes`,
  `relevant_cves`, and `suggested_next_queries`.
- **Safety**: every URL passes `validate_url` (web_researcher.py:1252) —
  private/internal hosts (RFC1918, localhost, `.internal`, metadata IPs)
  are blocked unless `allow_local_fetch` is set; `allowed_domains` /
  `blocked_domains` filters apply; queries are sanitized against shell
  metacharacters (web_researcher.py:756). Providers carry exponential
  backoff after failures (web_researcher.py:290-306).
- **Caching**: in-memory LRU `OrderedDict` caches for search and fetch,
  keyed by `provider|max_results|query` and `provider|max_content_chars|url`
  (web_researcher.py:1102-1141), TTL `cache_ttl_seconds` (default 1800s),
  capped at `cache_max_entries` (default 250).

## Recon Enrichment

`tools/recon_enrichers.py` is a standalone helper layer for
`SecondaryEnumerator` (tools/recon_pipeline.py:1033). Parsers are pure
(never raise); the spider is a bounded BFS that connects ONLY to the single
authorized `target_ip:port` (recon_enrichers.py:587).

### Enricher Inventory

| Enricher | Location | Input | Output |
|---|---|---|---|
| `parse_tls_info` | recon_enrichers.py:90 | nmap `ssl-cert` text or JSON cert dict | `{issuer, subject, san[], valid_from, valid_to, protocol, cipher}` |
| `parse_smtp_banner` | recon_enrichers.py:206 | SMTP EHLO/220 banner | `{server_software, supports_starttls, auth_methods[], banner}` |
| `parse_db_banner` | recon_enrichers.py:268 | DB handshake/banner + service name | `{db_type, version, auth_required, banner}` (mysql/postgres/mssql/mongo/redis) |
| `parse_udp_nmap_output` | recon_enrichers.py:425 | nmap UDP output (grepable or XML) | `[{port, protocol, service, state, banner}]` |
| `http_spider` | recon_enrichers.py:587 | target_ip, port, scheme, max_pages, injectable `fetch_fn` | `{target_ip, port, urls_visited, links, forms, status_codes, technologies}` |

Wiring in the recon pipeline (each targets only the authorized
`result.target_ip` and is routed through `run_command`):

- TLS: `_enumerate_tls` runs `nmap --script ssl-cert,ssl-enum` and parses
  with `parse_tls_info` → `svc.ssl_info` (recon_pipeline.py:1689-1724).
- SMTP: `_enumerate_smtp` runs `smtp-commands,smtp-open-relay` and parses
  with `parse_smtp_banner` → `svc.smtp_info` (recon_pipeline.py:1726-1762).
- DB: `_enumerate_db` runs `banner,default` and parses with
  `parse_db_banner` → `svc.db_info` (recon_pipeline.py:1764-1799).
- Web: `_enumerate_web_spider` calls `http_spider` (max 20 pages) →
  `result.spider_results` (recon_pipeline.py:1802-1833).
- UDP: `parse_udp_nmap_output` parses Round 1 UDP scan output
  (recon_pipeline.py:644-650).
- OSINT: `_enumerate_osint` runs passive `tools.recon_osint.run_osint`
  (reverse DNS, crt.sh, optional Shodan) → `result.osint`
  (recon_pipeline.py:1835-1859).

## CVE Lookup

`tools/cve_lookup.py` queries the NVD API 2.0
(`https://services.nvd.nist.gov/rest/json/cves/2.0`, cve_lookup.py:30) by
keyword (`keywordSearch`) or CPE name (`cpeName`, cve_lookup.py:395).

### Caching and resilience

- **LRU cache**: `OrderedDict` keyed by lowercased query, TTL
  `cache_ttl_seconds` (default 3600s), capped at `cache_max_entries`
  (default 100); shared between sync/async paths under a threading lock
  (cve_lookup.py:225-229, 260-267, 302-305).
- **Rate limiting**: per-instance `asyncio.Lock` + `_last_request_time`
  enforcing `rate_limit_seconds` (default 6.0s, NVD's no-key limit), or a
  process-wide shared `RateLimiter` built from
  `cve_lookup.search_rate_limit_per_minute` (default 10/min) when provided
  (cve_lookup.py:276-285; wired in tools/mcp_shared.py:92-115).
- **Circuit breaker**: after `circuit_failure_threshold` (5) consecutive
  failures the breaker opens and lookups short-circuit to `[]` for
  `circuit_recovery_timeout` (60s), then a half-open probe is allowed.
  4xx responses are soft misses that do NOT open the breaker
  (cve_lookup.py:269-300, 340-350).
- **API key**: `NVD_API_KEY` env (config `cve_lookup.api_key_env`) is
  appended as `apiKey` when present (cve_lookup.py:371-374).
- **EPSS/KEV enrichment** (opt-in, default off): `EPSSClient` batches one
  GET to `https://api.first.org/data/v1/epss?cve=...` per result set with an
  in-memory cache (cve_lookup.py:114-153); `KEVCatalog` downloads the CISA
  KEV feed once and caches it to `exploit_workspace/.kev_catalog.json` with a
  24h TTL (cve_lookup.py:156-214). Both degrade silently on failure.
- **Output**: `format_cve_results` (cve_lookup.py:490) renders
  `CVEEntry.summary()` (cve_lookup.py:95) — CVE ID, severity, CVSS, EPSS,
  KEV, CWE, published date, description, references.

## MCP Research Tools

Registered in `tools/mcp_tools/research.py:8` (`register_research_tools`),
wired into the server in `mcp_exploit_server.py:158`. All are read-only and
audited via the `@audit_tool` decorator; none require a target IP (they do
not touch the target).

| Tool | Location | Behavior |
|---|---|---|
| `search_exploit_db` | research.py:18 | `searchsploit --json` local search via `ExploitSearch` |
| `search_web_exploit` | research.py:23 | provider web search; disabled without a research API key |
| `fetch_webpage` | research.py:30 | fetch one public URL (private/internal blocked) |
| `deep_research` | research.py:37 | multi-source structured brief (JSON) |
| `search_cve_intel` | research.py:44 | NVD lookup; NVD failures degrade to `NO_CVE_RESULTS:` instead of erroring the loop |
| `cve_to_poc` | research.py:61 | CVE → VERIFIED PoC URLs only (GitHub Search API + `searchsploit --cve` + NVD refs, each HTTP-existence-checked via `url_exists`, exploit_search.py:36); returns `NO_VERIFIED_POC_FOUND` rather than guessing |

Web tools are gated on `research_api_keys_available` (tools/api_key_store.py:175):
when `research.require_api_key_for_mcp_tools` is true and no configured key
(`OLLAMA_API_KEY` / `SERPAPI_API_KEY`) is present, they return
`RESEARCH_API_KEY_MISSING: ... disabled` (api_key_store.py:190).

## Research Assistant (exploit-agent sidecar)

`ResearchAssistant` (tools/exploit_agent/research_assistant.py:184) is a
bounded, read-only sidecar LLM that runs its own short model conversation
through the exploit loop's existing MCP session. It can call ONLY the six
research tools (research_assistant.py:32); any other tool request is blocked
and warned (research_assistant.py:340-345). Its system prompt
(research_assistant.py:46) treats all fetched content as untrusted data and
requires a structured JSON advisory (status/summary/confidence/findings/
contradictions/unknowns/recommended_next_tests/warnings/sources).

### How results flow into the exploit agent

- **Construction**: built in attack mode when `research.assistant.enabled`
  (loop.py:638-657); the local `consult_research_assistant` tool schema is
  appended to the agent's tool list (loop.py:654) and a prompt briefing is
  appended to the system prompt (loop.py:691-692).
- **Explicit**: the main model calls `consult_research_assistant`; the loop
  runs `consult(trigger="explicit")` and appends the rendered advisory as a
  tool result (loop.py:1110-1156).
- **Automatic triggers** (when `automatic: true`, capped at
  `max_auto_consultations`, deduped by topic key):
  - startup evidence: known CVEs + service context (loop.py:776-796);
  - new target evidence: new service/CVE topics (loop.py:1889);
  - repeated exploit failures: after `failure_trigger` consecutive failures
    (loop.py:1631-1655, `note_exploit_outcome` at research_assistant.py:245).
- **Advisory rendering**: `format_for_main` (research_assistant.py:421)
  emits the `[RESEARCH ASSISTANT ADVISORY]` marker, findings with source
  URLs, suggested next tests, and a sources list, capped at
  `max_advisory_chars`; appended to the main conversation as a user message
  (loop.py:738-746). Every consultation is recorded in the policy audit log
  (loop.py:767-773, 1141-1154).
- **Budgets**: `max_model_rounds` (3), `max_tool_calls_per_consultation`
  (5), `timeout_seconds` (90); tool outputs are compacted to 12k chars with
  source URLs retained (research_assistant.py:739-754). Malformed model
  output degrades to a `partial` advisory (research_assistant.py:557-570).
- **Persistence**: advisories append to
  `<workspace>/research_advisories.jsonl` (research_assistant.py:663); on
  restart, counts and seen auto-topics are restored from that file
  (research_assistant.py:674), so auto-consult dedup survives restarts.
- **Model**: uses the active model, or `research.assistant.model_alias`
  resolved through `models.registry` (research_assistant.py:497-524).

## Session / Context Management

- `SessionManager` (tools/session_manager.py:104) persists per-target state
  to `<workspace>/session_state.json` (session_manager.py:110): target,
  CVEs, service context, phase, action history (last 100), loot, credentials,
  compromised hosts. `record_action` (session_manager.py:203) logs every
  tool call including research consultations (loop.py:1136-1140).
- On resume, `build_resume_messages` (session_manager.py:276) reconstitutes
  the conversation from saved state (or returns persisted messages verbatim
  in long-session mode).
- Research context for auto-consultations is built from the last 8 messages
  plus target/OS/CVE/service context (`_recent_research_context`,
  loop.py:723-736), bounded to 6000 chars.
- The research assistant's own state (counts, seen topics, sources) lives in
  `research_advisories.jsonl` (research_assistant.py:223).

## Config Keys

`config.yaml` — `cve_lookup:` (config.yaml:160-179) and `research:`
(config.yaml:180-213). Validated in tools/config_manager.py:634-700.

| Key | Default | Meaning |
|---|---|---|
| `cve_lookup.enabled` | true | master switch for NVD lookups |
| `cve_lookup.max_results` | 5 | results per NVD query |
| `cve_lookup.rate_limit_seconds` | 6.0 | per-instance NVD gap (no API key) |
| `cve_lookup.search_rate_limit_per_minute` | 10 | shared process-wide NVD budget |
| `cve_lookup.cache_ttl_seconds` / `cache_max_entries` | 3600 / 100 | NVD LRU cache |
| `cve_lookup.api_key_env` | `NVD_API_KEY` | env var for NVD API key |
| `cve_lookup.circuit_failure_threshold` / `circuit_recovery_timeout` | 5 / 60.0 | circuit breaker |
| `cve_lookup.epss_enabled` / `kev_enabled` | false | EPSS / KEV enrichment |
| `cve_lookup.kev_cache_ttl_seconds` / `kev_cache_path` | 86400 / "" | KEV catalog cache ("" = `exploit_workspace/.kev_catalog.json`) |
| `cve_lookup.github.token_env` | `GITHUB_TOKEN` | GitHub token for `cve_to_poc` |
| `research.enabled` | true | master switch for web research |
| `research.provider` / `fallback_provider` | ollama / serpapi | search/fetch chain |
| `research.timeout_seconds` | 15 | per-request timeout |
| `research.max_results` | 8 | search results kept |
| `research.max_fetch_depth` | 5 | pages fetched per brief |
| `research.max_content_chars` | 12000 | per-page content cap |
| `research.cache_ttl_seconds` / `cache_max_entries` | 1800 / 250 | web research LRU cache |
| `research.min_source_quality` | medium | fetch-candidate quality threshold |
| `research.require_api_key_for_mcp_tools` | true | gate web MCP tools on API keys |
| `research.allow_local_fetch` | false | allow private/internal fetch targets |
| `research.ollama.api_key_env` / `use_web_search` / `use_web_fetch` | `OLLAMA_API_KEY` / true / true | Ollama provider |
| `research.serpapi.api_key_env` / `endpoint` / `engine` / `region` | `SERPAPI_API_KEY` / serpapi.com / duckduckgo / us-en | SerpAPI provider |
| `research.assistant.enabled` | true | sidecar assistant |
| `research.assistant.model_alias` | "" | "" = active model |
| `research.assistant.automatic` | true | auto consultations on new evidence/failures |
| `research.assistant.failure_trigger` | 2 | consecutive failures before auto research |
| `research.assistant.max_auto_consultations` | 4 | auto-consult cap per run |
| `research.assistant.max_tool_calls_per_consultation` | 5 | tool budget per consult |
| `research.assistant.max_model_rounds` | 3 | model round budget |
| `research.assistant.max_advisory_chars` | 4000 | advisory size cap |
| `research.assistant.timeout_seconds` | 90 | consult deadline |
| `research.assistant.save_advisories` | true | persist to `research_advisories.jsonl` |

## Adding a New Research Source

Two extension points, depending on what the source does:

**1. A new web search/fetch provider** (e.g. a different search API):
subclass `ResearchProvider` (tools/web_researcher.py:235) implementing
`_search` / `_fetch`, add it to `WebResearcher._build_default_providers`
(web_researcher.py:736) and to the search/fetch chains
(web_researcher.py:824-830), and add a settings dataclass + config block
mirroring `SerpAPIResearchSettings` (web_researcher.py:181). Register the
new provider name in `tools/config_manager.py` validation
(config_manager.py:640-648) and document the key in README §Configuration.

**2. A new recon enrichment** — follow docs/extension-guide.md "Add Recon
Behavior" (extension-guide.md:125): add a pure parser to
`tools/recon_enrichers.py` (export it in `__all__`, recon_enrichers.py:677),
then add a `_enumerate_*` method on `SecondaryEnumerator`
(tools/recon_pipeline.py:1033) that runs the scan via `run_command` and
parses the output into the `ServiceInfo`/`HostReconResult` fields, mirroring
`_enumerate_tls` (recon_pipeline.py:1689). Keep it deterministic, target-
locked to `result.target_ip`, and covered by `tests/test_recon_pipeline.py`.

**3. A new MCP research tool**: register it in
`tools/mcp_tools/research.py` with the `@audit_tool` decorator, add it to
`RESEARCH_ASSISTANT_TOOLS` (research_assistant.py:32) if the sidecar should
use it, and add it to the tool list in `mcp_exploit_server.py` (per
AGENTS.md rule 4).
