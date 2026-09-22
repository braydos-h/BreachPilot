# God-File Split Plans (todo 06)

Status: 3 of the top god files are split (this task); the rest have
per-file plans below and are NOT split yet. Do not grow any file below —
extract a logical submodule instead (see `scripts/god_file_budget.py`).

## Done (this task)

| File | Before | After |
| --- | --- | --- |
| `tools/eval_harness.py` | 2374+ | shim (~100) + `tools/eval/` (`metrics`, `single_run`, `suite`, `graded`, `live`) |
| `tools/memory_service.py` | 1927 | shim (~30) + `tools/memory/` (`helpers`, `attack_store`, `experience`, `semantic`, `session`, `service`) |
| `tools/web_researcher.py` | 1565→1584 | shim (~90) + `tools/research/` (`models`, `providers`, `facade`, `text_utils`) |

Characterization tests (written, not yet run — CI's job):
`tests/test_eval_package.py`, `tests/test_memory_package.py`,
`tests/test_research_package.py`.

Seam contract for all three splits (precedent:
`tools/campaign/phases.py` → `tools.autonomous_orchestrator`): tests keep
patching the OLD module path (`tools.eval_harness.run_eval`,
`docker_suite_up/down`, `open_exploit_mcp_session`,
`default_check_executor`); the new submodules resolve those names through
the shim at call time via `_eval_shim()`. Memory/research had no
shim-path patch points, so they use direct imports.

Owned by todo 05 (do NOT touch here): `tools/exploit_agent/runner/_impl.py`.

## Per-file plans (not yet split)

### 1. `tools/recon/enumerator.py` (1324) — next candidate
One class (`SecondaryEnumerator`) with per-service methods
(`_enumerate_http/ssh/smb/ldap/ftp/redis/elasticsearch/...`). Split by
service family, not by layer:
`tools/recon/enumerate/__init__.py` (dispatcher + `SecondaryEnumerator`
facade), `http.py`, `ssh.py`, `smb.py`, `ldap.py`, `ftp.py`,
`redis_elastic.py`, `misc.py` (udp/tls/smtp/db leftovers). Keep
`tools/recon/enumerator.py` as a shim (imported by `pipeline.py`,
`service.py`, `tools/recon/__init__.py`, tests). Coroutine fan-out in
`enumerate_host` stays in the facade.

### 2. `tools/api/event_broker.py` (1463) — NOT grandfathered, gate risk
Over budget but absent from `GRANDFATHERED` in `scripts/god_file_budget.py`
— either add a split or confirm the gate status. Responsibilities:
JSONL index/seek helpers (`_load_index`, `_seek_for_seq`,
`_parse_first/last_seq`, `_parse_seq_range`, `_shape_indexed_page`),
`_PluginEventDispatcher` + lifecycle fns, `RunEventBroker`,
`EventSubscription`, `EventBrokerRegistry`. Plan: `tools/api/events/`
(`index.py`, `plugin_dispatch.py`, `broker.py`, `registry.py`) with
`event_broker.py` as a shim. Check API route imports before moving.

### 3. `tools/providers/opencode_go_provider.py` (1421)
Responsibilities: HTTP client lifecycle (`_build_persistent_client`,
`_live_clients`, `close_all_opencode_go_clients`, keepalive/http2),
config/key coalescing (`_opencode_go_defaults`, `_coalesce`,
`_get_api_key`), message/schema conversion
(`_convert_tool_schemas`, `_convert_messages_to_input`,
`_normalize_content/usage`), SSE parsing (`_parse_sse_stream`),
`OpenCodeGoResponsesClient`, model discovery, `build_opencode_go_router`,
`OpenCodeGoProvider`. Plan: `tools/providers/opencode_go/` (`client.py`,
`config.py`, `convert.py`, `sse.py`, `discovery.py`, `provider.py`)
behind the existing module shim. Provider #4 rule applies: adapter +
registration + config metadata + tests, no agent/swarm/doctor edits.

### 4. `tools/browser/playwright_backend.py` (1443)
Responsibilities: config coercion (`_browser_cfg`, `_int_cfg`),
text/indicator helpers (`_summarize_text`, `_detect_indicators`),
error mapping (`_map_launch_error`, `_map_op_error`, crash names),
`InProcessPlaywrightLauncher`, `_PlaywrightSession`,
`PlaywrightBackend`. Plan: `tools/browser/` package already exists —
add `config.py`, `errors.py`, `launcher.py`, `session.py`,
`backend.py`; keep `playwright_backend.py` as a shim. Browser tests
(`test_browser_integration.py`) pin the import path.

### 5. `tools/attack_modules/modules/ics_iot.py` (1517)
One module per protocol already delineated by class + `build_*`/`query`/
`parse_*`/`main` groups: Modbus, DNP3, S7, BACnet, HMI creds, IoT creds,
Modbus-write, S7 start/stop. Duplicated `build_adu`/`query`/`main`
helpers per protocol are the extraction seam. Plan:
`tools/attack_modules/modules/ics/` (`modbus.py`, `dnp3.py`, `s7.py`,
`bacnet.py`, `creds.py`, `__init__.py` re-exporting the module classes);
keep `ics_iot.py` as a shim (registered in `_MODULE_CLASSES` by import
path — verify registry before renaming).

### 6. `tools/attack_ui.py` (1392→1404)
Responsibilities: questionary fallback (`_FallbackChoice`,
`_ensure_questionary`, `__getattr__` lazy), spinner state, `_sanitize`,
Windows ANSI, `AttackUi` god class, `get_ui()`. Plan:
`tools/attack_ui/` (`prompt.py`, `spinner.py`, `ui.py`) with
`attack_ui.py` as a shim. `AttackUi` methods group by menu area —
split methods with the class (facade + per-area mixins only if the
class itself is the seam; prefer one class per file by menu area).

### 7. `tools/mcp_tools/domain.py` (1367→1389)
One `register_domain_tools` closure holding five tools
(`resolve_domain`, `enumerate_subdomains`, `dns_recon`, `vhost_enum`,
`domain_whois`) + `_stdlib_fetch` / `_dns_resolve_all` helpers.
Constraint: `tools/mcp_tools/registry.py:collect_tools()` auto-discovers
`register_*_tools` (pkgutil + AST, decorator required) — keep ONE
`register_domain_tools(mcp, ctx)` entry point. Plan:
`tools/mcp_tools/domain/` (`resolve.py`, `subdomains.py`, `dns.py`,
`vhost.py`, `whois.py`, each exposing a `register_*` helper or plain
tool factories) with `domain.py` keeping the single register function
that wires them. All target-touching tools keep `@require_allowlist()`.

### 8. `tools/recon/service.py` (1271→1272)
Responsibilities: banner/CVE parse helpers (`cve_query_from_banner`,
`extract_tool_text`, `parse_os_result`, `parse_scan_ports`,
`build_compact_summary`, `plan_cve_queries`), `CveEnrichmentCache`,
`FastReconConfig/Result` + cache fns, `FastReconCoordinator`,
`run_sequential_assessment`, `ReconService`. Plan: fold into the
existing `tools/recon/` package (`parse.py`, `cache.py`,
`coordinator.py`) with `service.py` as a shim; `tools/recon/__init__.py`
`_ATTR_MAP` keeps every name resolvable. Do NOT overlap with the
enumerator split (plan §1) — service owns orchestration, enumerator
owns per-service logic.

### 9. `tools/persistent_session_manager.py` (1220)
Responsibilities: name/workspace validation, proc-tree kill,
`SessionInfo`, `TmuxHelper`, `BackgroundJobHelper`, `ListenerHelper`,
`ProcessTracker`, `PersistentSessionManager`,
`get/reset_session_manager`. Plan: `tools/sessions/` (`helpers.py`,
`tmux.py`, `jobs.py`, `listeners.py`, `tracker.py`, `manager.py`) with
the module as a shim. Explicitly NOT memory (`memory_service` docstring
already scopes this out) — OS processes, not facts.

### 10. `tools/mcp_tools/metasploit.py` (1196)
Thin `_clamp_*`/`_validate_*`/`_parse_msf_options` helpers + one
`register_metasploit_tools` closure. Same registry constraint as §7.
Plan: `tools/mcp_tools/metasploit/` (`validate.py`, `options.py`,
tool groups by action) with `metasploit.py` keeping the single
register entry point. Bridge logic itself lives in §11 — do not merge
the two; the MCP family only calls through `tools/metasploit_bridge.py`.

### 11. `tools/metasploit_bridge.py` (1165)
Responsibilities: `MsfSessionInfo`, `MsfModuleResult`,
`MsfSessionParser`, `MsfconsoleSession`, `MsfPayloadGenerator`,
`MetasploitBridge`, singletons, plus `_MsfRecipeModule` attack-module
recipes. Plan: `tools/metasploit/` (`models.py`, `parser.py`,
`session.py`, `payloads.py`, `bridge.py`, `recipes.py`) with the module
as a shim. Recipes stay registered via the attack-module registry.

### 12. `tools/mcp_tools/modules/web.py` (1114)
`_check_*`/`_clamp_*`/`_http_host`/`_open_connection`/`_sock_budget`/
`_preview`/`_finish` helpers + `register_web_tools`. Same registry
constraint as §7. Plan: `tools/mcp_tools/modules/web/` (`validate.py`,
`http.py`, tool groups) with `web.py` keeping the register entry
point. Target-touching tools keep `@require_allowlist()`.

### 13. `outcome_judge.py` (1081)
Responsibilities: outcome/hypothesis types (`ExecutionOutcome`,
`HypothesisStatus/State`, `OutcomeAssessment`, judge errors),
`OutcomeJudge`, `HypothesisRepository`, key/fingerprint builders,
criterion evaluators (`_criterion_met`, `_structured_criterion_met`,
`_text_criterion_met`, ...), evidence/contradiction/information
scorers, row converters. Plan: `tools/outcome/` (`types.py`,
`judge.py`, `repository.py`, `criteria.py`, `scoring.py`) with
`outcome_judge.py` as a shim. Root-level like `db.py`/`mission.py` —
new package under `tools/` matches the Flow A direction.

### 14. `tools/api/routes/runs.py` (1011→1049)
One `create_router` closure (all endpoints) + request models
(`RunCreateRequest`, `DecisionAnswerRequest`, `TitleRequest`,
`ToolCallRequest`, `HitlDecideRequest`) + path guards
(`_safe_child`, `_safe_workspace_path`). Plan: `tools/api/routes/runs/`
(`models.py`, per-resource endpoint modules) with `runs.py` keeping
`create_router` as the single wiring point. API contract tests pin
routes — move handlers without renaming paths.

### 15. `tools/sandbox/remediation.py` (1072)
Responsibilities: platform/run helpers (`_sanitize`, `_which`,
`_platform`, `_run`, `_detect_*`, `_image_name_from_config`),
`PlanStep` + `build_plan`, `Job/JobStepState` + sync/async accessors,
docker daemon poll/install/start, `_execute_job_async`. Sandbox rule
(AGENTS.md): fail closed — `SandboxError` → `SANDBOX_*` blocks, never a
host-execution fallback. Plan: `tools/sandbox/remedy/` (`plan.py`,
`jobs.py`, `docker.py`) with `remediation.py` as a shim.

### 16. `tools/doctor.py` (1032→966, shrinking)
One `_check_*` per subsystem + `_collect_doctor_checks` /
`build_doctor_report` / `run_doctor`. Already shrinking — lowest
priority. Provider rule: `--doctor` probes ONLY the active provider.
Plan (when touched): `tools/doctor/` (`env.py`, `providers.py`,
`workspace.py`, `report.py`) with `doctor.py` keeping
`run_doctor`/`build_doctor_report` as the entry points.
