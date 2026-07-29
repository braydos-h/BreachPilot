# Extension Guide

This guide explains where to edit code when adding tools, integrations, config, runtime behavior, or tests. It assumes contributors have already read [architecture.md](architecture.md), [module-guide.md](module-guide.md), and [safety-model.md](safety-model.md).

## Add a Defensive MCP Tool

Use this path for scan-only or intelligence tools that should stay tightly scoped.

Edit:

- `mcp_server.py`: add a new `@mcp.tool()` inside `create_mcp_server`.
- `tools/validation_utils.py`: add or reuse target/input validation helpers if the tool accepts hosts, IPs, URLs, or commands.
- `tests/`: add a focused test near existing MCP/safety coverage.

Follow these patterns:

- Normalize and check allowlists before touching a target.
- Return structured dictionaries with status, command/result text, and error details.
- Keep commands narrow. Existing nmap tools use fixed arguments and `_run_nmap`.
- Avoid shell expansion where possible.

Relevant tests:

- `tests/test_scope_gate.py`
- `tests/test_mcp_workspace.py`
- `tests/test_command_analyzer.py`
- `tests/test_recon_pipeline.py`

## Add an Exploit MCP Tool

Use this path only when the capability belongs in the broader exploit workspace.

Edit:

- `tools/mcp_tools/<category>.py`: add the `@mcp.tool()` implementation inside the relevant `register_<category>_tools(...)` function.
- `tools/mcp_tools/registry.py`: add MCP-tool-local shared helpers or dependency bundle fields only when the helper is genuinely shared by multiple exploit tool modules.
- `mcp_exploit_server.py`: update wiring only if the new tool needs a new category module or shared service.
- `tools/mcp_shared.py`: reuse workspace path resolution, audit logging, allowlist checks, and redaction helpers.
- `tools/exploit_agent/policy.py`: update `ExploitPolicy` so the model cannot call the tool outside the intended permission mode.
- `tools/command_analyzer.py`: update command/code analysis if the tool runs shell, Python, Metasploit, package installs, listeners, callbacks, or file writes.
- `tests/`: add policy, audit, redaction, and workspace tests.

Required safety work:

- Gate the tool by `ExploitPermission` mode.
- Check `exploit.require_explicit_allowlist` and `exploit.allowed_targets` for target-touching calls.
- Write generated files into the configured workspace.
- Redact secrets before audit logging.
- Sanitize large output before returning it to the model.
- Preserve public MCP tool names, function signatures, return text formats, audit decorators, and config semantics when refactoring existing tools.

Current exploit MCP categories:

- `terminal.py`: terminal, package, install, environment, and root-command helpers.
- `workspace.py`: workspace read/list/write helpers and Python file write/run helpers.
- `research.py`: exploit search, web fetch, deep research, and CVE lookup.
- `runtime_skills.py`: read-only runtime skill listing/search/loading.
- `peer_models.py`: advisory peer-model consultation.
- `metasploit.py`: Metasploit module execution and bridge/console helpers.
- `credentials.py`: encrypted credential store plus credential-use helpers.
- `payloads.py`: payload generation helpers.
- `recon.py`: OS/service detection and recon pipeline tools.
- `attack_modules.py`: attack planning, exploit crafting/mutation, web probes, campaign, and module execution tools.
- `sessions.py`: persistent sessions, background jobs, listeners, and process helpers.

Relevant tests:

- `tests/test_mcp_workspace.py`
- `tests/test_mcp_tool_registration.py`
- `tests/test_command_analyzer.py`
- `tests/test_audit_redaction.py`
- `tests/test_credential_store.py`
- `tests/test_retry_logic.py`

## Add an Attack Module

Attack modules are reusable service/CVE/workflow modules selected by context.

Edit:

- `tools/attack_modules/modules/`: subclass `AttackModule` in the relevant category module.
- `tools/attack_modules/modules/`: implement `applicability(ctx: ModuleContext) -> int` if the base scoring is not enough.
- `tools/attack_modules/modules/`: implement `run(ctx: ModuleContext) -> dict[str, Any]`.
- `tools/attack_modules/registry.py`: register the class in `_MODULE_CLASSES`.
- `tests/test_attack_modules.py`: cover registry, applicability, run output, and edge cases.

Key types:

- `ModuleContext`: target IP, service, port, CVEs, banners, credentials, and metadata.
- `AttackModule`: base class with module metadata and execution contract.
- `list_modules`, `find_modules`, `get_module`: registry helpers used by higher-level flows.

Conventions:

- Return data, commands, workflow instructions, or generated script text as structured dictionaries.
- Keep module names stable because tests and orchestrators can reference them.
- Do not embed credentials in plain output.

## Add Runtime Skill Guidance

Use this path for advisory methodology that should guide the model without adding
new execution capability.

Edit:

- `skills-to-add/<skill-name>/SKILL.md`: add YAML front matter and Markdown guidance.
- `config.yaml`: add the skill to `skills.default_enabled` or rely on tags for contextual selection.
- `tests/test_skill_registry.py` or `tests/test_skill_selector.py`: cover parsing and selection behavior when the skill changes core routing.

Conventions:

- Skills are prompt context only. They must not bypass scope, permission, approval, command safety, workspace containment, or audit logging.
- Prefer accurate tags such as `nmap`, `api`, `active-directory`, `tls`, `reconnaissance`, or `vulnerability-scanning`.
- Put higher-risk or niche skills under `skills-to-add/maybe/`; they are ignored unless `skills.maybe_enabled` is true.
- Keep guidance compact. By default selected skills are exposed as short hints
  and full text is loaded later through `load_runtime_skill`; only
  `skills.inject_startup_context: true` uses `skills.max_total_chars` to inject
  selected skill bodies into the startup prompt.

## Add Recon Behavior

Use `tools/recon_pipeline.py` for host/service discovery and enrichment.

Important classes:

- `ServiceInfo`: parsed service/port details.
- `HostReconResult`: per-host recon output.
- `ReconConfig`: scanner behavior and timeouts.
- `PrimaryReconScanner`: initial host/port/service scanning.
- `SecondaryEnumerator`: deeper service-specific enumeration.
- `ReconPipeline`: high-level orchestration.

Also check:

- `main.py::run_recon_assessment`
- `tools/goal_suggester.py`
- `tests/test_recon_pipeline.py`
- `tests/test_recon_first_session.py`

Keep recon changes deterministic where possible and make external tool failures explicit.

## Add a Goal or Goal Suggestion

Preset goals and goal compatibility live in `tools/goal_engine.py`.

Recon-driven recommendations live in `tools/goal_suggester.py`.

Edit:

- `tools/goal_engine.py`: add or modify `AttackGoal` presets and compatibility checks.
- `tools/goal_suggester.py`: update assessment heuristics and suggested-goal output.
- `main.py`: update argument handling only if a new CLI flag or flow is needed.

Tests:

- `tests/test_goal_engine.py`
- `tests/test_recon_first_session.py`

## Add Model Routing Behavior

Edit:

- `tools/model_router.py`: model metadata, client selection, and routing strategy.
- `config.yaml`: operator-facing model aliases and info.
- `tools/config_manager.py`: defaults and validation.
- `tools/mcp_tools/peer_models.py`: peer-model advisory tooling when `multi_model` is involved.
- `main.py`: CLI flag behavior only if required.

Tests:

- `tests/test_config_manager.py`
- `tests/test_ultrathink.py`
- Any focused tests that exercise model selection in `main.py`.

Keep `config.yaml` model aliases and `models.info` synchronized because context-window metadata is used by adaptive context handling in `tools/exploit_agent/`. Peer consultation should stay opt-in via `multi_model.enabled` or a per-run CLI override because each consultation spends extra tokens.

## Add Config Keys

Edit:

- `config.yaml`: checked-in operator defaults.
- `tools/config_manager.py::CONFIG_SCHEMA`: defaults used when config is missing or incomplete.
- `tools/config_manager.py::ConfigValidator.validate`: type/range validation.
- `tools/interactive_menu.py`: only if operators should edit the setting interactively.
- `tests/test_config_manager.py`: defaulting and validation coverage.

Conventions:

- Keep first-run defaults conservative.
- Treat unknown keys as warnings unless they make runtime behavior ambiguous.
- Document new environment variables in [getting-started.md](getting-started.md) or this guide.

## Add Persistent Data

Edit:

- `db.py`: update `DDL`, `_SCHEMA_VERSION`, and `_run_migration`.
- Add migration helper methods for non-trivial schema changes.
- Add high-level database methods if multiple modules need the data.
- Update the relevant service module to use the database API rather than ad hoc SQL.

Tests:

- Existing module tests for the feature area.
- A migration/regression test if the schema change affects existing databases.

Conventions:

- Store JSON fields as text and deserialize at the boundary.
- Use prefix-style IDs created through `_new_id`.
- Keep writes inside `DatabaseManager.connection(write=True)`.

## Add Task or Agent-Loop Behavior

Edit based on the layer you are changing:

- `planner.py`: what work should exist.
- `task_queue.py`: task lifecycle, phase normalization, priority, deduplication.
- `risk_controller.py`: approval and budget behavior.
- `executor.py`: execution plans and results.
- `tool_router.py`: actual tool dispatch and scope-aware execution.
- `observer.py`: output parsing into facts, findings, memories, and follow-up tasks.
- `agent_loop.py`: high-level orchestration.

Tests:

- `tests/test_agent_loop.py`
- `tests/test_task_queue.py`
- `tests/test_risk_controller.py`
- `tests/test_scope_gate.py`

## Add Swarm Behavior

Edit:

- `tools/swarm/base.py`: shared agent result/status contract.
- `tools/swarm/orchestrator.py`: routing, parallel execution, critic/reflection flow, persisted state.
- `tools/swarm/agents/*.py`: specialist behavior.

Tests:

- `tests/test_swarm.py`
- `tests/test_swarm_integration.py`
- `tests/test_swarm_observability.py`

Conventions:

- Keep the critic path available for high-risk task types.
- Persist blackboard and battle-log changes where the orchestrator already writes state.
- Return structured `AgentResult` values rather than free-form strings only.

## Add Evidence, Finding, or Report Behavior

Edit:

- `evidence.py`: raw artifacts, metadata, hashes, and evidence lookup.
- `finding_verifier.py`: candidate lifecycle, validation scoring, rejection, report readiness.
- `report_generator.py`: Markdown report output.
- `tools/enhanced_reporting.py`: exploit-session timelines, CVSS helpers, chains, and technical finding reports.

Tests:

- `tests/test_evidence.py`
- `tests/test_finding_verifier.py`
- `tests/test_report_generator.py`

Conventions:

- Keep report output evidence-linked and reproducible.
- Avoid overstating severity when validation is incomplete.
- Store raw data separately from summaries.

## Add External Tool Integration

Existing integrations include nmap, Ollama, NVD, searchsploit, Metasploit, tmux/background jobs, and package managers.

Use these modules:

- `tools/reliability.py`: retries, timeouts, circuit breaker, fallback, error tracking.
- `tools/doctor.py`: local environment checks.
- `tools/self_test.py`: safe localhost smoke test.
- `tools/validation_utils.py`: target validation and command preflight checks.
- `tools/command_analyzer.py`: destructive command and egress analysis.
- `tools/logging_setup.py`: shared logging behavior.

Add tests for missing-tool behavior and timeout behavior. Do not assume the external binary exists on every developer machine.

## Debugging Checklist

1. Run the focused pytest file for the touched module.
2. Run `python main.py --doctor` for environment/config issues.
3. Run `python main.py --self-test` for safe integration smoke testing.
4. Inspect `research_workspace/logs/app.log` when logging is configured.
5. Inspect `exploit_workspace/exploit_audit.jsonl` for exploit MCP calls.
6. Inspect generated `reports/<timestamp>/` directories for session output.
7. For database state, use the SQLite file under `research_workspace/research.db` or the test workspace being exercised.
