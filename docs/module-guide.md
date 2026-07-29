# Module Guide

## Top-Level Modules

| Path | Responsibility |
| --- | --- |
| `main.py` | Primary launcher for interactive, recon, attack, doctor, self-test, resume, model, and MCP transport flows. |
| `app.py` | Tiny friendly launcher that imports and calls `main`. |
| `cli.py` | Deterministic workflow CLI over missions, scope, tasks, findings, and reports. |
| `agent_loop.py` | Full database-backed research loop orchestration. |
| `db.py` | SQLite schema, migrations, IDs, shared default database manager. |
| `mission.py` | Mission dataclass, validation, normalization, workspace initialization. |
| `scope_gate.py` | Asset allow/deny matching, forbidden actions, third-party detection, rate limiting. |
| `risk_controller.py` | Risk scoring, budgets, and human approval decisions. |
| `planner.py` | Task planning from mission, memory, graph, and recon state. |
| `task_queue.py` | Task creation, scoring, phase/status lifecycle, deduplication. |
| `executor.py` | Task execution through `ToolRouter`, with compact execution results. |
| `tool_router.py` | Routes approved tool requests and applies scope-aware execution rules. |
| `observer.py` | Parses tool output into structured observations and possible follow-up work. |
| `outcome_judge.py` | Typed deterministic outcome assessment, hypothesis persistence, terminal/duplicate check guards. |
| `summarizer.py` | Condenses nmap, HTTP, search, MSF, Python, terminal, and generic output. |
| `memory.py` | Persistent memories and semantic memory bridge. |
| `target_graph.py` | Graph model for assets, services, endpoints, parameters, evidence, and findings. |
| `evidence.py` | Filesystem evidence storage with SQLite metadata and integrity hashes. |
| `finding_verifier.py` | Candidate finding creation, validation, rejection, report readiness. |
| `report_generator.py` | Markdown finding and summary report generation. |
| `mcp_server.py` | Defensive MCP server with scope-aware nmap and intel tools. |
| `mcp_exploit_server.py` | Exploit MCP server with broad offensive tooling and workspace/session helpers. |

## `tools/`

| Area | Files |
| --- | --- |
| Model and reasoning | `model_router.py`, `goal_engine.py`, `goal_suggester.py`, `semantic_memory.py` |
| Safety and validation | `config_manager.py`, `doctor.py`, `safety_reviewer.py`, `validation_utils.py`, `command_analyzer.py`, `exceptions.py` |
| Recon and research | `recon_pipeline.py`, `cve_lookup.py`, `exploit_search.py`, `web_researcher.py`, `stealth.py` |
| Exploit orchestration | `exploit_agent/` (pkg: `loop.py`, `policy.py`, `context.py`, `prompt.py`, `reflection.py`, `skills.py`, `tool_calls.py`, `ollama_client.py`), `autonomous_orchestrator.py`, `attack_planner.py`, `attack_modules/` (pkg: `base.py`, `registry.py`, `modules/`), `payload_crafter.py`, `exploit_mutator.py`, `post_exploit.py` |
| External tooling | `metasploit_bridge.py`, `mcp_shared.py` |
| Persistence and learning | `session_manager.py`, `persistent_session_manager.py`, `experience_store.py`, `credential_store.py`, `activity_log.py` |
| Reporting and UX | `enhanced_reporting.py`, `interactive_menu.py`, `attack_ui.py`, `demo_mode.py`, `logging_setup.py`, `self_test.py`, `reliability.py` |

### Attack Modules

`tools/attack_modules/` defines `AttackModule`, `ModuleContext`, and seed modules. Categories include:

- CVE/service modules: Log4j, SMBGhost, EternalBlue, BlueKeep, OpenSSH checks.
- SSH/SMB modules: brute force, relay, null session.
- Web modules: basic auth, API fuzzing, upload, SQL injection, XSS, JWT, SSTI, deserialization, GraphQL, race/timing/request smuggling.
- Credential modules: spray, hash identification/cracking, pass-the-hash, dump hashes.
- Post-exploit modules: Linux/Windows privilege checks, SUID, kernel checks, container breakout.
- Network service modules: FTP, Redis, Elasticsearch, LDAP, RDP.
- AI-assisted modules: CVE-to-exploit, diff/patch analysis, fuzz-to-exploit.

Add a new module by subclassing `AttackModule`, implementing applicability and run behavior, and registering the class in `_MODULE_CLASSES`. Update `tests/test_attack_modules.py`.

## `tools/swarm/`

- `base.py`: common agent status/result types.
- `orchestrator.py`: routes tasks, runs agents in parallel, persists blackboard/battle log.
- `agents/recon_agent.py`: recon specialist.
- `agents/vuln_agent.py`: vulnerability research specialist.
- `agents/exploit_agent.py`: exploitation specialist.
- `agents/post_exploit_agent.py`: post-exploit specialist.
- `agents/critic_agent.py`: safety/policy critic.
- `agents/reflection_agent.py`: strategy reflection specialist.

Update `tests/test_swarm.py`, `tests/test_swarm_integration.py`, and `tests/test_swarm_observability.py` when changing this area.

## Tests

Tests are organized by module or feature. Examples:

- Core workflow: `test_mission.py`, `test_scope_gate.py`, `test_risk_controller.py`, `test_task_queue.py`, `test_outcome_judge.py`, `test_agent_loop.py`
- Persistence/reporting: `test_evidence.py`, `test_finding_verifier.py`, `test_report_generator.py`
- Exploit tooling: `test_attack_modules.py`, `test_mcp_workspace.py`, `test_retry_logic.py`, `test_lateral_tools.py`
- Safety/config: `test_safety_reviewer.py`, `test_config_manager.py`, `test_command_analyzer.py`, `test_audit_redaction.py`
- AI/research: `test_goal_engine.py`, `test_cve_lookup.py`, `test_recon_pipeline.py`, `test_semantic_memory.py`, `test_ultrathink.py`
- Menu/swarm: `test_interactive_menu.py`, `test_swarm.py`, `test_swarm_integration.py`, `test_swarm_observability.py`
