# Module Guide

## Top-Level Modules

| Path | Responsibility |
| --- | --- |
| `main.py` | Primary launcher: **WebUI daemon by default (no args)**, direct recon/attack runs, `--menu` terminal menu, doctor, self-test, resume, model, and MCP transport flows. |
| `app.py` | FastAPI app factory for the WebUI API daemon (`main._run_daemon` imports it; never run directly). |
| `cli.py` | Deterministic workflow CLI over missions, scope, tasks, findings, and reports (legacy Flow B shim → `legacy/cli.py`). |
| `agent_loop.py` | Full database-backed research loop orchestration (legacy Flow B shim → `legacy/agent_loop.py`). |
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
| Model and reasoning | `providers/` (pkg: `types/base/registry` + `ollama_provider.py`, `opencode_go_provider.py`, `chatgpt_provider.py`, `embeddings.py`), `model_router.py`, `model_telemetry.py`, `goal_engine.py`, `goal_suggester.py`, `semantic_memory.py` |
| Safety and validation | `tools/config/` (pkg: `schema.py`, `validator.py`, `loader.py`; `config_manager.py` is a re-export shim), `doctor.py`, `safety_reviewer.py`, `validation_utils.py`, `command_analyzer.py`, `exceptions.py`, `env_probe.py` |
| Recon and research | `tools/recon/` (pkg: `pipeline.py`, `scanner.py`, `enumerator.py`, `config.py`; `recon_pipeline.py` is a deprecated shim), `fast_recon.py`, `cve_lookup.py`, `exploit_search.py`, `web_researcher.py`, `recon_enrichers.py`, `recon_diff.py`, `recon_osint.py`, `nmap_priv.py`, `socket_scan.py` |
| Exploit orchestration | `tools/exploit_agent/runner/_impl.py` (**canonical agent loop**; loaded by `tools/exploit_agent/runner/loop.py`), `exploit_agent/` (pkg: `policy.py`, `phase_tracker.py`, `context.py`, `prompt.py`, `reflection.py`, `skills.py`, `tool_calls.py`, `tool_catalog.py`, `model_client.py` (`ollama_client.py` is its deprecation shim), `research_assistant.py`, `outcome_classify.py`, `outcome_truth.py`, `outcome_adapter.py`; `loop.py` is a deprecated re-export shim), `tools/campaign/` (pkg behind the `autonomous_orchestrator.py` facade), `attack_planner.py`, `attack_modules/` (pkg: `base.py`, `registry.py`, `modules/`), `payload_crafter.py`, `exploit_mutator.py`, `post_exploit.py` |
| Kill-chain state machine | `tools/killchain/` (pkg: machine, stages, edges, persistence; conditional on `killchain.enabled`) + `tools/mcp_tools/killchain.py` (MCP family) |
| Snapshots / rollback | `snapshots.py` (providers + `SnapshotManager`), `tools/mcp_tools/snapshots.py` (MCP family), counterfactual replay in `tools/exploit_agent/runner/_impl.py` |
| OPSEC and detection | `opsec.py`, `detection_coverage.py` |
| External tooling | `metasploit_bridge.py`, `mcp_shared.py` |
| Persistence and learning | `session_manager.py`, `persistent_session_manager.py`, `experience_store.py`, `credential_store.py`, `activity_log.py`, `attack_memory.py`, `api_key_store.py` |
| Skills | `skill_registry.py`, `skill_selector.py`, `skill_embeddings.py`, `skill_pipeline.py`, `skill_feedback.py`, `skill_registry_cache.py` |
| Flow A CLI orchestration | `config_cli.py`, `cli_exploit_settings.py`, `exploit_session.py`, `mcp_session.py`, `recon_assessment_cli.py`, `resume_state.py`, `safety_review_cli.py`, `skills_cli.py`, `swarm_bridge.py` |
| Reporting and UX | `enhanced_reporting.py`, `interactive_menu.py`, `attack_ui.py`, `demo_mode.py`, `logging_setup.py`, `self_test.py`, `reliability.py`, `eval_harness.py` |

### Attack Modules

`tools/attack_modules/` defines `AttackModule`, `ModuleContext`, and seed modules. Categories include:

- CVE/service modules: Log4j, SMBGhost, EternalBlue, BlueKeep, OpenSSH checks.
- SSH/SMB modules: brute force, relay, null session.
- Web modules: basic auth, API fuzzing, upload, SQL injection, XSS, JWT, SSTI, deserialization, GraphQL, race/timing/request smuggling.
- Credential modules: spray, hash identification/cracking, pass-the-hash, dump hashes.
- Post-exploit modules: Linux/Windows privilege checks, SUID, kernel checks, container breakout.
- Network service modules: FTP, Redis, Elasticsearch, LDAP, RDP.
- AI-assisted modules: CVE-to-exploit, diff/patch analysis, fuzz-to-exploit.
- Active Directory (`ad.py`): AD enumeration and attack modules.
- ICS/IoT (`ics_iot.py`): industrial control and IoT device modules.
- Detection/AV evasion (`detection.py`): detection-aware and AV-evasion modules.
- Persistence (`persistence.py`): persistence establishment modules.
- Supply chain (`supply_chain.py`): supply-chain attack modules.
- Orchestrator phases (`orchestrator_phases.py`): orchestrator phase modules.

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
- `agents/witness_agent.py`: advisory audit-stream watcher (NOT routed by the orchestrator; spawned per-run by `tools/run_service/execute.py` when `witness.enabled` is true — detection/flagging only, never gates the run).
- `skill_phase.py`: skill phase routing.

Update `tests/test_swarm.py`, `tests/test_swarm_integration.py`, and `tests/test_swarm_observability.py` when changing this area.

## Tests

Tests are organized by module or feature; the suite has grown to **~250** files (all mock subprocess/network — `python -m pytest tests/ -v` for the full set, or `python -m pytest tests/test_scope_gate.py -v` for one file). The list below highlights major areas, not every file.

- Core workflow: `test_mission.py`, `test_scope_gate.py`, `test_risk_controller.py`, `test_task_queue.py`, `test_outcome_judge.py`, `test_agent_loop.py`
- Persistence/reporting: `test_evidence.py`, `test_finding_verifier.py`, `test_report_generator.py`
- Exploit tooling: `test_attack_modules.py`, `test_mcp_workspace.py`, `test_retry_logic.py`, `test_lateral_tools.py`
- Safety/config: `test_safety_reviewer.py`, `test_config_manager.py`, `test_command_analyzer.py`, `test_audit_redaction.py`, `test_validate_target.py`
- AI/research: `test_goal_engine.py`, `test_cve_lookup.py`, `test_recon_pipeline.py`, `test_semantic_memory.py`, `test_ultrathink.py`
- Menu/swarm: `test_interactive_menu.py`, `test_swarm.py`, `test_swarm_integration.py`, `test_swarm_observability.py`
- OPSEC: `test_opsec_*` (target-aware posture, noise scoring, pacing, UA/DoH).
- Plugins: `test_plugins.py`, `test_plugin_wiring.py`.
- Domain targeting: `test_domain_*.py` (DNS recon, subdomain enumeration, vhost, WHOIS).
- Active Directory: `test_ad_*.py`.
- Detection/AV evasion: `test_detection_*.py`.
- Supply chain: `test_supply_chain_modules.py`.
- Persistence: `test_persistence_modules.py`.
- Autonomous orchestrator: `test_autonomous_*.py` (campaign phases, aggression, retry, chaining).
- Recon enrichers/OSINT/diff: service enrichment, OSINT recon, recon diffing tests.
- Resume flow: `test_resume_*.py`.
- Peer consultation: multi-model advisory consultation tests.
- Reasoning loop: reasoning/reflection loop tests.
- Model telemetry: LLM usage telemetry tests.
- Tool call parsing: tool-call argument parse tests.
