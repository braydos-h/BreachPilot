# Architecture

## System Shape

The codebase is organized around an authorized security research workflow. Most modules are plain Python services backed by SQLite and filesystem evidence, with CLI and MCP entry points on top.

```text
User
  -> main.py / cli.py / MCP client
  -> MissionController
  -> ScopeGate + RiskController
  -> PlannerAgent + TaskQueue
  -> ExecutorAgent + ToolRouter + MCP/tools
  -> ObserverAgent
  -> OutcomeJudge + HypothesisRepository
  -> MemoryManager + TargetGraph + EvidenceStore
  -> FindingVerifier
  -> ReportGenerator
```

There is also a newer exploit and swarm path:

```text
main.py
  -> tools.exploit_agent.ExploitPolicy
  -> mcp_exploit_server.py
  -> tools.mcp_tools exploit tool registrations
  -> tools.autonomous_orchestrator / tools.swarm
  -> tools.attack_planner + tools.attack_modules
  -> tools.payload_crafter + tools.exploit_mutator
  -> workspace/session/evidence artifacts
```

## Entry Points

### `main.py`

The main launcher for interactive menu, recon, attack, doctor, demo, self-test, resume, swarm, and model selection flows. It loads `config.yaml`, starts or connects to MCP transport, routes model calls through Ollama, and runs recon/attack sessions.

Important functions:

- `load_config`
- `open_exploit_mcp_session`
- `start_exploit_http_server`
- `run_exploit_session`
- `run_safety_review`
- `run_recon_assessment`
- `parse_args`
- `async_main`

### `cli.py`

The workflow CLI over the mission database. It is useful for deterministic local operations without the full AI loop.

Commands:

- `init-mission`
- `add-scope`
- `list-scope`
- `next-task`
- `list-tasks`
- `run-task`
- `summarize-target`
- `list-findings`
- `validate-finding`
- `generate-report`
- `status`

### MCP Servers

- `mcp_server.py`: defensive scanner surface. Tools are scope-aware and focused on nmap, limited terminal commands, and vulnerability intelligence.
- `mcp_exploit_server.py`: thin exploit MCP wiring layer. It parses CLI args, loads config, creates shared services and the `FastMCP` instance, registers tool categories from `tools/mcp_tools/`, and runs the server.
- `tools/mcp_tools/`: focused exploit MCP tool registration modules for terminal/workspace access, research, runtime skills, peer models, Metasploit, credentials, payloads, recon, attack modules, and sessions. `registry.py` holds MCP-local shared helper state and dependency bundling.

The exploit server intentionally says its tools are gated at the policy layer, not in the server itself. Treat `tools.exploit_agent.ExploitPolicy` as the control point for tool approval. Tool modules must still keep their existing defense-in-depth gates such as allowlist checks, audit logging, command preflight, workspace containment, credential redaction, and research API-key gating.

## Persistence

### SQLite

`db.py` owns the SQLite schema and migrations. It stores:

- missions
- scope rules
- tasks
- hypotheses and materially distinct check history
- outcome assessments
- observations
- graph nodes and edges
- evidence metadata
- findings
- audit logs
- memories

IDs use prefix-style identifiers such as mission/task/finding IDs. JSON fields are stored as text.

### Filesystem

`evidence.py` writes raw evidence files and stores metadata in SQLite. Runtime directories include:

- `reports/`
- `exploit_workspace/`
- `research_workspace/`
- `test_workspace*`

### Session State

Long-running exploit and campaign state is handled by:

- `tools/session_manager.py`
- `tools/persistent_session_manager.py`
- `tools/autonomous_orchestrator.py`
- `tools/swarm/orchestrator.py`

## Core Domain Services

- `mission.py`: mission normalization, validation, status, workspace initialization.
- `scope_gate.py`: allowed/disallowed asset checks, forbidden actions, third-party detection, rate limits.
- `risk_controller.py`: action risk assessment, command/task/session budgets, human approval checks.
- `planner.py`: turns mission and memory state into concrete tasks.
- `task_queue.py`: task lifecycle, phase normalization, priority scoring, deduplication.
- `executor.py`: executes approved tasks through `ToolRouter` and summarizes results.
- `observer.py`: turns tool output into structured observations and follow-up signals.
- `outcome_judge.py`: deterministically separates execution outcome from
  evidential outcome, evaluates task criteria/stop conditions, persists
  hypothesis state and assessments, and rejects terminal or repeated paths.
- `memory.py`: working, episodic, semantic, target, hypothesis, dead-end, and finding-note memory.
- `target_graph.py`: attack surface graph of assets, services, endpoints, evidence, and findings.
- `finding_verifier.py`: finding lifecycle and validation scoring.
- `report_generator.py`: Markdown report generation.

## Hypothesis and Outcome Boundary

`ExecutionResult.success` describes whether a tool invocation completed. It is
not a finding or investigation result. After every executed check,
`ObserverAgent` produces structured fields and `OutcomeJudge` evaluates those
fields against the task's `success_criteria` and `stop_conditions`. Raw output
words such as `success` are not proof.

The persisted hypothesis ledger owns statement/target identity, status,
confidence, evidence references, attempt counts, independent check history, and
timestamps. Confirmed, refuted, and exhausted states are terminal for planning.
Inconclusive states can continue only through a new check fingerprint. Outcome
judgment may stop or redirect work, but it never bypasses scope, risk,
permission, approval, target-lock, or tool-routing controls.

## Tooling Layer

`tools/` contains the operational helpers:

- AI/model: `model_router.py`, `goal_engine.py`, `goal_suggester.py`, `semantic_memory.py`
- Safety/config: `config_manager.py`, `doctor.py`, `safety_reviewer.py`, `validation_utils.py`, `command_analyzer.py`
- Recon/research: `recon_pipeline.py`, `cve_lookup.py`, `exploit_search.py`, `web_researcher.py`
- Exploitation: `exploit_agent/` (pkg), `attack_planner.py`, `attack_modules/` (pkg), `payload_crafter.py`, `exploit_mutator.py`, `post_exploit.py`, `metasploit_bridge.py`
- State/reporting: `session_manager.py`, `persistent_session_manager.py`, `activity_log.py`, `enhanced_reporting.py`, `experience_store.py`, `credential_store.py`
- UX: `interactive_menu.py`, `attack_ui.py`, `demo_mode.py`, `logging_setup.py`

## Swarm Architecture

`tools/swarm/` implements specialist agents with a shared blackboard and battle log:

- `recon_agent.py`: scanning, fingerprinting, attack surface scoring.
- `vuln_agent.py`: CVE/exploit correlation and module matching.
- `exploit_agent.py`: exploit module selection, payload crafting, mutation, handoff.
- `post_exploit_agent.py`: post-exploit checks, credential/loot handling, lateral target generation.
- `critic_agent.py`: pre-execution scope, risk, and policy review.
- `reflection_agent.py`: strategy review and lessons learned.
- `orchestrator.py`: task routing, parallel dispatch, reflection, state persistence.
