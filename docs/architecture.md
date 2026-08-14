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

The main launcher for interactive menu, recon, attack, doctor, demo, self-test, resume, swarm, and model selection flows. It loads `config.yaml`, starts or connects to MCP transport, routes model calls through the configured provider (`models.provider: ollama` default, or `chatgpt` via the vendored `openai-oauth/` loopback proxy — see [providers.md](providers.md)), and runs recon/attack sessions.

Important functions:

- `load_config`
- `open_exploit_mcp_session`
- `start_exploit_http_server`
- `run_exploit_session`
- `run_safety_review`
- `run_recon_assessment`
- `parse_args`
- `async_main`

Note: `open_exploit_mcp_session` and several of the functions above are re-wrapped/imported from the Flow A CLI orchestration layer — a set of top-level `tools/*.py` modules (`config_cli.py`, `cli_exploit_settings.py`, `exploit_session.py`, `mcp_session.py`, `recon_assessment_cli.py`, `resume_state.py`, `safety_review_cli.py`, `skills_cli.py`, `swarm_bridge.py`) extracted from `main.py` during the cleanup. See "## Flow A CLI Orchestration Layer" below.

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

- AI/model: `model_router.py`, `goal_engine.py`, `goal_suggester.py`, `semantic_memory.py`, `model_telemetry.py`
- Safety/config: `config_manager.py`, `doctor.py`, `safety_reviewer.py`, `validation_utils.py`, `command_analyzer.py`, `opsec.py`, `detection_coverage.py`
- Recon/research: `recon_pipeline.py`, `cve_lookup.py`, `exploit_search.py`, `web_researcher.py`
- Exploitation: `exploit_agent/` (pkg), `attack_planner.py`, `attack_modules/` (pkg), `payload_crafter.py`, `exploit_mutator.py`, `post_exploit.py`, `metasploit_bridge.py`
- State/reporting: `session_manager.py`, `persistent_session_manager.py`, `activity_log.py`, `enhanced_reporting.py`, `experience_store.py`, `credential_store.py`, `attack_memory.py`
- API keys: `api_key_store.py`
- Plugin system: `plugins.py`
- UX: `interactive_menu.py`, `attack_ui.py`, `demo_mode.py`, `logging_setup.py`

## Flow A CLI Orchestration Layer

During the cleanup, orchestration helpers were extracted from `main.py` into top-level `tools/*.py` modules so `main.py` stays a thin entry point. The modules and their responsibilities:

- `mcp_session.py` — `open_exploit_mcp_session`, the MCP boot async context manager (stdio/HTTP transports, 30s boot budget, `BaseExceptionGroup` handling via `tools/exceptions.py`).
- `exploit_session.py` — `run_exploit_session`, single-target orchestration wiring `ScopeGate` + MCP session + `run_exploit_agent`.
- `cli_exploit_settings.py` — `build_cli_exploit_settings`, `_resolve_exploit_permission` (missing-key fallback is `read_only`; `--mode attack` upgrades to `full_access` only when config explicitly grants it).
- `config_cli.py` — `load_config` + API key bootstrap (`bootstrap_startup_api_keys`).
- `recon_assessment_cli.py` — `run_recon_assessment` (OS/scan/CVE-intel → `ReconAssessment`).
- `resume_state.py` — `--resume` state loader (reloads `recon_assessment.json` + chosen goal).
- `safety_review_cli.py` — `run_safety_review` for recon mode.
- `skills_cli.py` — runtime skill overrides + startup selection (`--skills*` flags).
- `swarm_bridge.py` — `SwarmMcpBridge`: bridges the sync swarm `tool_executor` / `ExploitAgent.run` onto the live MCP `ClientSession` (preserves `run_exploit_session`'s single-session invariant).

This mirrors CLAUDE.md's "Flow A CLI orchestration layer" bullet list.

## Plugin System

`tools/plugins.py` manages opt-in filesystem + entry-point plugins that contribute attack modules, MCP tools, skill directories, and config sections. Plugins are trusted Python with full operator-box privileges and are OFF by default (enable via `config plugins.enabled`). A reference plugin lives at `plugins/example_recon_report/`. See `docs/plugin-development.md` for the full guide.

## Swarm Architecture

`tools/swarm/` implements specialist agents with a shared blackboard and battle log:

- `recon_agent.py`: scanning, fingerprinting, attack surface scoring.
- `vuln_agent.py`: CVE/exploit correlation and module matching.
- `exploit_agent.py`: exploit module selection, payload crafting, mutation, handoff.
- `post_exploit_agent.py`: post-exploit checks, credential/loot handling, lateral target generation.
- `critic_agent.py`: pre-execution scope, risk, and policy review.
- `reflection_agent.py`: strategy review and lessons learned.
- `orchestrator.py`: task routing, parallel dispatch, reflection, state persistence.
