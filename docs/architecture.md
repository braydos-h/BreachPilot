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

There is also a newer exploit, swarm, and WebUI path:

```text
main.py / app.py (WebUI daemon @ :8765, or direct CLI run)
  -> tools.run_service.AssessmentService (transport-neutral prep + execute)
  -> tools.exploit_session.run_exploit_session
  -> tools.exploit_agent (tools/exploit_agent/runner/_impl.py loop) + ExploitPolicy
  -> mcp_exploit_server.py
  -> tools.mcp_tools exploit tool registrations
  -> tools.campaign (AutonomousOrchestrator; facade: tools.autonomous_orchestrator) / tools.swarm
  -> tools.attack_planner + tools.attack_modules
  -> tools.payload_crafter + tools.exploit_mutator
  -> workspace/session/evidence artifacts
```

## Entry Points

### `main.py`

The main launcher. **With no arguments it starts the WebUI daemon** (builds
`webui/dist/` if needed, serves it at `http://127.0.0.1:8765/`, opens a
browser). It also handles direct recon/attack runs, `--menu` (the legacy
questionary terminal menu), doctor, self-test, eval, demo, resume, CTF
autopilot, swarm, and model selection flows. It loads `config.yaml`, starts or connects to MCP transport, routes model calls through the configured provider (`models.provider: ollama` default, or `chatgpt` via the vendored `oauth/` loopback proxy — see [providers.md](providers.md)), and runs recon/attack sessions.

### `app.py` / the WebUI API daemon

`app.py` exposes `create_app`, the FastAPI factory behind `--demon`/`--daemon`/`--web`
(`main._run_daemon`). The daemon serves `/api/v1` (loopback-only, bearer-token)
plus the bundled SPA when `api.serve_webui` is true. See `docs/api/` for the
endpoint reference.

Important functions (`main.py:342-430` `parse_args`; `tools/config_cli.py:30` `load_config`; `tools/mcp_session.py:117` `open_exploit_mcp_session`; `tools/mcp_session.py:609` `start_exploit_http_server`; `tools/exploit_session.py:70` `run_exploit_session`; `tools/safety_review_cli.py` `run_safety_review`; `tools/recon_assessment_cli.py` `run_recon_assessment`; `main.py:566` `async_main`):

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

### MCP Servers (all share `tools/mcp_shared.run_mcp_http_server:1064-1084` hardening)

- `mcp_server.py` (`mcp_server.py:346-349` HTTP `8000`): defensive scanner surface. Tools are scope-aware and focused on nmap, limited terminal commands, and vulnerability intelligence.
- `mcp_exploit_server.py` (`mcp_exploit_server.py:76-184` wiring `create_mcp_server`; `206-208` default `8001`): thin exploit MCP wiring layer. It parses CLI args, loads config, creates shared services and the `FastMCP` instance, registers every tool family via `tools/mcp_tools/registry.py:collect_tools()` (pkgutil auto-discovery of `register_*_tools` + AST decorator validation), and runs the server.
- `mcp_engine_server.py` (`mcp_engine_server.py:200-203` HTTP `8002`): advisory engine server for foreign assistants (`search_skills`, `get_skill`, `cve_lookup`, `list_runs`, `get_run`).
- `tools/mcp_tools/` (27 families — 20 in `tools/mcp_tools/*.py` + 7 in `tools/mcp_tools/modules/*.py`: web, synthesis, planning, hash, campaign, adaptive, etc. — `mcp_exploit_server.py:40-64` imports): terminal/workspace, research, runtime skills, peer models, Metasploit, credentials, payloads, recon, attack modules, sessions, domain, cracking, web_scan, assessment_state, parallel_agents, poc_verifier, replay_simulator, mitre, ad. `registry.py:104-112` `ToolContext` wiring + `registry.py:478-495` shared helpers.

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

## Capability Model, Task Graph, and Failure Taxonomy (Flow A)

The Flow A agent loop is wired to behave like: *understand target state →
build hypotheses → construct a task graph → select capabilities → execute →
interpret → update state → reflect → choose next action → recover from failure
→ validate → produce evidence*. Four new/changed seams carry that loop:

- **Capability metadata** (`tools/attack_modules/base.py`): every module
  declares `requires` / `produces` / `read_only` / `cost` / `phase_hint`.
  `find_producers(kind)` (`registry.py`) resolves which capability supplies a
  missing artifact — the dynamic-composition primitive used for
  prerequisite-recovery scheduling. `applicability_explain(ctx)` returns
  `ApplicabilityReport(score, reasons, penalties)` without disturbing
  `applicability()` scoring. `capability_record()` is the superset metadata
  dict; `to_json()` stays byte-identical.
- **Task graph** (`tools/attack_planner.py`): `AttackStep` gained
  `hypothesis`, `priority`, `status` (pending/running/done/failed/blocked/
  cancelled), `attempt_count`, `failure_class`, `failure_reason`, `capability`,
  `expected_evidence`, `confidence`, `created_from`. `AttackPlan` gained
  `ready_steps()` (open steps whose `depends_on` succeeded, priority-ordered),
  `blocked_steps()` (deps permanently failed/cancelled), `fail_step()`
  (retryable — does not complete), `reset_step()`, `cancel_step()`,
  `graph_summary()`. `to_json`/`from_json` stay tolerant (additive keys).
- **Assessment state** (`tools/assessment_state.py`): per-target
  `AssessmentState` (goal/phase/hypotheses/notes) persisted to
  `plans/<ip>_assessment.json`; `aggregate_state()` merges the plan DAG, the
  newest `recon_result.json`, credential-vault count, and an audit rollup into
  one compact snapshot. LLM-writable through the `record_hypothesis` /
  `update_task` MCP tools, which re-validate the target against the allowlist
  before writing.
- **Failure taxonomy** (`tools/failure_taxonomy.py`): single deterministic
  source for "why failed" (`FailureClass`) and "what to do next"
  (`RecoveryAction` — retry-same / retry-with-params / repair-code /
  create-prerequisite / switch-capability / gather-info / stop). RetryEngine,
  the replan prompts, and the reflection taxonomy express on top of it;
  permanent classes (scope-blocked, false-positive) never retry.

Observability: every outcome-normalized step appends one record to a per-run
`decision_log.jsonl` (`tools/decision_log.py`) — `{round, tool, outcome,
failure_class, success, evidence_refs}` fields only, never raw chain-of-thought.

## Tooling Layer

`tools/` contains the operational helpers:

- AI/model: `model_router.py`, `goal_engine.py`, `goal_suggester.py`, `semantic_memory.py`, `model_telemetry.py`
- Safety/config: `tools/config/` (schema/validator/loader; `config_manager.py` is a re-export shim), `doctor.py`, `safety_reviewer.py`, `validation_utils.py`, `command_analyzer.py`, `opsec.py`, `detection_coverage.py`
- Recon/research: `tools/recon/` (pkg; `recon_pipeline.py` is a deprecated shim), `fast_recon.py`, `cve_lookup.py`, `exploit_search.py`, `web_researcher.py`
- Exploitation: `exploit_agent/` (pkg) + `tools/exploit_agent/runner/_impl.py` (canonical loop), `tools/campaign/` (pkg; `autonomous_orchestrator.py` is a facade shim), `attack_planner.py`, `attack_modules/` (pkg), `payload_crafter.py`, `exploit_mutator.py`, `post_exploit.py`, `metasploit_bridge.py`
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

## ADR-001: Flow B Freeze (Phase 2)

**Status:** Accepted 2026-08-24 (Phase 2 — no behavior change). **Update 2026-08-24 (Phase 3 — CI honesty): physical move completed — canonical is `legacy/` with `DeprecationWarning` shims at root (see `legacy/README.md`).**

**Context:** Two control flows coexist in one checkout (`AGENTS.md` §Non-obvious rules, `CLAUDE.md` §High-Level Architecture). Flow A (`main.py`/`app.py` → `tools/exploit_agent/` / `tools/mcp_tools/` / `tools/swarm/` / `tools/autonomous_orchestrator.py` / `tools/run_service/` / `tools/api/`) is what users run. Flow B (`legacy/cli.py` + `legacy/agent_loop.py` / `db.py` / `legacy/mission.py` / `scope_gate.py` / `legacy/risk_controller.py` / `legacy/tool_router.py` / `legacy/planner.py` / `legacy/executor.py` / `legacy/observer.py` / `legacy/task_queue.py`) is the legacy SQLite research loop and still carries recon safety. `db.py` and `scope_gate.py` stay at root as shared kernel; `legacy/mission.py` is canonical with root `mission.py` shim.

**Decision:**

1. **Flow B is frozen as `legacy` namespace.** New code MUST NOT add features to Flow B files. Root shims (`agent_loop.py`, `executor.py`, `planner.py`, `observer.py`, `task_queue.py`, `cli.py`, `mission.py`, etc.) remain for one release and emit `DeprecationWarning` (`import legacy.agent_loop`), preserving the ~250-file test suite. Canonical location is `legacy/` (physical move completed 2026-08-24).
2. **Shared kernel stays at repo root / `tools/kernel/`.** `db.py`, `mission.py`, `scope_gate.py` remain at the root because both flows import them (see `docs/phase2-audit/architecture-debt.md` §1.2 import maps: `db.py` 62 sites, `scope_gate.py` 7 sites including 2 Flow A consumers for the Path B target lock). They are not moved in Phase 2. `tools/kernel/` (`allowlist.py`, `audit.py`, `workspace.py`) is the shared-kernel extraction for pure functions previously duplicated between `tools/mcp_shared.py` and `tools/mcp_tools/registry.py` / `tools/persistent_session_manager.py`.
3. **Safety files are untouched.** `scope_gate.py`, `safety_reviewer.py`, `agent_loop.py`, `tool_router.py`, `risk_controller.py`, `mission.py`, `db.py` are not edited for Flow A features (invariant `AGENTS.md` §2). Flow B safety stays intact.
4. **Deprecation signal:** Any new import of a Flow B module from Flow A code SHOULD emit a `DeprecationWarning` via `warnings.warn("Flow B is legacy; use tools.kernel / tools/run_service", DeprecationWarning, stacklevel=2)` — advisory only, not a gate.

**Consequences:**

- `tools/kernel/` is the single source for `allowlist` / `audit` / `workspace` pure functions; `tools/mcp_shared.py` and `tools/mcp_tools/registry.py` re-export for backwards compat (`from tools.kernel.allowlist import _allowed_target_list` etc.).
- `tools/persistent_session_manager.py:_is_inside_workspace` duplicate is deleted; it imports from `tools/kernel/workspace.py`.
- No behavior change: `python -m pytest tests/ -q` + `python main.py --doctor` + `python main.py --self-test` remain green.
- Future phases (3–6) may add `collect_tools()` introspection, `tools/recon/` / `tools/campaign/` splits, and `pkgutil.iter_modules` module discovery without touching the frozen surface.

**Alternatives considered:** Physical `legacy/` directory move in Phase 2 (rejected — would touch 12+ import sites and exceed 400-line budget); deleting Flow B outright (rejected — `cli.py` workflow still used deterministically, and tests cover it).
