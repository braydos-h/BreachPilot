# Glossary

Alphabetical reference of domain terms used across this codebase and its
docs. Each entry gives one crisp definition and a `file:line` pointer to
where the term is defined or primarily used.

## Core Concepts

- **Attack module** — A self-contained, registered exploit/recon unit under
  `tools/attack_modules/modules/` with metadata (id, family, risk) and
  applicability scoring. See [attack-modules.md](attack-modules.md) and
  `tools/attack_modules/registry.py`.
- **Flow A** — The modern flow users run: `main.py` / `app.py` →
  `tools/exploit_agent/`, `tools/mcp_tools/`, `tools/swarm/`,
  `tools/autonomous_orchestrator.py`, `tools/run_service/`, `tools/api/`.
- **Flow B** — The legacy, SQLite-backed flow: `cli.py` + root-level
  `agent_loop.py` / `db.py` / `mission.py` / `scope_gate.py` /
  `safety_reviewer.py`. Shares only `db.py` and `mission.py` schemas with
  Flow A (AGENTS.md rule 2).
- **Mission** — The top-level unit of work (a target + goal + scope). Created
  in the DB (`db.py:717 create_mission`), driven by a mission controller
  (`mission.py`), executed task-by-task.
- **Run** — The run-service unit of execution (Flow A / WebUI): one lifecycle
  from create → start → running → complete/failed/cancelled, persisted in
  `api_runtime.db` (`tools/run_service/service.py`, `tools/api/run_manager.py`).
- **Attempt** — One exploit attempt inside a target session, stored under
  `exploit_workspace/<target_ip>/<attempt_id>/` with its own audit JSONL.

## Flows & Lifecycle

- **Agent loop** — The main agent cycle: plan → call tools → observe →
  reflect → repeat (`tools/exploit_agent/loop.py`, Flow B `agent_loop.py:61
  AgentLoop`).
- **Autonomous orchestrator** — Unattended mission driver that starts the MCP
  exploit server, feeds target/goal, and monitors the agent to completion
  (`tools/autonomous_orchestrator.py`, esp. `:1048` primary-target resolution).
- **Recon phase** — Discovery stage; Flow A goes through `tools/mcp_tools/recon.py`,
  enrichers in `tools/recon_enrichers.py`; recon stays `read_only` by design.
- **Exploit session** — An interactive or autonomous session against a
  resolved target IP where exploit MCP tools run under a permission mode.
- **Pivot** — Moving from a foothold to further hosts; gated in Flow B by the
  scope gate and in Flow A by the target allowlist (no separate pivot gate —
  AGENTS.md rule 3).

## Safety

- **Allowlist (target-IP lock)** — THE attack-mode safety boundary: the union
  of `EXPLOIT_TARGET` / `EXPLOIT_TARGET_IP` / `EXPLOIT_TARGET_DOMAIN` /
  `EXPLOIT_DISCOVERED_TARGETS` env vars plus config, matched at tool-call time
  (`tools/mcp_shared.py:494 _allowed_target_list`, `:563`,
  `tools/mcp_tools/terminal.py:64 _target_lock_block`). Matches exact IP,
  domain, `*.wildcard`, CIDR.
- **Permission mode** — `read_only` vs `full_access`; resolved by
  `_resolve_exploit_permission` with a read-only fallback for missing keys
  (`tools/exploit_agent/policy.py:380`). `full_access` auto-approves all
  commands — the allowlist is the lock, not the policy.
- **Scope gate** — Flow B pre-execution check that a target/task is inside
  declared mission scope (`scope_gate.py`). Flow A enforces scope via the
  allowlist instead.
- **Risk controller** — Flow B safety review layer that scores proposed
  actions and blocks high-risk ones outside scope (`risk_controller.py`).
- **Safety reviewer** — Flow B pre-attack gate that reviews recon results
  before exploitation (`safety_reviewer.py`).
- **Exception-group pattern** — anyio raises `BaseExceptionGroup`, not
  `Exception`; code wrapping MCP clients must use `_EXC_GROUP_CATCH` +
  `_is_exception_group` / `_log_nested_exceptions` from `tools/exceptions.py`
  (AGENTS.md rule 1).

## Outcomes & Evidence

- **Outcome** — Judgment of what an action/tool call achieved; classified on
  three axes (execution, evidential, exploit outcome) by `outcome_judge.py`.
- **Outcome truth** — The authoritative, evidence-backed record of an action's
  result (`tools/exploit_agent/outcome_truth.py`), distinct from the model's
  own claim (`outcome_classify.py`).
- **Evidence** — Atomic proof items (command output, files, screenshots)
  saved via `evidence.py EvidenceStore`; the exploit audit JSONL is a
  hash-chained trail under `exploit_workspace/`, promotable into the evidence
  store (`evidence.py:288 promote_exploit_audit`).
- **Finding** — A validated, report-ready conclusion tied to evidence;
  lifecycle created → validated → rejected → report_ready
  (`finding_verifier.py:77 FindingVerifier`).
- **PoE (Proof of Execution)** — Canary-based verification that an exploit
  actually ran, not just that the model claimed it did
  (`tools/verification/poe_verifier.py`).
- **Report** — Generated summary of a mission/run, written under
  `reports/` (`report_generator.py`, `tools/enhanced_reporting.py`).
- **Audit trail** — Append-only JSONL of every tool call with redaction and
  hash chaining: `exploit_audit.jsonl`.

## Swarm

- **Swarm** — Multi-agent mission subsystem (`tools/swarm/`): orchestrator +
  blackboard + specialist agents.
- **Blackboard** — Shared mission state/messages bus agents read/write
  (`tools/swarm/blackboard.py`).
- **Orchestrator** — Swarm mission controller sequencing phases and agents
  (`tools/swarm/orchestrator.py`).
- **Swarm agents** — recon, vuln, exploit, post-exploit, critic, reflection
  (`tools/swarm/agents/`); critic reviews proposed actions for safety, and
  post-exploit handles privesc/loot/pivot.
- **Skill phase** — Swarm phase that injects runtime-skill guidance
  (`tools/swarm/skill_phase.py`).

## MCP & Tools

- **MCP** — Model Context Protocol; this repo runs three servers:
  exploit (`mcp_exploit_server.py`), engine (`mcp_engine_server.py`),
  defensive/legacy (`mcp_server.py`). See [mcp-wiring.md](mcp-wiring.md).
- **Tool family** — A group of MCP tools in one `tools/mcp_tools/<family>.py`
  file (recon, terminal, cracking, metasploit, ad, web_scan, …).
- **`@audit_tool`** — Decorator that registers + audits an exploit MCP tool;
  tools must also be added to the server tool list (`mcp_exploit_server.py`,
  `tools/mcp_tools/registry.py`).
- **`@require_allowlist()`** — Gate for target-touching tools: requires a
  target IP inside the allowlist (`tools/mcp_tools/registry.py`).
- **Tool catalog** — Phase-narrowed list of tools the agent may call
  (`tools/exploit_agent/tool_catalog.py`).

## Skills & Research

- **Skill** — Advisory `SKILL.md` (frontmatter + markdown) selected
  semantically; prompt context only, never execution authority
  (`tools/skill_registry.py:362 render_skill_context`, [skills.md](skills.md),
  [skill-authoring.md](skill-authoring.md)).
- **Recon enricher** — Post-scan parser that adds structured info (banner,
  TLS, SMTP, DB, HTTP spider) (`tools/recon_enrichers.py`).
- **Research assistant** — Read-only sidecar agent for web/CVE research with a
  JSON contract (`tools/exploit_agent/research_assistant.py:46`).
- **CVE lookup** — NVD API 2.0 client with LRU cache, rate limiting, circuit
  breaker, EPSS/KEV opt-in enrichment (`tools/cve_lookup.py`).

## UI & API

- **Run service** — Backend service managing runs, providers, events, and
  decisions (`tools/run_service/`); persisted in `api_runtime.db`.
- **Decision broker / event broker** — Route approval decisions and runtime
  events between agents, server, and WebUI over WS/SSE
  (`tools/api/decision_broker.py`, `tools/api/event_broker.py`).
- **Session titler** — Auto-generates human titles for runs
  (`tools/api/session_titler.py`).
- **WebUI** — Bundled React/Vite SPA under `webui/` (first `--web` run builds
  `webui/dist/`); docs in [webui.md](webui.md), API in [api.md](api.md).

## Runtime & Ops

- **`--doctor`** — Environment check (Python/nmap/Ollama/config)
  (`tools/doctor.py`).
- **`--self-test`** — Safe localhost smoke test (`tools/self_test.py`).
- **Demo mode** — Scripted safe demonstration runs (`tools/demo_mode.py`).
- **Eval harness / benchmark** — Offline evaluation: legacy self-scored
  `tools/eval_harness.py` vs oracle-backed `tools/eval_benchmark.py`
  (verified/false-positive rates, risk ratio + CI). See
  [evaluation.md](evaluation.md).
- **Detection coverage** — Scoring of how visible/covered an attack path is
  to detection (`tools/detection_coverage.py`, `attack_modules/modules/detection.py`).
- **OPSEC** — Advisory briefing injected into prompts to reduce detection
  noise (`tools/exploit_agent/prompt.py:282 build_opsec_briefing`).
- **Workspace dirs** — Gitignored runtime state: `reports/`,
  `exploit_workspace/`, `research_workspace/`, `swarm_workspace/`,
  `webui/dist/`.
- **`opencode.json`** — Editor-local config for the opencode editor's own
  model provider, gitignored; NOT application config (AGENTS.md rule 5).
  App config lives in `config.yaml` — see
  [config-reference.md](config-reference.md).
