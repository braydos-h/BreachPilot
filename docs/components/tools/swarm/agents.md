---
title: Swarm — Agents (all 7)
package: tools/swarm/agents
files: [recon_agent.py, vuln_agent.py, exploit_agent.py, post_exploit_agent.py, critic_agent.py, reflection_agent.py, witness_agent.py]
---

# Swarm — Agents (all 7)

Six swarm-routed agents (`Agent` subclasses) + `WitnessAgent` (advisory side watcher, not routed).

## Common contract (`tools/swarm/base.py`)

| Symbol | Line | Value |
|---|---|---|
| `AgentStatus` | 15 | `IDLE/RUNNING/COMPLETE/FAILED/BLOCKED` |
| `AgentResult` | 23 | `agent_type, status, task_id, output, error, execution_time, evidence_refs, new_tasks, memory_updates, graph_updates, findings, reflections` |
| `Agent.agent_type` | 51 | `ClassName.replace("Agent","").lower()` (so `PostExploitAgent→postexploit`) |
| `Agent.run(task, context)` | 60 | Abstract; returns `AgentResult` |
| `Agent._run_coro` | `recon_agent.py:23` | `asyncio.run` vs. thread+own loop if loop already running |

All agents read `target`, `task_id`, `config`, `blackboard`, `model_client`, `skill_selection` from `context`.

---

### 1. ReconAgent (`recon_agent.py`)

| Item | Detail |
|---|---|
| Class | `ReconAgent` | 
| `agent_type` | `recon` |
| `SYSTEM_PROMPT` | `_RECON_SYSTEM_PROMPT` at `recon_agent.py:94` |
| Entry | `run(self, task, context)` at `recon_agent.py:166` |
| Verified methods | `_run_coro`, `_fingerprint_tech`, `_categorize_tech` |

Stages (`recon_agent.py:192-363`):

1. Build `ReconConfig.from_config(config, aggression_level=stealth→stealth else normal)` + `ReconPipeline(recon_cfg)` + `_run_coro(pipeline.recon_host(target))`.
2. Enrich services with `_SERVICE_RISK_SCORES` (`recon_agent.py:67`: smb 90, rdp 85, ssh 70, http 60, …) + `_TECH_SIGNATURES` banner fingerprint.
3. Attack surface score = mean risk.
4. Generate downstream `analysis` tasks for `risk≥70` + web services, each with `depends_on=[target,"recon"]`.
5. Determine `recommended_next_phases` + write `recon_complete/discovered_services/target_os/attack_surface_score/technologies` via `bb_set`.

Tech DB ` _TECH_SIGNATURES` at `recon_agent.py:46` (Apache, Nginx, IIS, Spring, Cloudflare, …). Risk table `_SERVICE_RISK_SCORES` at `:67`.

Tests: `tests/test_swarm.py`, `tests/test_swarm_recon_fix.py`, `tests/test_recon_pipeline.py`.

---

### 2. VulnAgent (`vuln_agent.py`)

| Item | Detail |
|---|---|
| Class | `VulnAgent` |
| `agent_type` | `vuln` |
| Phases | `analysis`, `test` |
| `SYSTEM_PROMPT` | `_VULN_SYSTEM_PROMPT` at `vuln_agent.py:24` |
| Entry | `run` at `vuln_agent.py:102` |
| Verified | `_llm_analyze` |

Flow (`vuln_agent.py:130-357`):

- Pull `services` from task or `blackboard.discovered_services`.
- Per service: `NVDClient.search_sync(query)` + `ExploitSearch.search_exploit_db` + `search_web_exploit`, with per-service reset of `cves/cve_results/svc_exploits` (ponytail fix for stale-service leak).
- `ModuleContext(target_ip, target_os, services, cves=[])` + `find_modules(ctx, experience_store=ctx["experience"])` experience-blended ranking (confidence `0.5` neutral).
- Confidence `0.9/0.7/0.5/0.3` based on `has_exploit`+`has_critical_cve` (per-service now).
- `matched_modules[:5]` + `prerequisite = get_module(top).requires`.
- If `confidence≥0.7` emit `phase=exploit` task with `depends_on=[target,"analysis"]`.
- Optional `model_client` → `_llm_analyze` refines `recommended_exploit_path` (skills via `append_phase_skill_hints`, prompt `skill_selection="vuln"`).
- Write `vuln_research_complete/vulnerability_hypotheses/recommended_exploit_path/matched_attack_modules` via `bb_set`.

Tests: `tests/test_swarm.py`, `tests/test_version_aware_ranking.py`, `tests/test_cve_lookup.py`.

---

### 3. ExploitAgent (`agents/exploit_agent.py`)

| Item | Detail |
|---|---|
| Class | `ExploitAgent` |
| `agent_type` | `exploit` |
| Phases | `exploit`, `validate` |
| `SYSTEM_PROMPT` | `_EXPLOIT_SYSTEM_PROMPT` at `exploit_agent.py:35` |
| Entry | `run` at `exploit_agent.py:128` |
| Verified | per-attempt UUID workspace, `share_experience` wiring |

Flow (`exploit_agent.py:128-478`):

- Reads `vulnerability_hypotheses/matched_attack_modules/discovered_services/target_os` from blackboard.
- Builds `ExploitSettings` with per-attempt `workspace_root = base/<target>/<attempt_id>` (`:189`), attacker-OS-aware `build_skill_selection_for_context` advisory hints (`:210`).
- **Path A** (`client && session && tools_schemas`): `run_exploit_agent(...)` on `context["main_loop"]` via `run_coroutine_threadsafe` else `asyncio.run`; threads `scope_gate`, `experience`, `semantic_memory`, `skill_*`. Success only when `outcome_summary` shows `compromises: N≠0` or `cred dumps: N≠0` (`:315` verified flag).
- **Path B** (no session): try `matched_attack_modules` via `get_module(...).run(ModuleContext)`, fallback `PayloadCrafter.generate`; `script_generated` NOT counted as compromise.
- On success: `bb_set access_achieved`, `bb_append compromised_hosts`, emit `post_exploit` task + finding; on failure: `bb_set exploit_attempted/last_exploit_error`.
- ScopeGate threaded into `ExploitPolicy` twice (policy + loop arg).

Tests: `tests/test_swarm.py`, `tests/test_swarm_parallel_phase3.py`, `tests/test_exploit_scope_gate.py`.

---

### 4. PostExploitAgent (`post_exploit_agent.py`)

| Item | Detail |
|---|---|
| Class | `PostExploitAgent` |
| `agent_type` | `postexploit` (no underscore) |
| `SYSTEM_PROMPT` | `_POST_EXPLOIT_SYSTEM_PROMPT` at `post_exploit_agent.py:25` |
| Entry | `run` at `post_exploit_agent.py:68` |

Flow (`post_exploit_agent.py:68-243`):

- Per-attempt loot dir `<base>/<target>/<attempt_id>/loot` (`:102`).
- `PostExploitRunner(str(workspace))` + `CredentialStore`/`LootStore` on `workspace/loot` (`:112`).
- `runner.process_result("post_exploit", raw_output, target)` → `credentials_found`/`loot` + persist; enumeration summary (`sudo -l`, SUID, cron, …) even on empty raw_output.
- Generates pivot `phase=exploit` tasks for every other `compromised_hosts` entry.
- Writes `post_exploit_complete`, `privilege_level`, `credentials_found`/`loot` (via `bb_extend` deduped), `pivot_targets` (`bb_set`).

Tests: `tests/test_swarm.py`, `tests/test_post_exploit.py`.

---

### 5. CriticAgent (`critic_agent.py`)

| Item | Detail |
|---|---|
| Class | `CriticAgent` |
| `agent_type` | `critic` (never in `_DEFAULT_AGENT_MAP`; invoked pre-check) |
| `SYSTEM_PROMPT` | `_CRITIC_SYSTEM_PROMPT` at `critic_agent.py:20` |
| Entry | `run` at `critic_agent.py:90` |
| Verified | `_llm_review` |

Layers in order (`critic_agent.py:106-171`):

1. ScopeGate `check_scope(asset,target,phase,tool,risk)` → `deny` if `!allowed`.
2. RiskController `can_proceed()` → `deny` if budget exhausted.
3. `forbidden_actions` (mission) contains `phase` → `deny`.
4. Risk profile gating: `high` in non-`high_authorized_testing` → `modify {risk_level:medium}`.
5. Repeat failure: `proposed_module in blackboard.failed_modules` → `modify {require_mutation:true}`.
6. LLM deep review (only if `model_client` and still `approve`): scope context + mission/program + budget; decision cleansed to `approve/deny/modify`, unknown→`modify`; parse failure → fail-safe `modify` requiring confirmation (`critic_agent.py:211-301`).

Orchestrator `_negotiate` promotes decisions: `deny`→`BLOCKED` result, `modify`→`task.update(filtered_modifications)` bounded loop.

Tests: `tests/test_swarm.py`, `tests/test_swarm_negotiation.py`, `tests/test_swarm_observability.py`.

---

### 6. ReflectionAgent (`reflection_agent.py`)

| Item | Detail |
|---|---|
| Class | `ReflectionAgent` |
| `agent_type` | `reflection` |
| Trigger | `report` phase + auto after `exploit`/`post_exploit` (`orchestrator.py:278`) |
| Entry | `run` at `reflection_agent.py:157` |
| Verified | `_llm_reflect`, `_coerce_fc`, `_known_failure_classes` |

Stages (`reflection_agent.py:124-326`):

- Heuristic: successes/failures from `battle_log`, failure-tool counts, refused/timeout patterns, success-tool pattern.
- Root cause → `why`; hypothesis (`partial_success` > successes > none); strategy ladder: failures >3×successes → `MAJOR PIVOT` (0.9), >2×→`PIVOT` (0.7), successes only → `ACCELERATE` (0.9), mixed → 0.6.
- LLM `_llm_reflect` when `model_client`: injects known `FailureClass→REFLECTION_LABEL` map (`_FAILURE_CLASS_TO_REFLECTION_LABEL` at `:30`) if any entry carries `failure_class`.
- Blackboard: `bb_set last_reflection/strategy_shift`, `bb_extend failed_modules`, `bb_remove` succeeded tools, `bb_extend successful_modules`.
- Cross-mission `semantic_memory.store_lesson(action_type="reflection:strategy_shift")` distinct from exploit learning.
- Per-skill outcomes via `tools/skill_feedback.record_skill_outcome` when `skill_selection`+`experience` present.

Tests: `tests/test_swarm.py`, `tests/test_swarm_history_bound.py`, `tests/test_reflection_evidential_bridge.py`.

---

### 7. WitnessAgent (`witness_agent.py`) — not `Agent` subclass

Advisory audit-stream watcher running as side task, not routed by orchestrator (docstring `witness_agent.py:15`, class note `:334`).

**Wiring status: started by the run lifecycle when `witness.enabled` is true.**
`tools/run_service/execute.py` (the transport-neutral lifecycle serving BOTH
the CLI and API transports) spawns a per-run WitnessAgent side task
(`Callables.witness_agent_factory` seam): it polls
`reports/<run_id>/activity.jsonl`, registers the per-attempt
`exploit_audit.jsonl` (session result `audit_path`) at teardown for a final
scan, and writes flags to the witness log +, when
`escalate_to_event_broker` is true, `witness_flag` events through the
transport's event sink. Not routed by the orchestrator (docstring
`witness_agent.py:15`, class note `:334`). It is **detection/auditing only**:
it flags anomalies; it never blocks, modifies, or kills a run, and its
failure never propagates into the run's result path. The WebUI surfaces
flags via `GET /api/v1/runs/{run_id}/witness`, which reads the process-global
log file (404 when absent). Standalone use: `python -m
tools.swarm.agents.witness_agent`.

| Symbol | Line | Description |
|---|---|---|
| `WitnessAgent` | 333 | Poll loop over audit paths |
| `WitnessConfig` | 94 | `from_config` reads `witness.*` |
| `WitnessFlag` | 74 | `{signal, severity, message, record, timestamp}` |
| `WitnessContext` | 158 | `allowed_targets` + sliding window + `highest_permission` |
| `_DETECTORS` | 317 | 5 detectors ordered |

Detectors (`:198-312`): `allowlist_breach (critical)`, `poc_no_network_isolation (high)`, `permission_escalation (high)`, `prompt_injection_pattern (medium)`, `dos_drift (medium)`. Rate-capped per signal (`max_flags_per_signal_per_minute`) and windowed for DoS (`dos_failure_window_seconds/threshold`).

API: `WitnessAgent(config, audit_paths, event_callback, clock)` (`:346`), `scan_once() → list[WitnessFlag]` (`:376`, never raises, `witness_error` on exception), `stop()` (`:420`), `seen_count`. `demo()` + `_synthetic_stream()` self-check (`:512`).

Config (`witness` at `config.yaml:187`): `enabled: true`, `log_path: reports/witness.jsonl`, `poll_interval_seconds:5`, `escalate_to_event_broker:true`, `max_flags_per_signal_per_minute:10`, etc.

Tests: `tests/test_witness_agent.py` (verified present).
