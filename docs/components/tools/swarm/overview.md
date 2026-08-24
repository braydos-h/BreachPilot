---
title: Swarm — Overview
package: tools/swarm
files: [orchestrator.py, blackboard.py, base.py, skill_phase.py, bb_compat.py, __init__.py]
---

# Swarm — Overview

Multi-agent execution engine: six specialists via `SwarmOrchestrator`, shared `Blackboard`, critic gate, reflection adaptation. Lives in `tools/swarm/`.

## Package map

| File | Export | Line | Role |
|---|---|---|---|
| `base.py` | `AgentStatus` | 15 | `IDLE/RUNNING/COMPLETE/FAILED/BLOCKED` |
| `base.py` | `AgentResult` | 23 | `agent_type/status/task_id/output/findings/new_tasks/memory_updates/graph_updates` |
| `base.py` | `Agent` | 41 | `agent_type` = class name lowercased minus `Agent`; `run(task,ctx)` abstract |
| `blackboard.py` | `Blackboard` | 48 | `dict` subclass + atomic writes + per-target buckets |
| `bb_compat.py` | `bb_set/append/extend/remove` | 29 | Bridge atomic API to plain dict |
| `orchestrator.py` | `SwarmOrchestrator` | 39 | Route + parallel + critic + reflection + persist |
| `skill_phase.py` | `phase_tags(phase)` | 46 | Phase → skill-tag set; `None` = full set |

## `Blackboard` (`blackboard.py:48`)

`dict` subclass so `bb["k"]`/`bb.get` keep working – they hit `__global__` bucket.

| Method | Line | Semantics |
|---|---|---|
| `get(key, default, *, target)` | 93 | `target=None` → global; else namespaced |
| `set_scalar(key, value, *, target)` | 106 | Atomic overwrite, auto-creates bucket |
| `append_to(key, item, *, target)` | 115 | Atomic append, no dedup |
| `extend_list(key, items, *, target, dedupe=True)` | 133 | Atomic merge, order-preserving dedup |
| `remove_from_list(key, item, *, target)` | 164 | Atomic filter |
| `get_target(target)` | 182 | Copy of one bucket |
| `snapshot()` | 210 | `{__global__:…, "<ip>":…}` |
| `merge_snapshot(snapshot)` | 222 | Restore; scalars overwrite, lists extend |
| `flat()` | 251 | Legacy global view |

Seed keys (`orchestrator.py:118`): `recon_complete`, `vuln_research_complete`, `access_achieved`, `discovered_services`, `vulnerability_hypotheses`, `compromised_hosts`, `credentials_found`, `pivot_targets`, `loot`, `failed_modules`, `attack_surface_score`, `strategy_shift`.

## `SwarmOrchestrator` (`orchestrator.py:39`)

| Member | Line | Description |
|---|---|---|
| `__init__(context, *, agent_registry, max_parallel, critic_enabled, reflection_enabled, event_callback, state_path, exploit_parallel, negotiation_rounds)` | 50 | Builds `Blackboard`, injects into `context["blackboard"]`, builds `skill_selection` |
| `route(task)` | 155 | Sequential: critic pre-check → `agent.run` (unlocked) → blackboard merge → milestone |
| `route_parallel(tasks)` | 283 | Semaphore + milestone gating; recon-first by default |
| `reflect(battle_log, session_state)` | 391 | Runs `ReflectionAgent`, writes `last_reflection`/`strategy_shift` |
| `get_blackboard()` | 429 | `flat()` snapshot |
| `share_blackboard()` | 441 | Live `Blackboard` ref (shared with autonomous orchestrator) |
| `is_milestone_set` / `_await_milestone` / `_mark_milestone` | 480 | `threading.Event` per `(target,phase)` |
| `_negotiate` / `_negotiation_loop` | 653 | Bounded critic↔task loop |
| `_persist_state` / `load_state` | 528 | `swarm_state.json` atomic via `os.replace` |

Phase map `_DEFAULT_AGENT_MAP` (`orchestrator.py:28`): `recon→ReconAgent, analysis/test→VulnAgent, validate/exploit→ExploitAgent, post_exploit→PostExploitAgent, report→ReflectionAgent`.

### `route` flow

1. Resolve `agent_cls = registry[phase]`; unknown → `FAILED`.
2. `agent = _spawn(agent_cls, task_id)` under lock (`:184`).
3. Critic pre-check (unlocked) for `phase not in (recon, report)` when `critic_enabled` (`:190`) via `_negotiate`.
4. `result = agent.run(task, context)` unlocked (`:206`).
5. Append `_results`, emit `agent_{status}`, push to `_battle_log`, trim (`:209-239`).
6. Merge `access_achieved/compromised_hosts/credentials_found/loot` into blackboard (`:241-266`); Bug #18 fixed: lists extend deduped, scalars first-write-wins.
7. `_mark_milestone(target, phase)` even on failure (`:273`); `_persist_state`.
8. Auto `reflect` after `exploit`/`post_exploit` when enabled (`:278`).

### `route_parallel` (Phase 3)

- Recon-first: only `recon`+`analysis` parallelize unless `exploit_parallel`/`force_parallel` (`orchestrator.py:322`).
- `asyncio.Semaphore(max_parallel)` + `run_in_executor(None, route, task)` per task (`:335`).
- `depends_on=[target, phase]` → `_await_milestone(dep_target, dep_phase, timeout=600)` blocking in worker thread (`:347`).
- Results re-ordered to input order (`:365-389`).

### Critic negotiation

`negotiation_rounds=0` (default): one-shot modify then run (`:704`). `N>0`: loop re-reviews modified task until `approve`/`deny`/scope-expansion/repeated hash/deadlock/exhausted (`:712-785`). `_NEGOTIABLE_KEYS` (`orchestrator.py:640`): `risk_level, require_mutation, alternative_tool, rate_limit_seconds, delay_seconds, timeout_seconds, max_retries, mutation_strategy`; out-of-scope keys rejected.

### Persistence

`_persist_state` (`:528`) writes `{agents, blackboard: snapshot(), blackboard_schema:"namespaced", battle_log_tail[-20:], results_count, last_reflection, strategy_shift}` atomically (`tmp` + `os.replace` – Windows-safe). `load_state` restores namespaced or legacy flat shape.

## `skill_phase.py`

| Phase | Tags |
|---|---|
| `recon` | `reconnaissance, nmap, network-security, osint` |
| `vuln` | `vulnerability-scanning, cve, vulnerability-triage, cvss` |
| `exploit` | `exploit-research, exploit, web, api, database, sql-injection` |
| `post_exploit`/`postexploit` | `post-exploit, credential, active-directory, privilege-escalation, lateral` |
| `critic`/`reflection` | `None` = “full active set” (`skill_phase.py:43`) |

## `bb_compat.py`

`bb_set/append/extend/remove` (`bb_compat.py:29-89`) – if `hasattr(bb, "set_scalar")` use atomic path else fallback get-then-set; fallback only on single-threaded test path, not production.

## Config keys

| Key | Effect |
|---|---|
| `swarm.enabled` | Gate |
| `swarm.max_parallel_agents` | `max_parallel` (`agent_loop.py:271`) |
| `swarm.parallel_enabled` | Gates `route_parallel` + `spawn_subagent` |
| `swarm.exploit_parallel` | Exploits also parallelize |
| `swarm.per_phase_concurrency` | Per-phase (not yet wired to orchestrator) |
| `swarm.subagent_timeout_seconds` | `await_subagent` timeout |
| `swarm.negotiation_rounds` | Critic loop bound |
| `autonomous.max_cycles` / `max_pivot_depth` | Campaign loop |
| `long_session.swarm_session_timeout_minutes` | Swarm cap |
| `skills.swarm_inject` / `swarm_phase_hints_only` | Skill hints per agent |

## Tests

| File | Verified | Covers |
|---|---|---|
| `tests/test_swarm.py` | yes | Routing, agent_type, lifecycle, critic, reflection |
| `tests/test_swarm_parallel_phase3.py` | yes | Milestone, `depends_on`, concurrency, per-target buckets, order |
| `tests/test_swarm_mcp_bridge.py` | yes | `SwarmMcpBridge` dispatch/attach |
| `tests/test_swarm_observability.py` | yes | Events + `swarm_state.json` + provider |
| `tests/test_swarm_history_bound.py` | yes | `_trim_history` 500 cap |
| `tests/test_swarm_recon_fix.py` | yes | ReconAgent via `ReconPipeline` |
| `tests/test_blackboard_concurrency.py` | yes | `extend_list` atomicity |
| `tests/test_swarm_negotiation.py` | yes | Negotiation deadlock + scope reject |
| `tests/test_witness_agent.py` | yes | Witness scan (not orchestrator) |
