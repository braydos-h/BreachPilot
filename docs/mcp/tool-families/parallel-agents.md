---
title: "Tool Family: parallel-agents"
sources:
  - tools/mcp_tools/parallel_agents.py
  - tools/swarm/orchestrator.py
  - tools/kernel/allowlist.py
tests:
  - tests/test_swarm_parallel.py
  - tests/test_mcp_tool_registration.py
subsystem: mcp
---

# Tool Family: parallel-agents

- **Registration source:** `tools/mcp_tools/parallel_agents.py:253 register_parallel_agent_tools(mcp, *, ctx)` — auto-discovered but **conditionally registers** only when `swarm.parallel_enabled: true` (`parallel_agents.py:267-270`). When `false` (default), no tools are added; toggling requires MCP server restart.
- **Gate:** all `@audit_tool`; `spawn_subagent` additionally `check_targets_allowlist([target])` before spawning (the allowlist lock is the one safety that parallelizes workers must preserve).

## Tools Exported (3) — conditional

| Tool | Params | Result Shape | Notes |
|------|--------|--------------|-------|
| `spawn_subagent` | `phase: str` (`recon|analysis|exploit|post_exploit`), `target: str`, `objective: str`, `services: list[str]|None`, `known_cves: list[str]|None` | `{"subagent_id":"subagent-phase-8hex","status":"running"}` JSON | Validates phase set else `BLOCKED: phase must be one of ...`; validates target via `validate_target_or_ip` else `BLOCKED: invalid target`; then `check_targets_allowlist([target], config)` — off-list → `BLOCKED: target '...' not in allowlist: ...` even before task creation (the crucial parallel invariant: sub-agent inherits same allowlist). Calls `await _SubagentManager(workspace, config).spawn(...)` which builds `task_dict = {task_id, phase, target, objective, services, known_cves, _result_path: workspace/subagents/<id>.json}` and `asyncio.create_task(_run())` with strong ref; pre-populates `_results[id].status=running` so `list_subagents` shows immediately. `_run` does `asyncio.to_thread(orch.route, task_dict)` — `SwarmOrchestrator.route()` Path B (in-process ReconPipeline/NVD/attack modules, no `ClientSession` needed), writes atomic `tmp→replace` JSON result with `status/output/error/findings/new_tasks/execution_time`, then ` _results[id]=dict` + `_tasks.pop`. |
| `await_subagent` | `subagent_id: str`, `timeout_seconds: int=600` (capped 1..3600) | JSON `status: running|complete|failed|timeout|unknown` + `output/findings/error/partial` | Looks up `_tasks[subagent_id]` + cached `_results`; if `task is None` returns cached or `unknown: no sub-agent with id`. Else `asyncio.wait_for(task, timeout)` — `TimeoutError` → `status: timeout error: sub-agent did not finish within Xs + partial=cached`, other exception → `failed: sub-agent task raised: ...`. On success returns ` _results[subagent_id]` or `unknown: ... finished but no result`. |
| `list_subagents` | — | JSON array `[{subagent_id, phase, target, objective, status, started_at, completed_at?}]` | Non-blocking: returns `list(_results.values())` snapshot without acquiring per-task lock (poll call). |

## `_SubagentManager`

`tools/mcp_tools/parallel_agents.py:56-234` — process-singleton one-per-MCP-server (lazy via `_get_manager`, `parallel_agents.py:243-247`):

- `__init__(workspace, config)`: `_tasks: dict[id, Task]`, `_results: dict[id, dict]`, `_lock = asyncio.Lock()`, `_orchestrator=None` lazy.
- `_get_orchestrator()`: builds `SwarmOrchestrator(context={config, workspace_root=workspace, reports_dir=workspace}, critic_enabled=False, reflection_enabled=False, state_path=workspace/subagent_swarm_state.json)` once.
- `spawn(...)` / `await_result(...)` / `list_live()` as above.

Sub-agent uses Path B (no live MCP `ClientSession`) so it never needs the main loop's session; results are per-subagent JSON under `workspace/subagents/<id>.json`.

## Dependencies

- `tools/swarm/orchestrator.SwarmOrchestrator`, `tools/validation_utils.validate_target_or_ip`, `tools/kernel/allowlist.check_targets_allowlist`, `tools/kernel/workspace._attempt_dir` not used (subagent uses its own `subagents/` dir)
- `tools/mcp_shared._run_with_pgrp_timeout` not used (subagent is in-process route)

## Config

- `swarm.parallel_enabled: bool` (default false) — gate
- `exploit.require_explicit_allowlist`, `exploit.allowed_targets` — target lock at spawn
- `swarm.*` for orchestrator context

## Auditing

- All three `@audit_tool` — records `started`/`completed|blocked` with redacted args; `spawn_subagent` `BLOCKED` from allowlist flips to `blocked`.

## Tests

- `tests/test_swarm_parallel.py` — manager spawn/await/list, allowlist lock, orchestrator path
- `tests/test_mcp_tool_registration.py` — when `swarm.parallel_enabled: true` expects `spawn_subagent`, `await_subagent`, `list_subagents`? (only when enabled; legacy expected set not gated)

## Related Docs

- `docs/swarm.md` — swarm architecture
- `docs/mcp/security.md` — spawn-time allowlist inheritance
