---
title: executor.py + tool_router.py — Scope-Gated Tool Execution
sources:
  - executor.py
  - tool_router.py
tests:
  - tests/test_executor.py
  - tests/test_tool_router_approval.py
  - tests/test_scope_gate.py
  - tests/test_risk_controller.py
subsystem: flow-b
status: maintained
---

## Purpose

Execute approved tasks and nothing else. `ExecutorAgent` picks the first `allowed_tools` entry, builds arguments, calls `ToolRouter.route`; `ToolRouter` is the mandatory chokepoint that enforces scope → risk → human-approval → execution → evidence capture → audit. The only way `AgentLoop` or `cli run-task` reaches the instrumented `tool_executor` is through this pair.

## Source Files

| File | Lines | Role |
|------|-------|------|
| `executor.py` | 209 | `ExecutorAgent` + `ExecutionPlan` + `ExecutionResult` |
| `tool_router.py` | 261 | `ToolRouter` + `RoutedToolResult` — 6-step pipeline |

## Responsibilities

### `executor.py`

- Hold static max retries (unused after `planner.plan_retry_with_modifications` took over) (`executor.py:58` `ExecutorAgent.__init__` with `max_retries_per_task=2`).
- Implement `execute(task)` (`executor.py:72`): validate `task_id`/`target`/`phase`, pick `allowed_tools[0]`, build args via `_build_args` (`executor.py:162`), construct `ExecutionPlan` with `expected_observation = objective[:200]`, call `ToolRouter.route(...)`, measure `execution_time`, and synthesize `ExecutionResult` (success = `allowed && output non-empty && "error" not in output[:200]`; `expected_observation_matched` by keyword overlap).
- Bridge tool-specific defaults in `_build_args`: explicit `tool_args` dict wins; else `check_os`/`nmap`/`scan` → `{target_ip: target}`, `http/web` → `{target_ip, port:80}`, `cve` → `{query: objective}`, `smb/ssh/rdp/ldap` → `{target_ip}`, `dir/enum` → `{target_ip, port}`, `terminal` → `{command}`, `python_file` → `{target_ip, filename?, code?}`, `msf` → `{target_ip, module:"auxiliary/scanner/portscan/tcp"}`, always falls back to `target_ip` or `target`.

### `tool_router.py`

- Hold references to `ScopeGate`, `RiskController`, `EvidenceStore`, `tool_executor: Callable[[str,dict],str]`, `DatabaseManager`, `mission_id`, optional `human_approval_fn` (`tool_router.py:66`).
- Implement 6-step `route(task_id, tool_name, tool_args, target, risk_level="low", action_type="recon", hypothesis="")` (`tool_router.py:87`):
  1. `ScopeGate.check_scope(asset=target, action_type, tool_name, risk_level)`
  2. `RiskController.assess_action(action_type, tool_name, f"{tool_name}({json args})", target, risk_level)`
  3. Human approval if `risk.requires_human_approval || scope.requires_human_approval` (missing handler → block; denial → block, `tool_router.py:149`)
  4. `tool_executor(tool_name, tool_args)` (any exception → `allowed=False` with `TOOL_EXECUTION_ERROR`, `tool_router.py:181`)
  5. `RiskController.record_execution` + `EvidenceStore.save("raw_output", raw, metadata, task_id, target)` + `summarizer.summarize_tool_output`
  6. `RoutedToolResult` with `execution_time_seconds`, `evidence_refs=[evidence_id]`, scope/risk dicts.
- Log blocks (`tool_router.py:252` `_log_block` → `audit_logs event_type="tool_blocked"`) and successful audits (`tool_router.py:242` `tool_{tool_name}`).

## Public Interfaces

### `executor.py`

| Symbol | Location | Signature |
|--------|----------|-----------|
| `ExecutionPlan` | `executor.py:26` | `dataclass(task_id, hypothesis, planned_action, tool, tool_args, why_allowed, expected_observation, risk_level, target)` |
| `ExecutionResult` | `executor.py:41` | `dataclass(task_id, success, output_summary, evidence_refs, tool_name, target, expected_observation_matched, error, execution_time, scope_gate_passed, risk_gate_passed, raw_output)` |
| `ExecutorAgent` | `executor.py:58` | `(tool_router, max_retries_per_task=2)` |
| `ExecutorAgent.execute` | `executor.py:72` | `(task: dict) -> ExecutionResult` |
| `ExecutorAgent._build_args` | `executor.py:162` | `static (tool, target, task) -> dict` |

### `tool_router.py`

| Symbol | Location | Signature |
|--------|----------|-----------|
| `RoutedToolResult` | `tool_router.py:29` | `dataclass(allowed, reason, output, output_summary, tool_name, target, task_id, evidence_refs, scope_check?, risk_assessment?, execution_time_seconds, blocked_reason, requires_human)` |
| `ToolRouter` | `tool_router.py:47` | `(scope_gate, risk_controller, evidence_store, tool_executor, db, mission_id, human_approval_fn?)` |
| `ToolRouter.route` | `tool_router.py:87` | `(task_id, tool_name, tool_args, target, risk_level="low", action_type="recon", hypothesis="") -> RoutedToolResult` |
| `ToolRouter._log_audit` | `tool_router.py:242` | `(task_id, event_type, message)` |
| `ToolRouter._log_block` | `tool_router.py:252` | `(task_id, tool_name, gate, reason)` |

## Inputs/Outputs

| Input | Notes |
|-------|-------|
| `task` dict | `task_id`, `target`, `phase→action_type`, `objective`, `hypothesis`, `allowed_tools[0]`, `risk_level`, `tool_args?` |
| `tool_executor` | `fn(tool_name, args)->str` — mocked in tests, stub in `cli.run-task` |
| `human_approval_fn` | `fn(tool_name, {target,task_id,risk_level,tool_args,hypothesis,risk_warnings})->bool` |

| Output | Notes |
|--------|-------|
| `RoutedToolResult` | `allowed` false → `output=""`, `blocked_reason` populated, `evidence_refs=[]` |
| `ExecutionResult` | Wraps routed result + `expected_observation_matched` flag |
| Side effects | `audit_logs` row per attempt (success or block), `evidence` row+file on success, `RiskController` counter increment |

## State/Persistence

- Stateless execution; only bookkeeping is `RiskController._commands_executed` increment after success (`tool_router.py:199`) and the `audit_logs`/`evidence` DB rows.
- `evidence.type="raw_output"` files under `evidence/raw_output/<E-...>.txt` written by `EvidenceStore.save` before summarization.

## Configuration

- No config of its own; behavior inherits from the injected `ScopeGate` and `RiskController` (see `docs/components/flow-b/scope-risk.md`).

## Dependencies

- `executor.py` → `tool_router.ToolRouter`
- `tool_router.py` → `db.DatabaseManager`, `evidence.EvidenceStore`, `risk_controller.RiskController`, `scope_gate.ScopeGate`, `summarizer.summarize_tool_output`, `time`, `json`, `dataclasses`
- Callers: `agent_loop.AgentLoop` (primary), `cli.cmd_run_task` (with stub executor)

## Used By

- `agent_loop.run` — `ExecutorAgent.execute(task)` for the non-swarm path; swarm path still routes via `SwarmOrchestrator` which in turn uses its own `ToolRouter`-like gating.
- `cli.cmd_run_task` — constructs `ToolRouter` + `ExecutorAgent` with a stub that returns `"[tool] {name}..."`.

## Control Flow

```mermaid
flowchart TD
    A[task -> ExecutorAgent.execute] --> B[_build_args -> ExecutionPlan]
    B --> C[ToolRouter.route]
    C --> D{ScopeGate.check_scope?}
    D -->|deny| E[log_block scope -> return allowed=false]
    D -->|allow| F{RiskController.assess_action?}
    F -->|deny| G[log_block risk -> return allowed=false]
    F -->|allow| H{needs human?\nscope.requires_human || risk.requires_human}
    H -->|yes && no handler| I[block human_missing]
    H -->|yes && denied| J[block human_denied]
    H -->|no or approved| K[tool_executor -> raw_output]
    K -->|exception| L[return TOOL_EXECUTION_ERROR]
    K -->|ok| M[record_execution + EvidenceStore.save + summarize_tool_output]
    M --> N[RoutedToolResult allowed=true]
    N --> O[ExecutionResult success/expected_matched]
```

## Failure Modes

| Mode | Result |
|------|--------|
| `allowed_tools` empty | `ExecutionResult(success=False, error="No allowed_tools")` — no gate reached |
| Scope deny | `RoutedToolResult.allowed=False, blocked_reason=reason, scope_check={allowed:false, reason, matched_rule}`; `ExecutorAgent` maps to `success=False`, `scope_gate_passed=False` |
| Risk deny (destructive/budget/dangerous-tool/category) | Same but `risk_assessment` populated; `risk_gate_passed=False` |
| Human approval required but `human_approval_fn is None` | `allowed=False, requires_human=True, blocked_reason="Human approval required but no approval handler"` |
| Human denied | `allowed=False, requires_human=True, blocked_reason="Human approval denied."` |
| `tool_executor` raises | `allowed=False, blocked_reason="TOOL_EXECUTION_ERROR: {exc}"` (no evidence, no counter increment) |
| Empty or `"error"`-prefixed output | `ExecutionResult.success=False` even when `allowed=True` (the `bool(output) && "error" not in output[:200]` gate) |

## Invariants

- No execution path bypasses `ToolRouter.route`; the only entry is via this pair.
- `ExecutionPlan` is informational; `ToolRouter` re-derives scope/risk inputs independently from the passed `phase`/`target`/`risk_level`.
- `EvidenceStore.save` always precedes summarization so raw evidence is never lost even if summarization fails.
- `ToolRouter.route` increments `RiskController` only on successful execution (after `tool_executor` returns, before summarizing).

## Security Boundaries

- This is the enforcement surface for `ScopeGate` + `RiskController` (see `docs/components/flow-b/scope-risk.md`). Do not add a second direct `tool_executor` call site.
- `human_approval_fn` must be supplied for any `high` risk when `risk_profile != "high_authorized_testing"` else those tasks stall in `needs_approval`.

## Tests

| Test file | Covers |
|-----------|--------|
| `tests/test_executor.py` | `execute` with allowed/forbidden/empty tools, `_build_args` by tool family, `expected_observation_matched` |
| `tests/test_tool_router_approval.py` | Human-approval branching, missing/denied/approved paths |
| `tests/test_scope_gate.py` | Indirect: routed scope blocks |
| `tests/test_risk_controller.py` | Indirect: routed risk blocks |

Run: `python -m pytest tests/test_executor.py tests/test_tool_router_approval.py -v`

## Common Changes

| Change | Where |
|--------|-------|
| Support a new tool family default | `executor.py:162` `_build_args` branch |
| Change success heuristic | `executor.py:146` `bool(output) && "error" not in ...` predicate |
| Add a routing step | `tool_router.py:87` `route` method (keep scope→risk→approval→exec→evidence→audit order) |

## Update This Document When

- `ExecutionResult` / `RoutedToolResult` fields or `ExecutionPlan` contents change.
- `route` pipeline order or audit evidence/counter side effects change.
- `_build_args` adds/removes a tool family default.

## Related Documentation

- `scope_gate.py` + `risk_controller.py` (`docs/components/flow-b/scope-risk.md`) — gates enforced here
- `agent_loop.py` (`docs/components/flow-b/agent-loop.md`) — caller loop
- `observer.py` + `outcome_judge.py` (`docs/components/flow-b/observer-outcome.md`) — downstream consumers of `ExecutionResult`
- `evidence.py` (`docs/components/flow-b/evidence-memory-graph.md`) — evidence store written here
