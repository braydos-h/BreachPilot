"""Memoryless adapter from attack-planner steps to campaign execution.

The planner owns its plan and history. This adapter accepts only one
``StepContext``, creates the ephemeral campaign objects for it, and returns the
bounded result consumed by ``record_step_result``.
"""

from __future__ import annotations

from typing import Any, Protocol

from tools.attack_planner import StepContext
from tools.campaign.state import AttackPhase, AttackState, AttackTask
from tools.exceptions import _EXC_GROUP_CATCH, _is_exception_group, _log_nested_exceptions
from tools.failure_taxonomy import classify_failure


class _CampaignExecutor(Protocol):
    _action_count: int

    def _campaign_phase_for(self, planner_phase: str) -> AttackPhase: ...

    async def execute(self, task: AttackTask, state: AttackState) -> dict[str, Any]: ...


def _result_evidence(result: Any) -> list[str]:
    """Pull a bounded set of human-readable evidence strings from a result."""
    if not isinstance(result, dict):
        return [str(result)[:500]] if result else ["no evidence returned"]
    out: list[str] = []
    evidence = result.get("evidence")
    if isinstance(evidence, list):
        out.extend(str(item)[:500] for item in evidence)
    for key in ("note", "status"):
        value = result.get(key)
        if value:
            out.append(str(value)[:500])
    return out[:10] or ["no evidence returned"]


async def execute_plan_step(executor: _CampaignExecutor, step: StepContext) -> dict[str, Any]:
    """Run one step and fold its operational completion into the planner.

    Scope gating remains inside ``executor.execute`` and therefore stays
    fail-closed. ``success`` here means the requested tool step completed;
    verified compromise remains the separate ``verified_success`` signal on
    the underlying campaign result and is the only signal that changes access
    state. The planner receives no plan, battle log, or sibling-step history.
    """
    task = AttackTask(
        task_id=f"FSM-{executor._action_count + 1:05d}",
        phase=executor._campaign_phase_for(step.phase),
        module_name=step.tool,
        target=step.target_ip,
        parameters=dict(step.arguments),
    )
    state = AttackState(target=step.target_ip)
    try:
        raw = await executor.execute(task, state)
    except _EXC_GROUP_CATCH as exc:
        if _is_exception_group(exc):
            _log_nested_exceptions(exc)
        error = f"{type(exc).__name__}: {exc}"[:2000]
        failure_class = classify_failure(error).value
        return {
            "success": False,
            "evidence": [error],
            "failure_class": failure_class,
            "tool": step.tool,
            "target_ip": step.target_ip,
        }

    if raw.get("completed"):
        return {
            "success": True,
            "evidence": _result_evidence(raw.get("result")),
            "failure_class": "",
            "tool": step.tool,
            "target_ip": step.target_ip,
        }

    error = str(raw.get("error") or "unknown failure")[:2000]
    # Scope blocks must never enter a blind retry path, even when their text
    # does not match one of the classifier's known phrases.
    failure_class = "scope_blocked" if raw.get("blocked") else classify_failure(error).value
    return {
        "success": False,
        "evidence": [error],
        "failure_class": failure_class,
        "tool": step.tool,
        "target_ip": step.target_ip,
    }
