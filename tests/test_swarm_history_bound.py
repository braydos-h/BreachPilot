"""Regression: SwarmOrchestrator and AgentLoop bound their in-memory history.

``SwarmOrchestrator._results`` and ``._battle_log`` grow on every routed task
and reflection. They are read only for their length and a recent tail
(``_persist_state`` snapshots ``battle_log[-20:]``; reflection is fed
``battle_log[-reflection_interval:]``), so the full history is pure
accumulation — a memory leak in long multi-cycle campaigns. The full per-task
outcome is persisted to swarm_state.json on every event, so bounding the
in-memory lists loses no consumed data.

``AgentLoop._battle_log`` has the same shape and the same fix.
"""

from __future__ import annotations

from tools.swarm.base import AgentResult, AgentStatus
from tools.swarm.orchestrator import SwarmOrchestrator


def _fake_result(task_id: str) -> AgentResult:
    return AgentResult(
        agent_type="recon",
        status=AgentStatus.COMPLETE,
        task_id=task_id,
        output={"summary": "ok"},
    )


def test_swarm_results_and_battle_log_capped() -> None:
    orch = SwarmOrchestrator(context={}, critic_enabled=False, reflection_enabled=False)
    over = orch._max_results + 250
    for i in range(over):
        orch._results.append(_fake_result(f"T-{i}"))
        orch._battle_log.append({"task_id": f"T-{i}", "success": True})
        orch._trim_history()

    assert len(orch._results) == orch._max_results
    assert len(orch._battle_log) == orch._max_battle_log
    # Most recent entries are retained.
    assert orch._results[-1].task_id == f"T-{over - 1}"
    assert orch._battle_log[-1]["task_id"] == f"T-{over - 1}"


def test_swarm_trim_history_noop_under_cap() -> None:
    orch = SwarmOrchestrator(context={}, critic_enabled=False, reflection_enabled=False)
    for i in range(10):
        orch._results.append(_fake_result(f"T-{i}"))
        orch._battle_log.append({"task_id": f"T-{i}", "success": True})
    orch._trim_history()
    assert len(orch._results) == 10
    assert len(orch._battle_log) == 10
