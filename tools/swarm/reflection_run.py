"""Reflection dispatch — run the reflection agent over the battle log.

Extracted from ``SwarmOrchestrator`` (see ``tools/swarm/orchestrator.py``) to
keep the orchestrator under 500 lines. Bound onto ``SwarmOrchestrator``
after its definition, so ``self.reflect`` call sites and tests keep working
unchanged.
"""

from __future__ import annotations

import time
from typing import Any

from tools.swarm.agents.reflection_agent import ReflectionAgent
from tools.swarm.base import AgentResult, AgentStatus


def reflect(self, battle_log: list[dict[str, Any]], session_state: dict[str, Any]) -> AgentResult:
    """Run the reflection agent on the current phase results.

    The reflection agent analyzes the battle log, identifies patterns,
    and recommends strategy shifts. Results are stored on the blackboard.
    """
    with self._lock:
        if not self._reflection_enabled:
            return AgentResult(
                agent_type="reflection",
                status=AgentStatus.IDLE,
                task_id="reflection-skip",
                output={},
            )
        agent = ReflectionAgent()
        task = {
            "task_id": f"reflect-{int(time.time())}",
            "battle_log": battle_log,
            "session_state": session_state,
        }
        result = agent.run(task, self._context)
        self._results.append(result)
        self._trim_history()
        if result.output:
            self._blackboard.set_scalar("last_reflection", result.output)
            self._blackboard.set_scalar("strategy_shift", result.output.get("recommended_strategy_shift", ""))
            self._emit(
                "reflection_output",
                {
                    "task_id": task["task_id"],
                    "recommended_strategy_shift": self._blackboard["strategy_shift"],
                    "output_summary": str(result.output)[:500],
                },
            )
            self._persist_state()

        return result
