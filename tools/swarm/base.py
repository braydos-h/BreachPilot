"""Base Agent class for the multi-agent swarm.

All specialist agents inherit from `Agent` and implement `run(task, context)`.
The `SwarmOrchestrator` routes tasks to agents based on task type.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from typing import Any


class AgentStatus(str, enum.Enum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"
    BLOCKED = "blocked"


@dataclass
class AgentResult:
    """Structured output from any agent."""

    agent_type: str
    status: AgentStatus
    task_id: str
    output: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    execution_time: float = 0.0
    evidence_refs: list[str] = field(default_factory=list)
    new_tasks: list[dict[str, Any]] = field(default_factory=list)
    memory_updates: list[dict[str, Any]] = field(default_factory=list)
    graph_updates: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    reflections: list[dict[str, Any]] = field(default_factory=list)


class Agent:
    """Base class for all swarm agents.

    Subclasses must override `run(task, context)`.
    """

    def __init__(self, agent_id: str | None = None) -> None:
        self.agent_id = agent_id or f"{self.agent_type}-{uuid.uuid4().hex[:8]}"
        self._status = AgentStatus.IDLE

    @property
    def agent_type(self) -> str:
        """Return the agent type string (e.g., 'recon', 'exploit')."""
        return self.__class__.__name__.replace("Agent", "").lower()

    @property
    def status(self) -> AgentStatus:
        return self._status

    def run(self, task: dict[str, Any], context: dict[str, Any]) -> AgentResult:
        """Execute the agent's specialty against the given task.

        Args:
            task: Task dict from the TaskQueue (must contain 'task_id', 'phase', etc.)
            context: Shared context dict with keys like 'mission', 'memory', 'graph',
                     'scope_gate', 'risk_controller', 'db', 'mission_id', etc.

        Returns:
            AgentResult with structured output for the orchestrator to merge.
        """
        raise NotImplementedError("Subclasses must implement run(task, context)")

    def _set_status(self, status: AgentStatus) -> None:
        self._status = status

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} id={self.agent_id} status={self.status.value}>"
