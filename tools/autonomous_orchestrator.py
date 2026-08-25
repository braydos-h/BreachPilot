"""Autonomous Attack Orchestrator — facade re-exporting campaign package.

Thin 200-line facade preserving ``from tools.autonomous_orchestrator import X`` imports
while the implementation lives in ``tools.campaign/*``.
"""

from __future__ import annotations

# Re-export executor
from tools.campaign.executor import AttackModuleExecutor  # noqa: F401

# Re-export orchestrator (lives in persistence.py via mixins)
from tools.campaign.persistence import AutonomousOrchestrator  # noqa: F401

# Re-export state
from tools.campaign.state import (  # noqa: F401
    AggressionLevel,
    AttackPhase,
    AttackState,
    AttackTask,
    RetryEngine,
    TaskStatus,
    _report_autonomous_progress,
    observe_autonomous_progress,
)

__all__ = [
    "AggressionLevel",
    "AttackPhase",
    "AttackState",
    "AttackTask",
    "AttackModuleExecutor",
    "AutonomousOrchestrator",
    "RetryEngine",
    "TaskStatus",
    "observe_autonomous_progress",
]
