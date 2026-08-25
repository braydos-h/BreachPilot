"""Campaign package — canonical implementation for autonomous orchestration.

Re-exports the public API so both old and new import paths work:

  from tools.autonomous_orchestrator import AutonomousOrchestrator  # old (shim)
  from tools.campaign import AutonomousOrchestrator                # new
  from tools.campaign.orchestrator import AutonomousOrchestrator  # new direct
"""

from tools.campaign.executor import AttackModuleExecutor  # noqa: F401
from tools.campaign.orchestrator import AutonomousOrchestrator  # noqa: F401
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
    "_report_autonomous_progress",
]
