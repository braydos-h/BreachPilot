"""Campaign package — Phase 4 shim.

Phase 4 splits ``tools/autonomous_orchestrator.py`` (2720 LOC) into
``tools/campaign/`` (``state.py`` / ``phases.py`` / ``executor.py``). This
``__init__`` re-exports the public surface so both paths work during the
1-release shim window:

  from tools.autonomous_orchestrator import AutonomousOrchestrator  # old
  from tools.campaign import AutonomousOrchestrator                # new

The real split (moving bodies, reusing ``AssessmentService`` pattern from
``tools/run_service/service.py``) lands in the next sub-PR. See debt doc §12.
"""

from tools.autonomous_orchestrator import (  # noqa: F401
    AggressionLevel,
    AttackPhase,
    AttackState,
    AttackTask,
    AutonomousOrchestrator,
    TaskStatus,
)

__all__ = [
    "AggressionLevel",
    "AttackPhase",
    "AttackState",
    "AttackTask",
    "AutonomousOrchestrator",
    "TaskStatus",
]
