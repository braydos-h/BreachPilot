"""Autonomous Attack Orchestrator — facade re-exporting campaign package.

Thin shim preserving ``from tools.autonomous_orchestrator import X`` imports
while the implementation lives in ``tools.campaign`` (state / executor /
orchestrator / phases / batch / preflight / service_tasks / state_store).

Patch-seam contract (explicit re-exports only — no module-class magic):
tests patch ``tools.autonomous_orchestrator.find_modules`` /
``get_module`` / ``find_producers`` / ``AttackModuleExecutor`` /
``ReconPipeline``. That works WITHOUT setattr propagation because
``find_modules`` / ``find_producers`` / ``get_module`` are resolved through
THIS module at call time (``getattr(tools.autonomous_orchestrator, ...)`` in
``tools/campaign/phases.py``, ``batch.py``, ``executor.py``), and the
classes are shared objects (patching
``tools.autonomous_orchestrator.AttackModuleExecutor.execute`` patches the
method on the canonical class). New code in ``tools/campaign/*`` must keep
resolving those three helpers through this facade at call time — never a
top-level ``from tools.attack_modules import ...`` for a name tests stub
here.
"""

from __future__ import annotations

# Re-export attack_modules helpers for patch seams (tests patch via this module)
from tools.attack_modules import find_modules, find_producers, get_module

# Re-export executor
from tools.campaign.executor import AttackModuleExecutor

# Re-export orchestrator
from tools.campaign.orchestrator import AutonomousOrchestrator

# Re-export state
from tools.campaign.state import (
    AggressionLevel,
    AttackPhase,
    AttackState,
    AttackTask,
    RetryEngine,
    TaskStatus,
    _report_autonomous_progress,
    observe_autonomous_progress,
)

# Re-export recon pipeline (pre-extraction patch seam: tests patch
# tools.autonomous_orchestrator.ReconPipeline.recon_host)
from tools.recon.pipeline import ReconPipeline

__all__ = [
    "AggressionLevel",
    "AttackPhase",
    "AttackState",
    "AttackTask",
    "AttackModuleExecutor",
    "AutonomousOrchestrator",
    "ReconPipeline",
    "RetryEngine",
    "TaskStatus",
    "find_modules",
    "find_producers",
    "get_module",
    "observe_autonomous_progress",
    "_report_autonomous_progress",
]
