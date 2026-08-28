"""Autonomous Attack Orchestrator — facade re-exporting campaign package.

Thin shim preserving ``from tools.autonomous_orchestrator import X`` imports
while the implementation lives in ``tools.campaign`` (state / executor / orchestrator / phases).
"""

from __future__ import annotations

import sys
import types

# Re-export attack_modules helpers for patch seams (tests patch via this module)
from tools.attack_modules import find_modules, find_producers, get_module

# Re-export executor
from tools.campaign.executor import AttackModuleExecutor

# Re-export orchestrator
from tools.campaign.orchestrator import AutonomousOrchestrator

# Re-export recon pipeline (pre-extraction patch seam: tests patch
# tools.autonomous_orchestrator.ReconPipeline.recon_host)
from tools.recon.pipeline import ReconPipeline

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

# Propagate monkeypatch setattr to campaign modules so tests that patch
# tools.autonomous_orchestrator.find_modules / get_module / find_producers
# also affect the canonical implementations in tools.campaign.*.


class _ShimModule(types.ModuleType):
    def __setattr__(self, name, value):  # noqa: D401
        super().__setattr__(name, value)
        for mod_name in (
            "tools.campaign.orchestrator",
            "tools.campaign.phases",
            "tools.campaign.executor",
            "tools.campaign.state",
        ):
            mod = sys.modules.get(mod_name)
            if mod is not None and hasattr(mod, name):
                try:
                    setattr(mod, name, value)
                except Exception:
                    pass


# Install custom class for this module so future setattr goes through propagation
try:
    sys.modules[__name__].__class__ = _ShimModule
except Exception:
    pass
