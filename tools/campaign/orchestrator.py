"""Campaign orchestrator — AutonomousOrchestrator core.

Canonical source for AutonomousOrchestrator.
Moved from tools.autonomous_orchestrator to break the god file.
Phase handlers live in tools.campaign.phases and are bound after class definition
to preserve ``self._phase_*`` call sites.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from tools.attack_modules import ModuleContext
from tools.attack_ui import get_ui
from tools.logging_setup import get_logger
from tools.recon_pipeline import HostReconResult, ReconConfig, ReconPipeline
from tools.validation_utils import is_local_target

from tools.campaign.executor import AttackModuleExecutor
from tools.campaign.state import (
    AggressionLevel,
    AttackPhase,
    AttackState,
    AttackTask,
    RetryEngine,
    TaskStatus,
    _report_autonomous_progress,
)

logger = get_logger()
ui = get_ui()



# Bind phase handlers (preserve self._phase_* call sites without inheritance)
from tools.campaign import phases as _phases  # noqa: E402
AutonomousOrchestrator._phase_local_takeover = _phases._phase_local_takeover  # type: ignore[attr-defined]
AutonomousOrchestrator._phase_reconnaissance = _phases._phase_reconnaissance  # type: ignore[attr-defined]
AutonomousOrchestrator._phase_exploitation = _phases._phase_exploitation  # type: ignore[attr-defined]
AutonomousOrchestrator._phase_privilege_escalation = _phases._phase_privilege_escalation  # type: ignore[attr-defined]
AutonomousOrchestrator._phase_lateral_movement = _phases._phase_lateral_movement  # type: ignore[attr-defined]
AutonomousOrchestrator._phase_validation = _phases._phase_validation  # type: ignore[attr-defined]
AutonomousOrchestrator._extract_persistence_marker = _phases._extract_persistence_marker  # type: ignore[attr-defined]
AutonomousOrchestrator._module_context = _phases._module_context  # type: ignore[attr-defined]
AutonomousOrchestrator._phase_persistence = _phases._phase_persistence  # type: ignore[attr-defined]
AutonomousOrchestrator._run_adaptive_rounds = _phases._run_adaptive_rounds  # type: ignore[attr-defined]
AutonomousOrchestrator._schedule_vuln_chain = _phases._schedule_vuln_chain  # type: ignore[attr-defined]
