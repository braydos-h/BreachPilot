"""Campaign phases — exploitation / privesc / lateral / validation / persistence.

Extracted from AutonomousOrchestrator to keep each file <1000 LOC / 72kB.
These are the phase handlers that were previously methods on AutonomousOrchestrator;
they are defined here as functions and bound to the orchestrator class after import
to preserve the original ``self._phase_*`` call sites without an extra base class.

Each function takes ``self`` (the orchestrator instance) as first arg so the
body can stay verbatim from the monolith.
"""
from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Any

from tools.attack_modules import ModuleContext
from tools.logging_setup import get_logger
from tools.recon_pipeline import HostReconResult
from tools.validation_utils import is_local_target

from tools.campaign.state import AggressionLevel, AttackPhase, AttackState, AttackTask, TaskStatus, _report_autonomous_progress

logger = get_logger()

from tools.attack_ui import get_ui

ui = get_ui()


