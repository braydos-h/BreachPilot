"""Campaign executor — AttackModuleExecutor.

Canonical source for AttackModuleExecutor.
Moved from tools.autonomous_orchestrator to break the god file.
"""
from __future__ import annotations

import asyncio
import inspect
import re
import time
from pathlib import Path
from typing import Any, Callable

from tools.attack_modules import AttackModule, ModuleContext, ModuleResult, _module_target_signature
from tools.attack_ui import get_ui
from tools.logging_setup import get_logger

from tools.campaign.state import (
    AggressionLevel,
    AttackState,
    AttackTask,
    TaskStatus,
    _report_autonomous_progress,
)

logger = get_logger()
ui = get_ui()


