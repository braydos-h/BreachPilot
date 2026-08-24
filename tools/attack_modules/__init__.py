"""Attack modules plugin framework for autonomous AI-driven exploitation.

Provides a base class and seed modules that give the AI "known recipes"
for common vulnerabilities, so it doesn't have to write every exploit
from scratch.
"""

from tools.attack_modules.base import (
    ApplicabilityReport,
    AttackModule,
    ModuleContext,
    ModuleResult,
)

# Re-export module classes for tests that import them by name
from tools.attack_modules.modules import *  # noqa: F403
from tools.attack_modules.modules import __all__ as _MODULE_EXPORTS
from tools.attack_modules.registry import (
    _MODULE_CLASSES,
    _module_experience_confidence,
    _module_primary_service,
    _module_target_signature,
    find_modules,
    find_producers,
    get_module,
    list_modules,
    missing_prerequisites,
)

__all__ = [
    "AttackModule",
    "ModuleContext",
    "ModuleResult",
    "ApplicabilityReport",
    "list_modules",
    "find_modules",
    "find_producers",
    "missing_prerequisites",
    "get_module",
    "_MODULE_CLASSES",
    "_module_primary_service",
    "_module_target_signature",
    "_module_experience_confidence",
] + _MODULE_EXPORTS
