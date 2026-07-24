"""Attack modules plugin framework for autonomous AI-driven exploitation.

Provides a base class and seed modules that give the AI "known recipes"
for common vulnerabilities, so it doesn't have to write every exploit
from scratch.
"""

from tools.attack_modules.base import AttackModule, ModuleContext
from tools.attack_modules.registry import (
    find_modules,
    get_module,
    list_modules,
    _MODULE_CLASSES,
    _module_experience_confidence,
    _module_primary_service,
    _module_target_signature,
)

# Re-export module classes for tests that import them by name
from tools.attack_modules.modules import *  # noqa: F403
from tools.attack_modules.modules import __all__ as _MODULE_EXPORTS

__all__ = [
    "AttackModule",
    "ModuleContext",
    "list_modules",
    "find_modules",
    "get_module",
    "_MODULE_CLASSES",
    "_module_primary_service",
    "_module_target_signature",
    "_module_experience_confidence",
] + _MODULE_EXPORTS
