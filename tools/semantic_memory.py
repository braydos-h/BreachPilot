"""Thin re-export shim — implementation lives in tools.memory_service.

Preserved so existing import paths (exploit loop, swarm, campaign, legacy
flows, tests) keep working without behavior change.
"""

from tools.memory_service import SemanticMemoryManager as SemanticMemoryManager

__all__ = ["SemanticMemoryManager"]
