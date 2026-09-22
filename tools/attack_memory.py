"""Thin re-export shim — implementation lives in tools.memory_service.

Preserved so existing import paths (exploit loop, swarm, campaign, legacy
flows, tests) keep working without behavior change.
"""

from tools.memory_service import ATTACK_MEMORY_DB as ATTACK_MEMORY_DB
from tools.memory_service import AttackMemoryItem as AttackMemoryItem
from tools.memory_service import AttackMemoryStore as AttackMemoryStore

__all__ = ["ATTACK_MEMORY_DB", "AttackMemoryItem", "AttackMemoryStore"]
