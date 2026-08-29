"""Kill-chain state machine package (design §killchain).

Public API: :class:`AttackState`, the declarative edge registry
(:data:`EDGES` + accessors), and :class:`KillChainMachine` — the verified-only
transition engine that owns ``attack_state`` on graph nodes.
"""

from __future__ import annotations

from tools.killchain.edges import (
    EDGES,
    STUB_EDGES,
    all_edges,
    edges_from,
    get_edge,
    resolve_placeholders,
)
from tools.killchain.machine import DEFAULT_GOAL_STATE, KillChainMachine
from tools.killchain.states import AttackState

__all__ = [
    "AttackState",
    "DEFAULT_GOAL_STATE",
    "EDGES",
    "STUB_EDGES",
    "KillChainMachine",
    "all_edges",
    "edges_from",
    "get_edge",
    "resolve_placeholders",
]
