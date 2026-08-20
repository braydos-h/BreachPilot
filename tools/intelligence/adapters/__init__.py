"""Intelligence adapters — Flow B wiring seams for the v2 intelligence upgrade.

- ``target_graph_adapter``: value-based edge wiring for the legacy ``TargetGraph``
  (fixes orphan edges created by ``agent_loop`` passing values where IDs belong).
- ``planner_adapter``: task confidence plumbing, structured plan inputs, and the
  bidirectional ``AttackPhase`` bridge between the two attack-phase enums.
"""

from tools.intelligence.adapters.planner_adapter import (
    AttackPhaseBridge,
    PlannerAdapter,
    planning_score_to_confidence,
)
from tools.intelligence.adapters.target_graph_adapter import TargetGraphV2Adapter

__all__ = [
    "AttackPhaseBridge",
    "PlannerAdapter",
    "TargetGraphV2Adapter",
    "planning_score_to_confidence",
]
