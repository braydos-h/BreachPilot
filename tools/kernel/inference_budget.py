"""Single inference budget shared across orchestration layers.

Per-layer bounds already exist (campaign ``max_cycles``, task ``max_retries``,
worker ``attack_max_rounds``/``attack_max_commands``, peer
``max_consultations``) but nothing ties them together, so the product
(campaign cycles x task retries x model retries x consultations) can multiply
unboundedly. This module is the one object that threads the layers.

Ownership (see ``docs/architecture.md`` "Orchestration ownership"): the
**campaign** owns the budget — it constructs it via :meth:`from_config` and
shares it downward; the worker owns per-action consumption, the swarm owns
delegation consumption. No layer re-implements another's budget.

Fail-open by contract: an unbounded budget (the default, ``max_calls <= 0``)
always grants. A missing or malformed config degrades to unbounded — budget
infrastructure must never become an orchestration gate by accident. Set
``autonomous.max_inference_calls`` (or ``mission_config["max_inference_calls"]``)
to a positive int to bound a campaign.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping


@dataclass
class InferenceBudget:
    """Thread-compatible counter bounding total inference calls.

    ``max_calls <= 0`` means unbounded (fail-open default). Not thread-safe
    under true parallelism — call sites hold their own locks; the counter
    operations themselves are single bytecode steps under the GIL.
    """

    max_calls: int = 0
    spent: int = 0
    _history: list[str] = field(default_factory=list, repr=False)

    @property
    def is_bounded(self) -> bool:
        """True when a positive ceiling is configured."""
        return self.max_calls > 0

    @property
    def exhausted(self) -> bool:
        """True when a bounded budget has no calls left."""
        return self.is_bounded and self.spent >= self.max_calls

    @property
    def remaining(self) -> int | None:
        """Calls left, or None when unbounded."""
        if not self.is_bounded:
            return None
        return max(0, self.max_calls - self.spent)

    def consume(self, label: str = "") -> bool:
        """Consume one call; False when the budget is already spent.

        Never raises — a spent budget denies, anything unexpected grants
        (fail-open: the budget must not wedge orchestration).
        """
        try:
            if self.exhausted:
                return False
            self.spent += 1
            if label:
                self._history.append(label)
            return True
        except Exception:  # noqa: BLE001 -- fail-open by contract
            return True

    def reset(self) -> None:
        """Restore a spent budget (per-target lifecycle resets)."""
        self.spent = 0
        self._history.clear()

    def to_dict(self) -> dict[str, int]:
        """Telemetry snapshot (counts only, never prompts or payloads)."""
        return {"max_calls": self.max_calls, "spent": self.spent, "remaining": self.remaining or 0}

    @classmethod
    def from_config(cls, mission_config: Mapping[str, object] | None) -> InferenceBudget:
        """Build a budget from a mission/config mapping (never raises).

        Reads ``max_inference_calls`` (positive int = bounded, anything else =
        unbounded). ``None`` or malformed input degrades to unbounded.
        """
        try:
            if not isinstance(mission_config, Mapping):
                return cls()
            raw = mission_config.get("max_inference_calls", 0)
            if isinstance(raw, bool):
                return cls()
            if isinstance(raw, float):
                ceiling = int(raw)
            elif isinstance(raw, int):
                ceiling = raw
            elif isinstance(raw, str):
                ceiling = int(raw.strip())
            else:
                return cls()
        except (TypeError, ValueError):
            return cls()
        if ceiling <= 0:
            return cls()
        return cls(max_calls=ceiling)
