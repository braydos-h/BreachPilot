"""Explicit run budgets (#34).

Time, actions, tokens, cost, requests, retries, browser ops, and assets
each get a limit; :class:`BudgetTracker` records consumption and reports
*which* budget stopped the run using the #36 stop-taxonomy reason
(``budget exhausted`` with the dimension named). The exploit runner owns
time/round budgets today; this tracker is the typed home the remaining
dimensions migrate to (runner wiring is the follow-up — the semantics and
the stop reasons land here first).
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any

__all__ = [
    "BUDGET_EXHAUSTED",
    "BudgetLimits",
    "BudgetUsage",
    "BudgetTracker",
]

#: Stop-taxonomy reason (#36) used for every budget stop.
BUDGET_EXHAUSTED = "budget exhausted"


@dataclass(slots=True)
class BudgetLimits:
    """Maximum consumption per dimension (0/None = unbounded)."""

    time_seconds: float = 0.0
    actions: int = 0
    tokens: int = 0
    cost_usd: float = 0.0
    requests: int = 0
    retries: int = 0
    browser_ops: int = 0
    assets: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class BudgetUsage:
    """Consumption so far (monotonic counters)."""

    elapsed_seconds: float = 0.0
    actions: int = 0
    tokens: int = 0
    cost_usd: float = 0.0
    requests: int = 0
    retries: int = 0
    browser_ops: int = 0
    assets: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BudgetTracker:
    """Record consumption; report which budget (if any) is exhausted."""

    limits: BudgetLimits = field(default_factory=BudgetLimits)
    usage: BudgetUsage = field(default_factory=BudgetUsage)
    _started: float = field(default_factory=time.monotonic, repr=False)

    def add(
        self,
        *,
        actions: int = 0,
        tokens: int = 0,
        cost_usd: float = 0.0,
        requests: int = 0,
        retries: int = 0,
        browser_ops: int = 0,
        assets: int = 0,
    ) -> None:
        """Record consumption (all deltas must be non-negative)."""
        for value in (actions, tokens, cost_usd, requests, retries, browser_ops, assets):
            if value < 0:
                raise ValueError("budget consumption deltas must be non-negative")
        self.usage.actions += actions
        self.usage.tokens += tokens
        self.usage.cost_usd += cost_usd
        self.usage.requests += requests
        self.usage.retries += retries
        self.usage.browser_ops += browser_ops
        self.usage.assets += assets

    def elapsed(self) -> float:
        """Wall-clock seconds since tracker creation (plus recorded usage)."""
        return self.usage.elapsed_seconds + (time.monotonic() - self._started)

    def exhausted(self) -> list[str]:
        """Names of exhausted dimensions (empty = budget remains)."""
        hit: list[str] = []
        limits, usage = self.limits, self.usage
        if limits.time_seconds > 0 and self.elapsed() >= limits.time_seconds:
            hit.append("time")
        if limits.actions > 0 and usage.actions >= limits.actions:
            hit.append("actions")
        if limits.tokens > 0 and usage.tokens >= limits.tokens:
            hit.append("tokens")
        if limits.cost_usd > 0 and usage.cost_usd >= limits.cost_usd:
            hit.append("cost")
        if limits.requests > 0 and usage.requests >= limits.requests:
            hit.append("requests")
        if limits.retries > 0 and usage.retries >= limits.retries:
            hit.append("retries")
        if limits.browser_ops > 0 and usage.browser_ops >= limits.browser_ops:
            hit.append("browser_ops")
        if limits.assets > 0 and usage.assets >= limits.assets:
            hit.append("assets")
        return hit

    def stop_reason(self) -> str:
        """Stop-taxonomy reason, or "" when budget remains."""
        hit = self.exhausted()
        if not hit:
            return ""
        return f"{BUDGET_EXHAUSTED} ({', '.join(hit)})"

    def to_dict(self) -> dict[str, Any]:
        return {"limits": self.limits.to_dict(), "usage": self.usage.to_dict(), "exhausted": self.exhausted()}
