"""Provider comparison for benchmark runs (#38).

Pure aggregation over stored run summaries grouped by model provider:
verified rate, false-positive rate, median actions, and cost side by side
so the router can choose per-role models on data (cheap recon model vs
high-capability auth reasoning vs separate verifier).

No I/O — callers load persisted summaries and pass them in. Runs with
different scenario suites are compared row-by-row, never blended into a
single misleading number: each row pins provider + model + suite + trials.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ProviderRow:
    """One comparable cell: a single provider/model/suite run."""

    provider: str = "unknown"
    model_id: str = "unknown"
    suite: str = "unknown"
    trials: int = 0
    verified_rate: float = 0.0
    false_positive_rate: float = 0.0
    median_actions: float | None = None
    estimated_cost: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "model_id": self.model_id,
            "suite": self.suite,
            "trials": self.trials,
            "verified_rate": self.verified_rate,
            "false_positive_rate": self.false_positive_rate,
            "median_actions": self.median_actions,
            "estimated_cost": self.estimated_cost,
        }


@dataclass
class ProviderComparison:
    """Grouped comparison across providers (one row per run)."""

    rows: list[ProviderRow] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"rows": [r.to_dict() for r in self.rows]}

    def to_markdown(self) -> str:
        lines = [
            "| Provider | Model | Suite | Trials | Verified | False+ | Median actions | Cost |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for r in self.rows:
            med = f"{r.median_actions:.0f}" if r.median_actions is not None else "n/a"
            cost = f"${r.estimated_cost:.2f}" if r.estimated_cost is not None else "n/a"
            lines.append(
                f"| {r.provider} | {r.model_id} | {r.suite} | {r.trials} | "
                f"{r.verified_rate:.1%} | {r.false_positive_rate:.1%} | {med} | {cost} |"
            )
        if len(self.rows) < 2:
            lines.append("")
            lines.append("_Single run — add a second provider run for a real comparison._")
        return "\n".join(lines) + "\n"


def _median(values: list[float]) -> float | None:
    return statistics.median(values) if values else None


def compare_runs(runs: list[dict[str, Any]]) -> ProviderComparison:
    """Build a comparison from stored run payloads.

    Each payload is ``{"environment": {...}, "summary": {...}}`` as persisted
    by BenchmarkStorage. Missing keys degrade to unknown/zero — a malformed
    payload never aborts the comparison.
    """
    comparison = ProviderComparison()
    for payload in runs:
        if not isinstance(payload, dict):
            continue
        env = payload.get("environment", {}) if isinstance(payload.get("environment"), dict) else {}
        summary = payload.get("summary", {}) if isinstance(payload.get("summary"), dict) else {}
        # Median actions over verified trials when per-trial rows are present.
        median_actions: float | None = None
        trials = payload.get("trials", [])
        if isinstance(trials, list) and trials:
            verified_actions = [
                float(t.get("tool_calls", 0) or 0)
                for t in trials
                if isinstance(t, dict) and t.get("oracle_verified_success") is True
            ]
            median_actions = _median(verified_actions)
        if median_actions is None and isinstance(summary.get("median_tool_actions"), (int, float)):
            median_actions = float(summary["median_tool_actions"])
        cost = summary.get("estimated_cost")
        comparison.rows.append(
            ProviderRow(
                provider=str(env.get("model_provider", "unknown") or "unknown"),
                model_id=str(env.get("model_id", "unknown") or "unknown"),
                suite=str(summary.get("suite", "unknown") or "unknown"),
                trials=int(summary.get("trials_total", 0) or 0),
                verified_rate=float(summary.get("verified_success_rate", 0.0) or 0.0),
                false_positive_rate=float(summary.get("false_positive_rate", 0.0) or 0.0),
                median_actions=median_actions,
                estimated_cost=float(cost) if isinstance(cost, (int, float)) else None,
            )
        )
    comparison.rows.sort(key=lambda r: (r.provider, r.model_id, r.suite))
    return comparison
