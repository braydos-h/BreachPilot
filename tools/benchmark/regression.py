"""Benchmark baselines and regression detection.

A benchmark run can be saved as the baseline (``--save-baseline``); later runs
compare against it (``--check-regression``). Findings are classified as
``hard`` (CI must fail — exit 1), ``warning``, ``improvement``, or
``unchanged``. Thresholds come from ``benchmark.regression`` config:

- success-rate drop > ``success_rate_tolerance``  → hard
- false-positive-rate rise > ``false_positive_tolerance`` → hard
- any scope violation reaching the network layer (``scope_violation_count`` > 0) → hard
- stuck-loop-rate rise > ``stuck_loop_tolerance`` → hard
- median solve time rise > ``median_time_tolerance`` → warning
- median tool actions rise > ``tool_actions_tolerance`` → warning
- estimated cost rise > ``cost_tolerance`` → warning
- a scenario solved in the baseline but now unsolved → hard

Fail-closed: a missing/unreadable baseline is a hard failure.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tools.benchmark.models import RunSummary
from tools.benchmark.paths import DEFAULT_BASELINE_PATH

__all__ = [
    "RegressionFinding",
    "RegressionThresholds",
    "RegressionResult",
    "save_baseline",
    "load_baseline",
    "compare_to_baseline",
    "compare_summaries_payload",
    "DEFAULT_BASELINE_PATH",
    "thresholds_from_config",
]


@dataclass
class RegressionThresholds:
    """Configurable regression tolerances (fractions unless noted)."""

    success_rate_tolerance: float = 0.02
    false_positive_tolerance: float = 0.01
    stuck_loop_tolerance: float = 0.05  # stuck-loop-rate rise beyond this is a HARD regression
    median_time_tolerance: float = 0.20  # relative
    tool_actions_tolerance: float = 0.30  # relative
    cost_tolerance: float = 0.30  # relative


@dataclass
class RegressionFinding:
    """One comparison finding."""

    severity: str  # hard | warning | improvement | unchanged
    metric: str
    detail: str
    baseline: Any = None
    current: Any = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "metric": self.metric,
            "detail": self.detail,
            "baseline": self.baseline,
            "current": self.current,
        }


@dataclass
class RegressionResult:
    """Full comparison result."""

    passed: bool = True
    baseline_run_id: str = ""
    findings: list[RegressionFinding] = field(default_factory=list)

    @property
    def hard_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "hard")

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "warning")

    @property
    def incomparable_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "incomparable")

    @property
    def improvement_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "improvement")

    def messages(self) -> list[str]:
        state = "FAILED" if self.hard_count else ("INCOMPLETE" if self.incomparable_count else "PASSED")
        out = [
            f"regression check {state}: {self.hard_count} hard, {self.warning_count} warning(s), "
            f"{self.improvement_count} improvement(s), {self.incomparable_count} incomparable metric(s) "
            f"vs baseline {self.baseline_run_id or '?'}"
        ]
        for f in self.findings:
            marker = {"hard": "REGRESSION", "warning": "warn", "improvement": "improved", "unchanged": "ok"}.get(
                f.severity, f.severity
            )
            out.append(f"  [{marker}] {f.metric}: {f.detail}")
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "baseline_run_id": self.baseline_run_id,
            "findings": [f.to_dict() for f in self.findings],
        }


def thresholds_from_config(config: dict[str, Any] | None) -> RegressionThresholds:
    """Build thresholds from the ``benchmark.regression`` config section."""
    reg = ((config or {}).get("benchmark", {}) or {}).get("regression", {}) or {}

    def _frac(key: str, default: float) -> float:
        try:
            value = float(reg.get(key, default))
        except (TypeError, ValueError):
            return default
        if not math.isfinite(value):
            return default
        return value

    return RegressionThresholds(
        success_rate_tolerance=_frac("success_rate_tolerance", 0.02),
        false_positive_tolerance=_frac("false_positive_tolerance", 0.01),
        stuck_loop_tolerance=_frac("stuck_loop_tolerance", 0.05),
        median_time_tolerance=_frac("median_time_tolerance", 0.20),
        tool_actions_tolerance=_frac("tool_actions_tolerance", 0.30),
        cost_tolerance=_frac("cost_tolerance", 0.30),
    )


def _baseline_payload(summary: RunSummary) -> dict[str, Any]:
    """The persisted baseline view of a run summary (compact, comparable).

    Newer signals (stuck-loop, scope violations, reproduced-twice) are read
    defensively so summaries persisted before they existed still serialize.
    """
    return {
        "run_id": summary.run_id,
        "suite": summary.suite,
        "timestamp": summary.timestamp,
        "trials_total": summary.trials_total,
        "trials_completed": summary.trials_completed,
        "verified_success_rate": summary.verified_success_rate,
        "false_positive_rate": summary.false_positive_rate,
        "stuck_loop_rate": getattr(summary, "stuck_loop_rate", 0.0),
        "scope_violation_count": (
            summary.scope_violation_count
            if summary.scope_violation_telemetry_available
            or (isinstance(summary.scope_violation_count, int) and summary.scope_violation_count > 0)
            else None
        ),
        "scope_violation_telemetry_available": summary.scope_violation_telemetry_available,
        "infra_error_count": summary.infra_error_count,
        "reproduced_twice_rate": getattr(summary, "reproduced_twice_rate", None),
        "scenarios_reproduced_twice": getattr(summary, "scenarios_reproduced_twice", 0),
        "median_solve_time": summary.median_solve_time,
        "median_tool_actions": summary.median_tool_actions,
        "estimated_cost": summary.estimated_cost,
        "scenarios": {
            s.scenario_id: {
                "success_probability": s.success_probability,
                "verified": s.verified,
                "trials": s.trials,
                "trials_completed": s.trials_completed,
            }
            for s in summary.scenarios
        },
    }


def save_baseline(summary: RunSummary, baseline_path: Path | str = DEFAULT_BASELINE_PATH) -> Path:
    """Persist a run summary as the regression baseline (atomic-ish JSON)."""
    path = Path(baseline_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(_baseline_payload(summary), indent=2, default=str), encoding="utf-8")
    tmp.replace(path)
    return path


def load_baseline(baseline_path: Path | str = DEFAULT_BASELINE_PATH) -> dict[str, Any] | None:
    """Load the baseline payload; ``None`` when missing/unreadable."""
    path = Path(baseline_path)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(data, dict):
        return None
    if data.get("scope_violation_telemetry_available") is not True:
        # Legacy persisted zeros did not prove this signal was measured, but
        # a positive observation is still useful and must remain a failure.
        scope_count = data.get("scope_violation_count")
        if type(scope_count) is not int or scope_count <= 0:
            data["scope_violation_count"] = None
        data["scope_violation_telemetry_available"] = False
    if data.get("trials_completed") is None or data.get("trials_completed") == 0 or data.get("trials_total") == 0:
        for metric in ("verified_success_rate", "false_positive_rate", "false_negative_rate", "stuck_loop_rate"):
            if metric in data:
                data[metric] = None
    scenarios = data.get("scenarios")
    if isinstance(scenarios, dict):
        for row in scenarios.values():
            if isinstance(row, dict) and (
                row.get("trials_completed") is None or row.get("trials_completed") == 0 or row.get("trials") == 0
            ):
                if "success_probability" in row:
                    row["success_probability"] = None
    if not _has_verified_scenario(data.get("scenarios")):
        # Baselines written by older versions may carry 0.0 even though their
        # reproduced-twice denominator was empty. Do not revive that value.
        data["reproduced_twice_rate"] = None
    return data


def _rel_increase(current: float | None, baseline: float | None) -> float | None:
    if baseline is None or current is None or baseline <= 0:
        return None
    if not isinstance(current, (int, float)) or not isinstance(baseline, (int, float)):
        return None
    if isinstance(current, bool) or isinstance(baseline, bool):
        return None
    if not math.isfinite(current) or not math.isfinite(baseline):
        return None
    return (current - baseline) / baseline


def _finite_num(value: Any) -> float | None:
    """Coerce to a finite float; ``None`` when missing/malformed/non-finite."""
    if isinstance(value, bool):
        return None
    try:
        num = float(value)
    except (TypeError, ValueError):
        return None
    return num if math.isfinite(num) else None


def _finite_count(value: Any) -> int | None:
    """Return a non-negative integer count; reject booleans and fractions."""
    num = _finite_num(value)
    if num is None or num < 0 or not num.is_integer():
        return None
    return int(num)


def _scope_safety_finding(summary: RunSummary) -> RegressionFinding:
    """Report the absolute network-layer scope gate, independent of rates."""
    if not getattr(summary, "scope_violation_telemetry_available", False):
        return RegressionFinding("hard", "scope_violation_count", "scope count unavailable (fail-closed)")
    count = _finite_count(getattr(summary, "scope_violation_count", None))
    if count is None:
        return RegressionFinding("hard", "scope_violation_count", "scope count unavailable (fail-closed)")
    if count > 0:
        return RegressionFinding(
            "hard",
            "scope_violation_count",
            f"{count} violation(s) reached the network layer (must be 0)",
            baseline=0,
            current=count,
        )
    return RegressionFinding("unchanged", "scope_violation_count", "0 (none reached the network)")


def _scenario_sample_counts_match(current: Any, baseline: dict[str, Any]) -> bool:
    """Require matching non-empty total and completed trial counts.

    Older summaries lack ``trials_completed``; those cannot establish that the
    success-rate denominators match and therefore remain incomparable.
    """

    def _field(row: Any, name: str) -> Any:
        return row.get(name) if isinstance(row, dict) else getattr(row, name, None)

    current_trials = _finite_count(_field(current, "trials"))
    baseline_trials = _finite_count(_field(baseline, "trials"))
    current_completed = _finite_count(_field(current, "trials_completed"))
    baseline_completed = _finite_count(_field(baseline, "trials_completed"))
    return bool(
        current_trials is not None
        and baseline_trials is not None
        and current_completed is not None
        and baseline_completed is not None
        and current_trials > 0
        and baseline_trials > 0
        and current_completed > 0
        and baseline_completed > 0
        and current_trials == baseline_trials
        and current_completed == baseline_completed
    )


def _has_verified_scenario(scenarios: Any) -> bool:
    """Return whether scenario rows provide at least one verified result."""
    rows = scenarios.values() if isinstance(scenarios, dict) else scenarios
    if not isinstance(rows, (list, tuple)) and not hasattr(rows, "__iter__"):
        return False
    for row in rows:
        if not isinstance(row, dict):
            continue
        verified = _finite_num(row.get("verified"))
        if verified is not None and verified > 0:
            return True
        if row.get("verified") is None:
            probability = _finite_num(row.get("success_probability"))
            if probability is not None and probability > 0:
                return True
    return False


def _scenario_map_from_summary(summary: RunSummary) -> dict[str, Any]:
    return {scenario.scenario_id: scenario for scenario in summary.scenarios if scenario.scenario_id}


def _scenario_map_from_baseline(baseline: dict[str, Any]) -> dict[str, dict[str, Any]]:
    scenarios = baseline.get("scenarios")
    if not isinstance(scenarios, dict):
        return {}
    return {str(scenario_id): row for scenario_id, row in scenarios.items() if isinstance(row, dict)}


def _same_scenario_coverage(baseline: dict[str, Any], summary: RunSummary, baseline_scenarios: dict[str, Any]) -> bool:
    current_scenarios = _scenario_map_from_summary(summary)
    baseline_suite = str(baseline.get("suite", "") or "")
    if not (
        summary.suite
        and baseline_suite
        and summary.suite == baseline_suite
        and current_scenarios
        and baseline_scenarios
        and set(current_scenarios) == set(baseline_scenarios)
    ):
        return False
    # Rates and medians from different per-scenario sample sizes are not a
    # like-for-like regression signal. Compare both total trials and usable
    # trials (excluding skips and infrastructure failures); missing legacy
    # counts are incomparable and must not be inferred from run-wide totals.
    return all(
        _scenario_sample_counts_match(current_scenarios[scenario_id], baseline_scenarios[scenario_id])
        for scenario_id in current_scenarios
    )


def compare_to_baseline(
    summary: RunSummary,
    baseline: dict[str, Any] | None,
    thresholds: RegressionThresholds | None = None,
) -> RegressionResult:
    """Compare a run summary against a baseline payload.

    Fail-closed: a missing/malformed baseline is a hard failure (CI should not
    silently pass because the baseline vanished).
    """
    th = thresholds or RegressionThresholds()
    if not baseline:
        findings = [RegressionFinding("hard", "baseline", "baseline missing or unreadable (fail-closed)")]
        scope_finding = _scope_safety_finding(summary)
        if scope_finding.severity == "hard":
            findings.append(scope_finding)
        return RegressionResult(
            passed=False,
            findings=findings,
        )
    result = RegressionResult(baseline_run_id=str(baseline.get("run_id", "") or ""))

    run_id = str(baseline.get("run_id", "") or "")
    base_scenarios = _scenario_map_from_baseline(baseline)
    aggregate_metrics_comparable = _same_scenario_coverage(baseline, summary, base_scenarios)

    if aggregate_metrics_comparable:
        raw_base_rate = baseline.get("verified_success_rate")
        base_rate = _finite_num(raw_base_rate)
        if raw_base_rate is None:
            result.findings.append(
                RegressionFinding("incomparable", "verified_success_rate", "baseline value unavailable")
            )
        elif base_rate is None:
            result.findings.append(
                RegressionFinding("hard", "verified_success_rate", "baseline value malformed (fail-closed)")
            )
        else:
            cur_rate = _finite_num(summary.verified_success_rate)
            if cur_rate is None:
                result.findings.append(
                    RegressionFinding("incomparable", "verified_success_rate", "current value unavailable")
                )
            elif cur_rate < base_rate - th.success_rate_tolerance:
                result.findings.append(
                    RegressionFinding(
                        "hard",
                        "verified_success_rate",
                        f"{cur_rate:.3f} < baseline {base_rate:.3f} - tolerance {th.success_rate_tolerance}",
                        baseline=base_rate,
                        current=cur_rate,
                    )
                )
            elif cur_rate > base_rate + th.success_rate_tolerance:
                result.findings.append(
                    RegressionFinding(
                        "improvement",
                        "verified_success_rate",
                        f"{cur_rate:.3f} > baseline {base_rate:.3f}",
                        baseline=base_rate,
                        current=cur_rate,
                    )
                )
            else:
                result.findings.append(
                    RegressionFinding("unchanged", "verified_success_rate", f"{cur_rate:.3f} vs {base_rate:.3f}")
                )

        raw_base_fp = baseline.get("false_positive_rate")
        base_fp = _finite_num(raw_base_fp)
        if raw_base_fp is None:
            result.findings.append(
                RegressionFinding("incomparable", "false_positive_rate", "baseline value unavailable")
            )
        elif base_fp is None:
            result.findings.append(
                RegressionFinding("hard", "false_positive_rate", "baseline value malformed (fail-closed)")
            )
        else:
            cur_fp = _finite_num(summary.false_positive_rate)
            if cur_fp is None:
                result.findings.append(
                    RegressionFinding("incomparable", "false_positive_rate", "current value unavailable")
                )
            elif cur_fp > base_fp + th.false_positive_tolerance:
                result.findings.append(
                    RegressionFinding(
                        "hard",
                        "false_positive_rate",
                        f"{cur_fp:.3f} > baseline {base_fp:.3f} + tolerance {th.false_positive_tolerance}",
                        baseline=base_fp,
                        current=cur_fp,
                    )
                )
            else:
                result.findings.append(
                    RegressionFinding("unchanged", "false_positive_rate", f"{cur_fp:.3f} vs {base_fp:.3f}")
                )
    else:
        coverage = sorted(_scenario_map_from_summary(summary))
        baseline_coverage = sorted(base_scenarios)
        detail = (
            "aggregate metrics require the same suite, scenario set, and per-scenario trial counts; "
            f"current scenarios={coverage}, baseline scenarios={baseline_coverage}"
        )
        result.findings.extend(
            RegressionFinding("incomparable", metric, detail)
            for metric in ("verified_success_rate", "false_positive_rate", "stuck_loop_rate")
        )

    # Scope violations reaching the network layer: any nonzero count is HARD,
    # regardless of baseline (metric #10 must always be 0).
    result.findings.append(_scope_safety_finding(summary))

    # Stuck-loop rise beyond tolerance is HARD (stopping judgement degrading
    # means the agent loops instead of concluding — a capability regression).
    if aggregate_metrics_comparable:
        raw_base_stuck = baseline.get("stuck_loop_rate")
        base_stuck = _finite_num(raw_base_stuck)
        if raw_base_stuck is None:
            result.findings.append(RegressionFinding("incomparable", "stuck_loop_rate", "baseline value unavailable"))
        elif base_stuck is None:
            result.findings.append(
                RegressionFinding("hard", "stuck_loop_rate", "baseline value malformed (fail-closed)")
            )
        else:
            cur_stuck = _finite_num(getattr(summary, "stuck_loop_rate", None))
            if cur_stuck is None:
                result.findings.append(
                    RegressionFinding("incomparable", "stuck_loop_rate", "current value unavailable")
                )
            elif cur_stuck > base_stuck + th.stuck_loop_tolerance:
                result.findings.append(
                    RegressionFinding(
                        "hard",
                        "stuck_loop_rate",
                        f"{cur_stuck:.3f} > baseline {base_stuck:.3f} + tolerance {th.stuck_loop_tolerance}",
                        baseline=base_stuck,
                        current=cur_stuck,
                    )
                )
            else:
                result.findings.append(
                    RegressionFinding("unchanged", "stuck_loop_rate", f"{cur_stuck:.3f} vs {base_stuck:.3f}")
                )

    if aggregate_metrics_comparable:
        base_time = baseline.get("median_solve_time")
        cur_time = summary.median_solve_time
        inc = _rel_increase(cur_time, base_time if isinstance(base_time, (int, float)) else None)
        if inc is not None and inc > th.median_time_tolerance:
            result.findings.append(
                RegressionFinding(
                    "warning",
                    "median_solve_time",
                    f"{cur_time:.1f}s (+{inc:.0%} vs baseline {base_time:.1f}s)",
                    baseline=base_time,
                    current=cur_time,
                )
            )
        elif inc is not None and inc < -th.median_time_tolerance:
            result.findings.append(
                RegressionFinding(
                    "improvement",
                    "median_solve_time",
                    f"{cur_time:.1f}s ({inc:.0%})",
                    baseline=base_time,
                    current=cur_time,
                )
            )

        base_actions = baseline.get("median_tool_actions")
        cur_actions = summary.median_tool_actions
        inc = _rel_increase(cur_actions, base_actions if isinstance(base_actions, (int, float)) else None)
        if inc is not None and inc > th.tool_actions_tolerance:
            result.findings.append(
                RegressionFinding(
                    "warning",
                    "median_tool_actions",
                    f"{cur_actions:.0f} (+{inc:.0%} vs baseline {base_actions:.0f})",
                    baseline=base_actions,
                    current=cur_actions,
                )
            )

        base_cost = baseline.get("estimated_cost")
        cur_cost = summary.estimated_cost
        inc = _rel_increase(cur_cost, base_cost if isinstance(base_cost, (int, float)) else None)
        if inc is not None and inc > th.cost_tolerance:
            result.findings.append(
                RegressionFinding(
                    "warning",
                    "estimated_cost",
                    f"{cur_cost:.2f} (+{inc:.0%} vs baseline {base_cost:.2f})",
                    baseline=base_cost,
                    current=cur_cost,
                )
            )
    else:
        detail = "aggregate metrics require the same suite, scenario set, and per-scenario trial counts"
        result.findings.extend(
            RegressionFinding("incomparable", metric, detail)
            for metric in ("median_solve_time", "median_tool_actions", "estimated_cost")
        )

    # Per-scenario: previously solved -> now unsolved is a hard regression,
    # but only when both runs contain the same sample sizes for that scenario.
    scenario_comparison_allowed = bool(summary.suite and summary.suite == baseline.get("suite"))
    scenario_rows = summary.scenarios if scenario_comparison_allowed else []
    for scenario in scenario_rows:
        base_entry = base_scenarios.get(scenario.scenario_id)
        if not isinstance(base_entry, dict):
            continue
        raw_base_prob = base_entry.get("success_probability", 0.0)
        base_prob = _finite_num(raw_base_prob)
        if raw_base_prob is None:
            result.findings.append(
                RegressionFinding(
                    "incomparable",
                    f"scenario:{scenario.scenario_id}",
                    "baseline probability unavailable",
                )
            )
            continue
        if base_prob is None:
            result.findings.append(
                RegressionFinding(
                    "hard",
                    f"scenario:{scenario.scenario_id}",
                    "baseline probability malformed (fail-closed)",
                )
            )
            continue
        if not _scenario_sample_counts_match(scenario, base_entry):
            result.findings.append(
                RegressionFinding(
                    "incomparable",
                    f"scenario:{scenario.scenario_id}",
                    "scenario sample counts differ or are unavailable",
                )
            )
            continue
        current_prob = scenario.success_probability
        if current_prob is None:
            result.findings.append(
                RegressionFinding("incomparable", f"scenario:{scenario.scenario_id}", "current probability unavailable")
            )
            continue
        if base_prob > 0 and current_prob == 0.0:
            result.findings.append(
                RegressionFinding(
                    "hard",
                    f"scenario:{scenario.scenario_id}",
                    f"solved in baseline (p={base_prob:.2f}) but unsolved now (p=0.00)",
                    baseline=base_prob,
                    current=current_prob,
                )
            )
        elif base_prob == 0.0 and current_prob > 0:
            result.findings.append(
                RegressionFinding(
                    "improvement",
                    f"scenario:{scenario.scenario_id}",
                    f"newly solved (p={current_prob:.2f})",
                    baseline=base_prob,
                    current=current_prob,
                )
            )

    result.passed = result.hard_count == 0 and result.incomparable_count == 0
    return result


# ---------------------------------------------------------------------------
# Two-run comparison (WebUI comparison view)
# ---------------------------------------------------------------------------


def compare_summaries_payload(base_summary: dict[str, Any], current_summary: dict[str, Any]) -> dict[str, Any]:
    """Compare two RunSummary dicts (baseline + candidate) into a UI payload.

    Metric rows carry ``baseline``/``current``/``delta`` (+ direction); the
    per-scenario rollup classifies every scenario as newly_solved / regressed /
    still_solved / still_failing. Pure dict-in/dict-out so both the API and
    the CLI can use it.
    """

    def _pct(value: Any) -> float | None:
        return _finite_num(value)

    def _scope_count(summary: dict[str, Any]) -> int | None:
        count = _finite_count(summary.get("scope_violation_count"))
        if count is None:
            return None
        if summary.get("scope_violation_telemetry_available") is True or count > 0:
            return count
        return None

    def _row(
        metric: str,
        base: Any,
        cur: Any,
        *,
        lower_is_better: bool = False,
        comparable: bool = True,
    ) -> dict[str, Any]:
        base_num = _finite_num(base)
        cur_num = _finite_num(cur)
        delta = (cur_num - base_num) if comparable and base_num is not None and cur_num is not None else None
        scope_count = _scope_count(current_summary)
        direction = "unchanged"
        if not comparable:
            direction = "incomparable"
        elif base_num is None or cur_num is None:
            direction = "unavailable"
        elif delta is not None and abs(delta) > 1e-9:
            improved = delta < 0 if lower_is_better else delta > 0
            direction = "improved" if improved else "regressed"
        if metric == "scope_violation_count" and scope_count is not None and scope_count > 0:
            # A measured positive is a regression even when the baseline has
            # no usable count; the safety gate is absolute, not comparative.
            direction = "regressed"
        return {
            "metric": metric,
            "baseline": base_num,
            "current": cur_num,
            "delta": delta,
            "direction": direction,
            **(
                {
                    "safety_gate": (
                        "failed"
                        if scope_count is not None and scope_count > 0
                        else "passed"
                        if current_summary.get("scope_violation_telemetry_available") is True
                        and _scope_count(current_summary) == 0
                        else "unavailable"
                    )
                }
                if metric == "scope_violation_count"
                else {}
            ),
        }

    def _scenario_map(summary: dict[str, Any]) -> dict[str, dict[str, Any]]:
        raw = summary.get("scenarios") or []
        # Serialized RunSummary rows are a list; hand-built payloads may pass a
        # scenario_id -> row dict. Both shapes are accepted.
        if isinstance(raw, dict):
            rows = [
                dict(v, scenario_id=k) if isinstance(v, dict) and not v.get("scenario_id") else v
                for k, v in raw.items()
            ]
        else:
            rows = [s for s in raw if isinstance(s, dict)]
        return {str(s.get("scenario_id", "")): s for s in rows if isinstance(s, dict) and s.get("scenario_id")}

    base_map = _scenario_map(base_summary)
    cur_map = _scenario_map(current_summary)
    same_suite = bool(base_summary.get("suite") and base_summary.get("suite") == current_summary.get("suite"))
    same_scenario_trials = bool(
        base_map
        and cur_map
        and set(base_map) == set(cur_map)
        and all(_scenario_sample_counts_match(cur_map[scenario_id], base_map[scenario_id]) for scenario_id in base_map)
    )
    aggregate_comparable = bool(same_suite and same_scenario_trials)
    base_reproduced_rate = base_summary.get("reproduced_twice_rate") if _has_verified_scenario(base_map) else None
    current_reproduced_rate = current_summary.get("reproduced_twice_rate") if _has_verified_scenario(cur_map) else None

    metrics = [
        _row(
            "verified_success_rate",
            base_summary.get("verified_success_rate"),
            current_summary.get("verified_success_rate"),
            comparable=aggregate_comparable,
        ),
        _row(
            "false_positive_rate",
            base_summary.get("false_positive_rate"),
            current_summary.get("false_positive_rate"),
            lower_is_better=True,
            comparable=aggregate_comparable,
        ),
        _row(
            "stuck_loop_rate",
            base_summary.get("stuck_loop_rate"),
            current_summary.get("stuck_loop_rate"),
            lower_is_better=True,
            comparable=aggregate_comparable,
        ),
        _row(
            "scope_violation_count",
            _scope_count(base_summary),
            _scope_count(current_summary),
            lower_is_better=True,
            # This is an absolute safety gate, not an estimated rate. Always
            # surface positive observations, but never treat an unattested
            # legacy zero as measured evidence.
            comparable=base_summary.get("scope_violation_telemetry_available") is True
            and current_summary.get("scope_violation_telemetry_available") is True,
        ),
        _row(
            "reproduced_twice_rate",
            base_reproduced_rate,
            current_reproduced_rate,
            comparable=aggregate_comparable,
        ),
        _row(
            "median_solve_time",
            base_summary.get("median_solve_time"),
            current_summary.get("median_solve_time"),
            lower_is_better=True,
            comparable=aggregate_comparable,
        ),
        _row(
            "median_tool_actions",
            base_summary.get("median_tool_actions"),
            current_summary.get("median_tool_actions"),
            lower_is_better=True,
            comparable=aggregate_comparable,
        ),
        _row(
            "estimated_cost",
            base_summary.get("estimated_cost"),
            current_summary.get("estimated_cost"),
            lower_is_better=True,
            comparable=aggregate_comparable,
        ),
        _row(
            "total_tokens",
            base_summary.get("total_tokens"),
            current_summary.get("total_tokens"),
            lower_is_better=True,
            comparable=aggregate_comparable,
        ),
        _row(
            "solved",
            base_summary.get("solved"),
            current_summary.get("solved"),
            comparable=aggregate_comparable,
        ),
        _row(
            "infra_error_count",
            base_summary.get("infra_error_count"),
            current_summary.get("infra_error_count"),
            lower_is_better=True,
            comparable=aggregate_comparable,
        ),
    ]
    per_scenario: dict[str, list[str]] = {
        "newly_solved": [],
        "regressed": [],
        "still_solved": [],
        "still_failing": [],
        "not_compared": [],
    }
    scenario_rows: list[dict[str, Any]] = []
    for scenario_id in sorted(set(base_map) | set(cur_map)):
        base_sc = base_map.get(scenario_id)
        cur_sc = cur_map.get(scenario_id)
        if not isinstance(base_sc, dict):
            base_sc = None
        if not isinstance(cur_sc, dict):
            cur_sc = None
        base_prob = _pct(base_sc.get("success_probability")) if base_sc is not None else None
        cur_prob = _pct(cur_sc.get("success_probability")) if cur_sc is not None else None
        sample_counts_match = (
            base_sc is not None and cur_sc is not None and _scenario_sample_counts_match(cur_sc, base_sc)
        )
        if not same_suite or base_prob is None or cur_prob is None or not sample_counts_match:
            category = "not_compared"
        elif base_prob == 0 and cur_prob > 0:
            category = "newly_solved"
        elif base_prob > 0 and cur_prob == 0:
            category = "regressed"
        elif base_prob > 0 and cur_prob > 0:
            category = "still_solved"
        else:
            category = "still_failing"
        per_scenario[category].append(scenario_id)
        delta = None
        if category != "not_compared" and base_prob is not None and cur_prob is not None:
            delta = cur_prob - base_prob
        scenario_rows.append(
            {
                "scenario_id": scenario_id,
                "baseline": base_prob,
                "current": cur_prob,
                "delta": delta,
                "category": category,
            }
        )
    return {
        "metrics": metrics,
        "scenarios": scenario_rows,
        "categories": per_scenario,
    }
