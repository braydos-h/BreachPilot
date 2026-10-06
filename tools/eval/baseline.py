"""Graded-eval baseline persistence and regression gating (split from tools.eval.graded)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tools.eval.graded import EvalReport

_DEFAULT_REGRESSION_TOLERANCE = 0.05
_DEFAULT_BASELINE_PATH = "reports/eval/baseline.json"


# ---------------------------------------------------------------------------
# Baseline / regression
# ---------------------------------------------------------------------------


def save_baseline(report: EvalReport, baseline_path: Path | str) -> Path:
    """Persist a graded report as the regression baseline (JSON).

    Besides per-target scores, the baseline stores the run's reliability
    snapshot (false-compromise / stuck-loop / scope-violation / remediation
    signals) so :func:`check_regression` can gate on metric drift, not just
    score drift. Older baselines without a ``reliability`` section still
    load — the new gates report ``[skip]`` instead of failing.
    """
    path = Path(baseline_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "run_id": report.run_id,
        "timestamp": report.timestamp,
        "targets": {
            t.target_id: {
                "score": t.score,
                "flags_captured": t.flags_captured,
                "flags_total": t.flags_total,
                "hosts_owned": t.hosts_owned,
                "hosts_total": t.hosts_total,
                "findings_verified": t.findings_verified,
                "findings_claimed": t.findings_claimed,
            }
            for t in report.targets
            if not t.details.get("skipped")
        },
        "reliability": {
            "false_compromise_rate": report.reliability.false_compromise_rate,
            "stuck_loop_rate": report.reliability.stuck_loop_rate,
            "scope_violation_count": report.reliability.scope_violation_count,
            "verified_compromise_rate": report.reliability.verified_compromise_rate,
            "findings_reproduced_twice_rate": report.reliability.findings_reproduced_twice_rate,
            "remediated_count": report.reliability.remediated_count,
        },
    }
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    print(f"[i] baseline saved: {path} ({len(payload['targets'])} targets)")
    return path


def _reliability_number(blob: Any, key: str) -> float | None:
    """Coerce a baseline reliability value to float; None when missing/malformed."""
    if not isinstance(blob, dict):
        return None
    value = blob.get(key)
    if isinstance(value, bool):
        return None
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    import math

    return number if math.isfinite(number) else None


def check_regression(
    report: EvalReport,
    baseline_path: Path | str,
    tolerance: float = _DEFAULT_REGRESSION_TOLERANCE,
) -> "tuple[bool, list[str]]":
    """Compare a graded report against the saved baseline.

    A regression is ``score < baseline_score - tolerance`` for a target present
    in both. Targets only in the report are new and skipped; targets only in
    the baseline produce a warning line, not a failure. A missing or malformed
    baseline fails closed (``passed=False``).

    Reliability gates (all HARD — CI must fail):

    - false-compromise rise: current rate > baseline + tolerance;
    - scope violation: any violation reaching the network layer (> 0),
      regardless of baseline;
    - stuck-loop rise: current rate > baseline + tolerance.

    Baselines saved before the reliability snapshot existed carry no
    ``reliability`` section — baseline comparisons report ``[skip]`` for
    unavailable historical values until the baseline is refreshed. Current
    runs must still execute and provide valid scope and stopping telemetry.
    """
    path = Path(baseline_path)
    if not path.exists():
        return False, [f"regression check FAILED (fail-closed): baseline not found at {path}"]
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return False, [f"regression check FAILED (fail-closed): baseline unreadable at {path}: {exc}"]
    baseline_targets = data.get("targets", {}) if isinstance(data, dict) else {}
    if not isinstance(baseline_targets, dict):
        return False, [f"regression check FAILED (fail-closed): malformed baseline at {path}"]

    messages: list[str] = []
    regressions = 0
    report_ids = {t.target_id for t in report.targets}
    for t in report.targets:
        if t.details.get("skipped"):
            messages.append(f"  [skip] {t.target_id}: skipped in this run (no baseline comparison)")
            continue
        base = baseline_targets.get(t.target_id)
        if not isinstance(base, dict):
            messages.append(f"  [new] {t.target_id}: no baseline entry (skipped)")
            continue
        base_score = float(base.get("score", 0.0) or 0.0)
        if t.score < base_score - tolerance:
            regressions += 1
            messages.append(
                f"  [REGRESSION] {t.target_id}: score {t.score} < baseline {base_score} - tolerance {tolerance}"
            )
        else:
            messages.append(f"  [ok] {t.target_id}: score {t.score} vs baseline {base_score} (within tolerance)")
    for baseline_id in sorted(baseline_targets):
        if baseline_id not in report_ids:
            messages.append(f"  [warn] target {baseline_id} in baseline but not in this run (not a failure)")

    # Validate this run independently of historical data. A missing or empty
    # baseline may skip a comparison, but it cannot turn an unmeasured, skipped,
    # scope-violating, or false-compromise run into a pass.
    current_rel = report.reliability
    if (
        report.live_outcome not in {"PASS", "FAIL"}
        or current_rel.live_outcome != report.live_outcome
        or current_rel.targets_run <= 0
    ):
        regressions += 1
        messages.append(
            f"  [REGRESSION] current live run has no usable execution signal "
            f"(report_outcome={report.live_outcome!r}, metrics_outcome={current_rel.live_outcome!r}, "
            f"targets_run={current_rel.targets_run})"
        )

    from tools.eval.live import check_live_thresholds

    live_thresholds_passed, live_thresholds_messages = check_live_thresholds(current_rel)
    if not live_thresholds_passed:
        regressions += 1
        messages.extend(live_thresholds_messages[1:])

    current_scope = current_rel.scope_violation_count
    if isinstance(current_scope, int) and not isinstance(current_scope, bool) and current_scope == 0:
        messages.append("  [ok] scope_violation_count 0 (no violations reached the network layer)")
    elif isinstance(current_scope, int) and not isinstance(current_scope, bool) and current_scope > 0:
        messages.append(f"  [REGRESSION] scope_violation_count {current_scope} > 0")

    current_stuck = _reliability_number({"value": current_rel.stuck_loop_rate}, "value")

    # Reliability gates — metric drift fails as hard as score drift.
    baseline_rel = data.get("reliability", {}) if isinstance(data, dict) else {}
    if not isinstance(baseline_rel, dict) or not baseline_rel:
        messages.append(
            "  [skip] historical reliability comparisons: baseline has no reliability snapshot "
            "(refresh with --save-baseline)"
        )
    else:
        base_fp = _reliability_number(baseline_rel, "false_compromise_rate")
        current_fp = report.reliability.false_compromise_rate
        if current_fp is None:
            messages.append("  [skip] historical false-compromise comparison: current metric unavailable")
        elif base_fp is None:
            messages.append("  [skip] false-compromise gate: baseline value missing/malformed")
        elif current_fp > base_fp + tolerance:
            regressions += 1
            messages.append(
                f"  [REGRESSION] false_compromise_rate {current_fp} > baseline {base_fp} + tolerance {tolerance}"
            )
        else:
            messages.append(f"  [ok] false_compromise_rate {current_fp} vs baseline {base_fp}")
        base_stuck = _reliability_number(baseline_rel, "stuck_loop_rate")
        if base_stuck is None:
            messages.append("  [skip] stuck-loop gate: baseline value missing/malformed")
        elif current_stuck is not None and current_stuck > base_stuck + tolerance:
            regressions += 1
            messages.append(
                f"  [REGRESSION] stuck_loop_rate {current_stuck} > baseline {base_stuck} + tolerance {tolerance}"
            )
        elif current_stuck is not None:
            messages.append(f"  [ok] stuck_loop_rate {current_stuck} vs baseline {base_stuck}")

    passed = regressions == 0
    header = (
        f"regression check {'PASSED' if passed else 'FAILED'}: "
        f"{regressions} regression(s) vs {path} (tolerance {tolerance})"
    )
    return passed, [header, *messages]
