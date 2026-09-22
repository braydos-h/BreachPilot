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
    ``reliability`` section — those gates report ``[skip]`` (never a failure)
    until the baseline is refreshed with ``--save-baseline``.
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

    # Reliability gates — metric drift fails as hard as score drift.
    baseline_rel = data.get("reliability", {}) if isinstance(data, dict) else {}
    if not isinstance(baseline_rel, dict) or not baseline_rel:
        messages.append(
            "  [skip] reliability gates: baseline has no reliability snapshot (refresh with --save-baseline)"
        )
    else:
        base_fp = _reliability_number(baseline_rel, "false_compromise_rate")
        if base_fp is None:
            messages.append("  [skip] false-compromise gate: baseline value missing/malformed")
        elif report.reliability.false_compromise_rate > base_fp + tolerance:
            regressions += 1
            messages.append(
                f"  [REGRESSION] false_compromise_rate {report.reliability.false_compromise_rate} "
                f"> baseline {base_fp} + tolerance {tolerance}"
            )
        else:
            messages.append(
                f"  [ok] false_compromise_rate {report.reliability.false_compromise_rate} vs baseline {base_fp}"
            )
        if report.reliability.scope_violation_count > 0:
            regressions += 1
            messages.append(
                f"  [REGRESSION] scope_violation_count {report.reliability.scope_violation_count} > 0 "
                "(violations reaching the network layer must always be 0)"
            )
        else:
            messages.append("  [ok] scope_violation_count 0 (no violations reached the network layer)")
        base_stuck = _reliability_number(baseline_rel, "stuck_loop_rate")
        if base_stuck is None:
            messages.append("  [skip] stuck-loop gate: baseline value missing/malformed")
        elif report.reliability.stuck_loop_rate > base_stuck + tolerance:
            regressions += 1
            messages.append(
                f"  [REGRESSION] stuck_loop_rate {report.reliability.stuck_loop_rate} "
                f"> baseline {base_stuck} + tolerance {tolerance}"
            )
        else:
            messages.append(f"  [ok] stuck_loop_rate {report.reliability.stuck_loop_rate} vs baseline {base_stuck}")

    passed = regressions == 0
    header = (
        f"regression check {'PASSED' if passed else 'FAILED'}: "
        f"{regressions} regression(s) vs {path} (tolerance {tolerance})"
    )
    return passed, [header, *messages]
