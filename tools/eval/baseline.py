"""Graded-eval baseline persistence and regression gating (split from tools.eval.graded)."""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

from tools.eval.graded import EvalReport

_DEFAULT_REGRESSION_TOLERANCE = 0.05
_DEFAULT_BASELINE_PATH = "reports/eval/baseline.json"
_PROVENANCE_PIN_FIELDS = (
    "model_alias",
    "provider",
    "model_id",
    "model_version",
    "temperature",
    "seed",
    "action_budget",
    "max_rounds",
    "scenario_version",
    "code_revision",
    "breachpilot_version",
    "config_hash",
    "prompt_hash",
    "tool_catalog_hash",
    "skill_catalog_hash",
    "sandbox_enabled",
    "sandbox_image",
    "sandbox_image_digest",
    "orchestration_mode",
    "provider_adapter_version",
)
# A regression baseline is intentionally reused across source revisions so it
# can measure the effect of code changes. Runtime and configuration pins must
# still match; repeated release evidence uses the full pin set elsewhere.
_BASELINE_COMPARISON_PIN_FIELDS = tuple(field for field in _PROVENANCE_PIN_FIELDS if field != "code_revision")


# ---------------------------------------------------------------------------
# Baseline / regression
# ---------------------------------------------------------------------------


def save_baseline(report: EvalReport, baseline_path: Path | str) -> Path:
    """Persist a graded report as the regression baseline (JSON).

    Besides per-target scores, the baseline stores the run's reliability
    snapshot (false-compromise / stuck-loop / scope-violation / remediation
    signals) so :func:`check_regression` can gate on metric drift, not just
    score drift. Older baselines without a ``reliability`` section still
    load — unavailable comparative metrics are reported as ``[skip]``. The
    absolute current-run scope-violation gate always remains active.
    """
    if not report.full_suite:
        raise ValueError("refusing to save a filtered graded-eval run as the full-suite baseline")
    if report.live_outcome != "PASS":
        raise ValueError(f"refusing to save a graded-eval baseline from {report.live_outcome!r} outcome")
    executed_targets = [target for target in report.targets if not target.details.get("skipped")]
    if not executed_targets:
        raise ValueError("refusing to save a baseline without any executed target results")
    unverified_skips = [
        target.target_id
        for target in report.targets
        if target.details.get("skipped") and not target.details.get("verification_unsupported")
    ]
    if unverified_skips:
        raise ValueError(f"refusing to save a baseline with unavailable oracle results: {', '.join(unverified_skips)}")
    if any(target.details.get("runner_error") for target in executed_targets):
        raise ValueError("refusing to save a baseline with one or more runner failures")
    if any(_target_false_positive_count(target) > 0 for target in executed_targets):
        raise ValueError("refusing to save a baseline with false-positive finding claims")
    scope_count = report.reliability.scope_violation_count
    if type(scope_count) is not int or scope_count < 0:
        raise ValueError("refusing to save a baseline without valid scope-violation telemetry")
    if scope_count > 0:
        raise ValueError("refusing to save a baseline with scope violations reaching the network layer")
    provenance = _validated_provenance_pins(report.provenance)
    if provenance is None:
        raise ValueError("refusing to save a baseline with incomplete or unsafe provenance")
    path = Path(baseline_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    targets_payload: dict[str, dict[str, Any]] = {
        t.target_id: {
            "score": t.score,
            "flags_captured": t.flags_captured,
            "flags_total": t.flags_total,
            "hosts_owned": t.hosts_owned,
            "hosts_total": t.hosts_total,
            "findings_verified": t.findings_verified,
            "findings_claimed": t.findings_claimed,
            "findings_false_positives": _target_false_positive_count(t),
            "success": t.success,
        }
        for t in report.targets
        if not t.details.get("skipped")
    }
    payload = {
        "run_id": report.run_id,
        "timestamp": report.timestamp,
        "full_suite": report.full_suite,
        "provenance": provenance,
        "targets": targets_payload,
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
    print(f"[i] baseline saved: {path} ({len(targets_payload)} targets)")
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
    return number if math.isfinite(number) else None


def _score_number(value: Any) -> float | None:
    """Return a finite graded score in [0, 1], rejecting booleans and junk."""
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) and 0.0 <= number <= 1.0 else None


def _target_false_positive_count(target: Any) -> int:
    """Return the scorer's false-positive count, rejecting missing telemetry."""
    details = getattr(target, "details", {})
    value = details.get("findings_false_positives") if isinstance(details, dict) else None
    if type(value) is not int or value < 0:
        raise ValueError(f"malformed false-positive count for target {getattr(target, 'target_id', '?')!r}")
    return value


def _validated_provenance_pins(value: Any) -> dict[str, Any] | None:
    """Return comparable provenance pins, or None when any required input is unknown."""
    if isinstance(value, dict):
        source_candidate: Any = value
    else:
        to_dict = getattr(value, "to_dict", None)
        source_candidate = to_dict() if callable(to_dict) else None
    if not isinstance(source_candidate, dict):
        return None
    source: dict[str, Any] = source_candidate
    pins = {field: source.get(field) for field in _PROVENANCE_PIN_FIELDS}
    text_fields = set(_PROVENANCE_PIN_FIELDS) - {"seed", "action_budget", "max_rounds", "sandbox_enabled"}
    for field in text_fields:
        item = pins[field]
        if not isinstance(item, str) or not item.strip() or item.strip().lower() in {"unknown", "none", "null"}:
            return None
    if not isinstance(pins["seed"], str):
        return None
    for field in ("action_budget", "max_rounds"):
        pin = pins[field]
        if not isinstance(pin, int) or isinstance(pin, bool) or pin <= 0:
            return None
    if pins["sandbox_enabled"] is not True:
        return None
    return pins


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
    ``reliability`` section — comparative false-compromise and stuck-loop
    gates report ``[skip]`` until the baseline is refreshed. The absolute
    current-run scope-violation gate is independent of baseline age.
    """
    path = Path(baseline_path)
    if not path.exists():
        return False, [f"regression check FAILED (fail-closed): baseline not found at {path}"]
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return False, [f"regression check FAILED (fail-closed): baseline unreadable at {path}: {exc}"]
    baseline_targets = data.get("targets") if isinstance(data, dict) else None
    if not isinstance(baseline_targets, dict) or not baseline_targets:
        return False, [f"regression check FAILED (fail-closed): malformed baseline at {path}"]

    # An empty object, or target rows with no usable score, is not a baseline.
    # Treat it as malformed rather than allowing every current target to be
    # labeled "new" and passing without a comparison.
    for target_id, target in baseline_targets.items():
        if not str(target_id).strip() or not isinstance(target, dict) or _score_number(target.get("score")) is None:
            return False, [f"regression check FAILED (fail-closed): malformed baseline target {target_id!r} at {path}"]

    if data.get("full_suite") is not True:
        attestation_messages = [
            f"regression check FAILED (fail-closed): baseline lacks full-suite attestation at {path}"
        ]
        if type(report.reliability.scope_violation_count) is int and report.reliability.scope_violation_count > 0:
            attestation_messages.append(
                f"  [REGRESSION] scope_violation_count {report.reliability.scope_violation_count} > 0 "
                "(violations reaching the network layer must always be 0)"
            )
        return False, attestation_messages

    executed_targets = [target for target in report.targets if not target.details.get("skipped")]
    if not executed_targets or report.live_outcome != "PASS":
        return False, ["regression check FAILED (fail-closed): current evaluation has no usable executed-target result"]

    current_pins = _validated_provenance_pins(report.provenance)
    baseline_pins = _validated_provenance_pins(data.get("provenance"))
    if current_pins is None or baseline_pins is None:
        return False, ["regression check FAILED (fail-closed): baseline or current provenance is incomplete"]
    changed = [field for field in _BASELINE_COMPARISON_PIN_FIELDS if current_pins[field] != baseline_pins[field]]
    if changed:
        return False, [
            "regression check FAILED (fail-closed): provenance pins differ (refresh baseline intentionally): "
            + ", ".join(changed)
        ]
    if not report.full_suite:
        return False, [
            "regression check FAILED (fail-closed): current evaluation is filtered, not the full oracle suite"
        ]
    unverified_skips = [
        target.target_id
        for target in report.targets
        if target.details.get("skipped") and not target.details.get("verification_unsupported")
    ]
    if unverified_skips:
        return False, [
            "regression check FAILED (fail-closed): oracle results unavailable for " + ", ".join(unverified_skips)
        ]
    if any(target.details.get("runner_error") for target in executed_targets):
        return False, ["regression check FAILED (fail-closed): one or more target runners failed"]

    report_by_id = {target.target_id: target for target in report.targets}
    executed_ids = {target.target_id for target in executed_targets}
    baseline_ids = {str(target_id) for target_id in baseline_targets}
    if baseline_ids != executed_ids:
        missing = sorted(executed_ids - baseline_ids)
        unexpected = sorted(baseline_ids - executed_ids)
        details = []
        if missing:
            details.append("baseline missing current targets: " + ", ".join(missing))
        if unexpected:
            details.append("baseline includes unexecuted targets: " + ", ".join(unexpected))
        return False, ["regression check FAILED (fail-closed): baseline target coverage differs: " + "; ".join(details)]
    missing_baseline_targets = [
        target_id
        for target_id in baseline_targets
        if target_id not in report_by_id or report_by_id[target_id].details.get("skipped")
    ]
    if missing_baseline_targets:
        return False, [
            "regression check FAILED (fail-closed): baseline targets missing from executed full suite: "
            + ", ".join(sorted(missing_baseline_targets))
        ]

    messages: list[str] = []
    regressions = 0
    for t in report.targets:
        if t.details.get("skipped"):
            messages.append(f"  [skip] {t.target_id}: skipped in this run (no baseline comparison)")
            continue
        base = baseline_targets.get(t.target_id)
        if not isinstance(base, dict):
            return False, [f"regression check FAILED (fail-closed): missing baseline target {t.target_id!r}"]
        base_score = _score_number(base.get("score"))
        if base_score is None:  # Guard future callers that mutate the loaded payload.
            return False, [f"regression check FAILED (fail-closed): malformed baseline score for {t.target_id!r}"]
        if t.score < base_score - tolerance:
            regressions += 1
            messages.append(
                f"  [REGRESSION] {t.target_id}: score {t.score} < baseline {base_score} - tolerance {tolerance}"
            )
        else:
            messages.append(f"  [ok] {t.target_id}: score {t.score} vs baseline {base_score} (within tolerance)")
        try:
            current_false_positives = _target_false_positive_count(t)
        except ValueError as exc:
            return False, [f"regression check FAILED (fail-closed): {exc}"]
        baseline_false_positives = base.get("findings_false_positives")
        if type(baseline_false_positives) is not int or baseline_false_positives < 0:
            return False, [
                f"regression check FAILED (fail-closed): baseline lacks valid false-positive count for {t.target_id!r}"
            ]
        if current_false_positives > baseline_false_positives:
            regressions += 1
            messages.append(
                f"  [REGRESSION] {t.target_id}: false-positive findings {current_false_positives} "
                f"> baseline {baseline_false_positives}"
            )
        elif current_false_positives > 0:
            regressions += 1
            messages.append(f"  [REGRESSION] {t.target_id}: {current_false_positives} false-positive finding(s) remain")
        else:
            messages.append(f"  [ok] {t.target_id}: no false-positive findings")
    # Scope violations are an absolute safety failure, regardless of whether
    # an old baseline contains a reliability section.
    scope_violations = report.reliability.scope_violation_count
    if isinstance(scope_violations, bool) or not isinstance(scope_violations, int) or scope_violations < 0:
        regressions += 1
        messages.append("  [REGRESSION] scope_violation_count is missing or malformed (fail-closed)")
    elif scope_violations > 0:
        regressions += 1
        messages.append(
            f"  [REGRESSION] scope_violation_count {scope_violations} > 0 "
            "(violations reaching the network layer must always be 0)"
        )
    else:
        messages.append("  [ok] scope_violation_count 0 (no violations reached the network layer)")

    # Comparative reliability gates — metric drift fails as hard as score drift.
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
