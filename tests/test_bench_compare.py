"""P3-02: bench_compare threshold logic on fixture JSONs (no live I/O)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from bench_compare import DEFAULT_TOLERANCE, compare


def _doc(replay_p95: float, emit_p95: float = 1.0) -> dict:
    return {
        "metadata": {"host": "test", "python": "3.11", "timestamp": "2026-09-22T00:00:00Z"},
        "scenarios": {
            "event_replay_ms": {"p50": 90.0, "p95": replay_p95, "p99": 120.0, "n": 3},
            "event_emit_ms": {"p50": 0.8, "p95": emit_p95, "p99": 1.2, "n": 1000},
        },
    }


def test_no_regression_within_tolerance(tmp_path: Path) -> None:
    base = tmp_path / "base.json"
    cur = tmp_path / "cur.json"
    base.write_text(json.dumps(_doc(100.0)), encoding="utf-8")
    cur.write_text(json.dumps(_doc(110.0)), encoding="utf-8")  # +10% < 15%
    regressions = compare(base, cur)
    assert regressions == []


def test_p95_regression_over_tolerance_detected(tmp_path: Path) -> None:
    base = tmp_path / "base.json"
    cur = tmp_path / "cur.json"
    base.write_text(json.dumps(_doc(100.0)), encoding="utf-8")
    cur.write_text(json.dumps(_doc(130.0)), encoding="utf-8")  # +30% > 15%
    regressions = compare(base, cur)
    assert len(regressions) == 1
    assert regressions[0]["metric"] == "event_replay_ms"
    assert regressions[0]["baseline_p95"] == 100.0
    assert regressions[0]["current_p95"] == 130.0


def test_improvement_is_not_regression(tmp_path: Path) -> None:
    base = tmp_path / "base.json"
    cur = tmp_path / "cur.json"
    base.write_text(json.dumps(_doc(100.0)), encoding="utf-8")
    cur.write_text(json.dumps(_doc(50.0)), encoding="utf-8")
    assert compare(base, cur) == []


def test_missing_metric_skipped_not_failed(tmp_path: Path) -> None:
    base = tmp_path / "base.json"
    cur = tmp_path / "cur.json"
    base.write_text(json.dumps(_doc(100.0)), encoding="utf-8")
    doc = _doc(100.0)
    doc["scenarios"].pop("event_emit_ms")
    cur.write_text(json.dumps(doc), encoding="utf-8")
    assert compare(base, cur) == []


def test_default_tolerance_is_fifteen_percent() -> None:
    assert DEFAULT_TOLERANCE == 0.15
