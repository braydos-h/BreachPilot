"""P2-05: telemetry O(1) aggregation parity (no unbounded list)."""

from __future__ import annotations

import json


def _line(ctx: float) -> str:
    return (
        json.dumps(
            {
                "total_tokens": 100,
                "context_usage_pct": ctx,
                "context_window_tokens": 128000,
                "estimated_context_tokens": 5000,
            }
        )
        + "\n"
    )


def test_telemetry_o1_parity(tmp_path):
    from tools.run_service.prepare import _TelemetryAccumulator

    path = tmp_path / "llm_usage.jsonl"
    acc = _TelemetryAccumulator(path)
    assert not hasattr(acc, "_ctx_values"), "unbounded _ctx_values list must be gone"
    values = [10.0, 50.0, 90.0, 25.0, 75.0]
    with path.open("a", encoding="utf-8") as f:
        f.writelines([_line(v) for v in values])
    snap = acc.snapshot()
    assert snap is not None
    assert snap["calls"] == 5
    assert snap["total_tokens"] == 500
    assert abs(snap["avg_ctx"] - (sum(values) / len(values))) < 1e-9
    assert snap["max_ctx"] == 90.0
    # Empty accumulator keeps max None (not 0.0).
    acc2 = _TelemetryAccumulator(tmp_path / "missing.jsonl")
    assert acc2.snapshot() is None


def test_telemetry_truncation_resets(tmp_path):
    from tools.run_service.prepare import _TelemetryAccumulator

    path = tmp_path / "llm_usage.jsonl"
    path.write_text(_line(80.0), encoding="utf-8")
    acc = _TelemetryAccumulator(path)
    # Constructor starts at current EOF; append + snapshot.
    with path.open("a", encoding="utf-8") as f:
        f.write(_line(20.0))
    snap = acc.snapshot()
    assert snap is not None and snap["max_ctx"] == 20.0
    # Truncate: counters reset together.
    path.write_text(_line(60.0), encoding="utf-8")
    snap2 = acc.snapshot()
    assert snap2 is not None
    assert snap2["calls"] == 1 and snap2["max_ctx"] == 60.0 and snap2["avg_ctx"] == 60.0
