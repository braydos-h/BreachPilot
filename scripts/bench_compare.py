#!/usr/bin/env python3
"""Compare a current benchmark JSON doc against a checked-in baseline.

Fails (exit 1) when any pinned metric's p95 regresses by more than
``--tolerance`` (default 15%). Improvements and missing metrics never fail;
missing metrics are reported as skipped so apple-to-apple drift stays visible.

Usage:
    python3 scripts/bench_compare.py benchmarks/baseline.json /tmp/current.json
    python3 scripts/bench_compare.py baseline.json current.json --tolerance 0.2 --json out.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

DEFAULT_TOLERANCE = 0.15


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _scenarios(doc: dict[str, Any]) -> dict[str, Any]:
    scenarios = doc.get("scenarios")
    return scenarios if isinstance(scenarios, dict) else {}


def compare(
    baseline_path: Path,
    current_path: Path,
    tolerance: float = DEFAULT_TOLERANCE,
) -> list[dict[str, Any]]:
    """Return one row per regressed metric (empty list = no regression)."""
    baseline = _scenarios(_load(baseline_path))
    current = _scenarios(_load(current_path))
    regressions: list[dict[str, Any]] = []
    for name, base_stats in baseline.items():
        if not isinstance(base_stats, dict):
            continue
        cur_stats = current.get(name)
        if not isinstance(cur_stats, dict):
            continue
        try:
            base_p95 = float(base_stats["p95"])
            cur_p95 = float(cur_stats["p95"])
        except (KeyError, TypeError, ValueError):
            continue
        if base_p95 <= 0:
            continue
        delta = (cur_p95 - base_p95) / base_p95
        if delta > tolerance:
            regressions.append(
                {
                    "metric": name,
                    "baseline_p95": base_p95,
                    "current_p95": cur_p95,
                    "delta_pct": round(delta * 100.0, 2),
                    "tolerance_pct": round(tolerance * 100.0, 2),
                }
            )
    return regressions


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fail on >tolerance p95 benchmark regression.")
    parser.add_argument("baseline", type=Path)
    parser.add_argument("current", type=Path)
    parser.add_argument("--tolerance", type=float, default=DEFAULT_TOLERANCE)
    parser.add_argument("--json", type=Path, default=None, help="Write regression rows as JSON.")
    args = parser.parse_args(argv)

    regressions = compare(args.baseline, args.current, args.tolerance)
    baseline = _scenarios(_load(args.baseline))
    current = _scenarios(_load(args.current))
    skipped = sorted(set(baseline) - set(current))
    print(f"compared {len(baseline)} baseline metrics vs {len(current)} current metrics")
    for name in sorted(set(baseline) & set(current)):
        base_stats = baseline[name]
        cur_stats = current[name]
        if isinstance(base_stats, dict) and isinstance(cur_stats, dict):
            try:
                delta = (float(cur_stats["p95"]) - float(base_stats["p95"])) / float(base_stats["p95"]) * 100.0
                flag = "  REGRESSION" if any(r["metric"] == name for r in regressions) else ""
                print(
                    f"  {name}: baseline p95={base_stats['p95']} current p95={cur_stats['p95']} ({delta:+.1f}%){flag}"
                )
            except (KeyError, TypeError, ValueError, ZeroDivisionError):
                print(f"  {name}: unreadable p95, skipped")
    for name in skipped:
        print(f"  {name}: missing from current run, skipped (not a failure)")
    if args.json is not None:
        args.json.write_text(json.dumps(regressions, indent=2) + "\n", encoding="utf-8")
    if regressions:
        print(f"FAIL: {len(regressions)} metric(s) regressed beyond {args.tolerance * 100:.0f}% p95 tolerance")
        return 1
    print("OK: no p95 regression beyond tolerance")
    return 0


if __name__ == "__main__":
    sys.exit(main())
