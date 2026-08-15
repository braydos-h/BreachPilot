#!/usr/bin/env python3
"""Benchmark the WebUI event/persistence hot paths.

Self-contained, stdlib-only harness. Runs against a throwaway
``tempfile.TemporaryDirectory`` so it never touches real ``reports/``.

Usage:
    python scripts/benchmark_webui.py

Prints p50/p95/p99 latencies + throughput for:
  - RunEventBroker emit + replay (256/1k/10k/100k events, 1 KB / 16 KB payloads)
  - ApiPersistence create_run / list_runs / get_run (1 MB result_json)
  - _TelemetryAccumulator.snapshot over an appended llm_usage.jsonl
  - exploit_audit.jsonl read (mirrors GET /runs/{id}/audit)
"""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import time
from pathlib import Path

# Make ``tools`` importable when run from anywhere (repo root is two levels up).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# ── Code under test (guarded: a missing symbol prints "skipped") ──────────
try:
    from tools.api.event_broker import RunEventBroker
except Exception as _exc:  # noqa: BLE001
    RunEventBroker = None
    _EVENT_BROKER_ERR = _exc
else:
    _EVENT_BROKER_ERR = None

try:
    from tools.api.persistence import ApiPersistence
except Exception as _exc:  # noqa: BLE001
    ApiPersistence = None
    _PERSISTENCE_ERR = _exc
else:
    _PERSISTENCE_ERR = None

try:
    from tools.run_service.service import _TelemetryAccumulator
except Exception as _exc:  # noqa: BLE001
    _TelemetryAccumulator = None
    _TELEMETRY_ERR = _exc
else:
    _TELEMETRY_ERR = None


def _pct(samples: list[float]) -> tuple[float, float, float]:
    """Return (p50, p95, p99) using nearest-rank on sorted samples."""
    if not samples:
        return (0.0, 0.0, 0.0)
    s = sorted(samples)
    n = len(s)

    def at(q: float) -> float:
        return s[min(n - 1, int(q * (n - 1)))]

    return at(0.50), at(0.95), at(0.99)


# ── Event broker ───────────────────────────────────────────────────────────

async def _bench_events(reports_dir: Path, n: int, payload_size: int):
    payload = {"data": "x" * payload_size}
    broker = RunEventBroker("bench", reports_dir)
    latencies: list[float] = []
    for _ in range(n):
        t0 = time.perf_counter()
        await broker.emit("bench", payload)
        latencies.append(time.perf_counter() - t0)
    total = sum(latencies)
    throughput = n / total if total else 0.0
    t0 = time.perf_counter()
    events = await broker.replay(0)
    replay_ms = (time.perf_counter() - t0) * 1000.0
    broker.close()
    p50, p95, p99 = _pct([x * 1000.0 for x in latencies])
    return throughput, p50, p95, p99, replay_ms, len(events)


def _run_events(tmp: Path) -> None:
    if RunEventBroker is None:
        print(f"event broker: skipped ({_EVENT_BROKER_ERR})")
        return
    print("Event broker (emit + replay):")
    print(f"  {'events':>8} {'payload':>8} {'emit/s':>10} "
          f"{'p50 ms':>8} {'p95 ms':>8} {'p99 ms':>8} {'replay ms':>10}")
    for n in (256, 1_000, 10_000, 100_000):
        for size in (1024, 16 * 1024):
            sub = tmp / f"events-{n}-{size}"
            sub.mkdir(parents=True, exist_ok=True)
            throughput, p50, p95, p99, replay_ms, count = asyncio.run(
                _bench_events(sub, n, size)
            )
            print(f"  {n:>8} {size:>8} {throughput:>10.0f} "
                  f"{p50:>8.3f} {p95:>8.3f} {p99:>8.3f} {replay_ms:>10.1f}")


# ── Persistence ────────────────────────────────────────────────────────────

def _run_persistence(tmp: Path) -> None:
    if ApiPersistence is None:
        print(f"persistence: skipped ({_PERSISTENCE_ERR})")
        return
    ps = ApiPersistence(tmp / "persist")
    big_result = {"records": [{"id": i, "data": "x" * 200} for i in range(5000)]}
    n_runs = 10
    t0 = time.perf_counter()
    for i in range(n_runs):
        ps.create_run(
            run_id=f"bench-{i}",
            request={"target": "10.0.0.1"},
            preview={"goal": "recon"},
        )
    create_ms = (time.perf_counter() - t0) / n_runs * 1000.0
    for i in range(n_runs):
        ps.update_run_state(f"bench-{i}", "completed", result=big_result)
    t0 = time.perf_counter()
    rows = ps.list_runs(limit=50)
    list_ms = (time.perf_counter() - t0) * 1000.0
    t0 = time.perf_counter()
    run = ps.get_run("bench-0")
    get_ms = (time.perf_counter() - t0) * 1000.0
    print("Persistence (1 MB result_json):")
    print(f"  create_run: {create_ms:.3f} ms/run ({n_runs} runs)")
    print(f"  list_runs : {list_ms:.3f} ms ({len(rows)} rows, result_json NOT decoded)")
    print(f"  get_run   : {get_ms:.3f} ms (decodes {len(run['result_json']['records'])} records)")


# ── Telemetry accumulator ──────────────────────────────────────────────────

def _run_telemetry(tmp: Path) -> None:
    if _TelemetryAccumulator is None:
        print(f"telemetry: skipped ({_TELEMETRY_ERR})")
        return
    path = tmp / "llm_usage.jsonl"
    acc = _TelemetryAccumulator(path)
    n = 10_000
    line = json.dumps(
        {
            "total_tokens": 100,
            "context_usage_pct": 50.0,
            "context_window_tokens": 128000,
            "estimated_context_tokens": 5000,
        }
    ) + "\n"
    with path.open("a", encoding="utf-8") as f:
        f.writelines([line] * n)
    t0 = time.perf_counter()
    snap = acc.snapshot()
    ms = (time.perf_counter() - t0) * 1000.0
    calls = snap["calls"] if snap else 0
    print("Telemetry accumulator:")
    print(f"  snapshot: {ms:.3f} ms over {n} appended lines ({calls} calls aggregated)")


# ── Audit read ─────────────────────────────────────────────────────────────

def _run_audit(tmp: Path) -> None:
    path = tmp / "exploit_audit.jsonl"
    n = 10_000
    rec = {
        "ts": "2026-08-15T00:00:00Z",
        "tool": "run_exploit_terminal",
        "target": "10.0.0.1",
        "command": "id",
        "sha256": "a" * 64,
    }
    with path.open("w", encoding="utf-8") as f:
        for _ in range(n):
            f.write(json.dumps(rec) + "\n")
    t0 = time.perf_counter()
    records: list[dict] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    ms = (time.perf_counter() - t0) * 1000.0
    print("Audit read (mirrors GET /runs/{id}/audit):")
    print(f"  read: {ms:.3f} ms over {len(records)} records")


def main() -> None:
    print("WebUI hot-path benchmark")
    print("=" * 60)
    with tempfile.TemporaryDirectory(prefix="webui-bench-") as td:
        tmp = Path(td)
        _run_events(tmp)
        print()
        _run_persistence(tmp)
        print()
        _run_telemetry(tmp)
        print()
        _run_audit(tmp)
    print("=" * 60)
    print("done")


if __name__ == "__main__":
    main()
