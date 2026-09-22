# Benchmarks

Machine-readable WebUI hot-path benchmarks (P3-02). No live Nmap/LLM/network —
all scenarios use mock/local I/O against throwaway temp dirs.

## Files

- `baseline.json` — pinned pre-change baselines for the 10k/100k pinned
  histories (1 KB payload): `event_emit_ms_n10000`, `event_replay_ms_n10000`,
  `event_emit_ms_n10000` … plus per-scenario emit/replay entries. Recorded via
  `scripts/benchmark_webui.py --events 10000 --events 100000 --payload-bytes 1024 --json`.
- `xben/` — oracle-verified benchmark suites (unrelated to the WebUI perf suite).

## Usage

```bash
# Record a current run (subset for speed; full matrix by default)
python3 scripts/benchmark_webui.py --events 10000 --payload-bytes 1024 --json /tmp/current.json

# Compare against baseline (fails if any p95 regresses >15%)
python3 scripts/bench_compare.py benchmarks/baseline.json /tmp/current.json

# Custom tolerance + machine-readable regressions
python3 scripts/bench_compare.py benchmarks/baseline.json /tmp/current.json --tolerance 0.2 --json /tmp/regressions.json
```

## Thresholds

- Default p95 regression tolerance: 15% (`scripts/bench_compare.py:DEFAULT_TOLERANCE`).
- Replay p95 is strict; graph-build stays looser until P2-04 lands.
- Never gate per-PR on wall-clock by default (flaky runners) — warn-first, then tighten.

## Recording a new baseline

Pin event/graph fixtures, record machine metadata (written automatically into
`--json` output), and commit the file:

```bash
python3 scripts/benchmark_webui.py --events 10000 --events 100000 --payload-bytes 1024 --json benchmarks/baseline.json
```

Every PERF todo cites before/after p50/p95/p99 from this suite.
