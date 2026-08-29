"""CLI glue for the benchmark suite flags (``--benchmark*``).

Kept out of main.py (which stays orchestration-only) and out of the API routes
(no benchmark logic in handlers). Everything heavy lives in
:mod:`tools.benchmark.runner` / :mod:`tools.benchmark.service`.

Exit codes: 0 success; 1 hard regression (--check-regression) or run error;
2 usage error.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from tools.benchmark.models import RunConfig
from tools.benchmark.registry import list_scenarios, list_suites
from tools.benchmark.runner import BenchmarkRunner
from tools.config_manager import load_validated_config

__all__ = ["run_benchmark_cli"]


def _print_suite_list() -> int:
    from tools.benchmark import register_default_providers

    register_default_providers()
    suites = list_suites()
    if not suites:
        print("No benchmark suites registered. Add manifests under benchmarks/<suite>/*.json.")
        return 0
    for suite in suites:
        print(
            f"{suite.get('suite_id', '?')}\t{suite.get('scenarios', 0)} scenarios"
            + (f"\t[tags: {', '.join(sorted(suite.get('tags', {})))}]" if suite.get("tags") else "")
        )
        for scenario in list_scenarios(suite["suite_id"]):
            tags = ",".join(scenario.get("tags", []))
            print(
                f"  {scenario.get('scenario_id', '?')}\t{scenario.get('difficulty', '?')}\t"
                f"{scenario.get('oracle_flag_count', 0)} flags\t{tags}"
            )
    return 0


def run_benchmark_cli(args: Any) -> int:
    """``--benchmark`` / ``--benchmark-list`` entry. Returns the process exit code."""
    if getattr(args, "benchmark_list", False):
        return _print_suite_list()

    from tools.benchmark import register_default_providers

    register_default_providers()

    config_path = Path(getattr(args, "config", "config.yaml"))
    try:
        config = load_validated_config(config_path)
    except Exception as exc:  # noqa: BLE001 -- config errors are usage errors
        print(f"[!] Could not load/validate config: {exc}")
        return 2

    benchmark_cfg = config.get("benchmark", {}) or {}
    if benchmark_cfg.get("enabled") is False:
        print("[!] benchmark.enabled is false in config; refusing to run.")
        return 2

    suite_ids = list(getattr(args, "benchmark", None) or [])
    suite = suite_ids[0] if suite_ids else "xben"
    if len(suite_ids) > 1:
        print("[!] --benchmark takes one suite id (use --scenario for scenario filters).")
        return 2

    trials = getattr(args, "trials", None)
    if trials is None:
        trials = int(benchmark_cfg.get("trials", 1) or 1)
    if not 1 <= int(trials) <= 20:
        print("[!] --trials must be between 1 and 20.")
        return 2

    run_config = RunConfig(
        suite=suite,
        scenario_ids=[str(s) for s in (getattr(args, "scenario", None) or [])],
        tags=[str(t) for t in (getattr(args, "tag", None) or [])],
        trials=int(trials),
        timeout_seconds=int(benchmark_cfg.get("timeout_seconds", 1800) or 1800),
        sandbox_required=bool(benchmark_cfg.get("sandbox_required", True)),
        save_baseline=bool(getattr(args, "save_baseline", False)),
        check_regression=bool(getattr(args, "check_regression", False)),
        output_dir=str(benchmark_cfg.get("output_dir", "reports/benchmarks") or "reports/benchmarks"),
    )

    print("=" * 60)
    print("  NetAttackAI — Benchmark Suite")
    print(f"  Suite: {run_config.suite}  trials={run_config.trials}  sandbox_required={run_config.sandbox_required}")
    if run_config.scenario_ids:
        print(f"  Scenarios: {', '.join(run_config.scenario_ids)}")
    if run_config.tags:
        print(f"  Tags: {', '.join(run_config.tags)}")
    print("=" * 60)

    runner = BenchmarkRunner(config, config_path)

    def _progress(event: dict[str, Any]) -> None:
        etype = str(event.get("type", ""))
        if etype == "trial_start":
            print(f"\n--- {event.get('scenario_id')} trial {event.get('trial')}/{event.get('trials')} ---")
        elif etype == "trial_phase":
            print(f"  [{event.get('phase')}] {event.get('scenario_id')} #{event.get('trial_id', '')}")
        elif etype == "oracle_result":
            print(
                f"  oracle: verified={event.get('verified')} flags={event.get('flags_captured')}/{event.get('flags_total')}"
            )
        elif etype == "run_end":
            print(f"\nrun end: {event.get('status')}")

    try:
        payload = asyncio.run(runner.run(run_config, progress=_progress))
    except KeyboardInterrupt:
        print("\n[!] Benchmark cancelled.")
        return 130
    except Exception as exc:  # noqa: BLE001 -- CLI guard
        print(f"[!] Benchmark run failed: {exc}")
        return 1

    if payload.get("error"):
        print(f"[!] {payload['error']}")
        return 1

    summary = payload.get("summary", {}) or {}
    print("\n" + "=" * 60)
    print("  Benchmark results")
    print(f"  Run ID: {payload.get('run_id')}")
    print(
        f"  Verified: {summary.get('solved', 0)}/{summary.get('trials_total', 0)} ({summary.get('verified_success_rate', 0):.1%})"
    )
    print(f"  False positives: {summary.get('false_positive_rate', 0):.1%}")
    median_time = summary.get("median_solve_time")
    if median_time:
        minutes, secs = divmod(int(median_time), 60)
        print(f"  Median solve time: {minutes}m {secs:02d}s")
    cost = summary.get("estimated_cost")
    if cost is not None:
        print(f"  Estimated cost: ${float(cost):.2f}")
    print(f"  Infra errors: {summary.get('infra_error_count', 0)}  timeouts: {summary.get('timeout_count', 0)}")
    print(f"  Report: {payload.get('report_markdown')}")
    print("=" * 60)

    exit_code = 0
    regression = payload.get("regression")
    if regression is not None:
        for finding in regression.get("findings", []):
            marker = {"hard": "REGRESSION", "warning": "warn", "improvement": "improved", "unchanged": "ok"}.get(
                finding.get("severity", ""), finding.get("severity", "")
            )
            print(f"  [{marker}] {finding.get('metric')}: {finding.get('detail')}")
        if not regression.get("passed", True):
            exit_code = 1
            print("[!] Hard regression detected; exiting non-zero for CI.")
    return exit_code
