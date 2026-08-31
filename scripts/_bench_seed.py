"""Seed two synthetic completed benchmark runs (verification data only).

Uses the real storage + metrics layer so the persisted shapes are exactly
what the backend produces. Deleted by scripts/_bench_cleanup.py afterwards.
"""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.benchmark.metrics import compute_run_summary  # noqa: E402
from tools.benchmark.models import (  # noqa: E402
    FailureCategory,
    RunConfig,
    RunEnvironment,
    SandboxSnapshot,
    TargetSnapshot,
    TrialResult,
    TrialStatus,
    TrialTelemetry,
)
from tools.benchmark.storage import BenchmarkStorage  # noqa: E402

STORAGE = BenchmarkStorage("reports/benchmarks")


def env_for(run_id: str) -> RunEnvironment:
    return RunEnvironment(
        breachpilot_version="0.49.12",
        git_sha="c27c176fb96abb08f7ca27bdb4c08764e39ec27d",
        git_dirty=False,
        git_branch="main",
        model_provider="opencode_go",
        model_alias="glm",
        model_id="glm-test",
        model_version="test",
        reasoning_config={},
        temperature=None,
        config_hash="seed" + run_id[-4:],
        benchmark_config_hash="seedbench",
        sandbox_image="breachpilot-sandbox:latest",
        sandbox_image_digest="unknown",
        sandbox_enabled=True,
        sandbox_required=True,
        target_images={},
        platform="Windows/11",
        python_version="3.13.9",
    )


def make_trial(run_id: str, scenario: str, idx: int, verified: bool, fp: bool, duration: float) -> TrialResult:
    t = TrialResult(
        run_id=run_id,
        suite="xben",
        scenario_id=scenario,
        trial_index=idx,
        trial_id=f"{scenario}#t{idx + 1}",
        started_at=(datetime.now(timezone.utc) - timedelta(seconds=duration)).isoformat(),
    )
    t.status = (
        TrialStatus.VERIFIED.value
        if verified
        else (TrialStatus.FALSE_POSITIVE.value if fp else TrialStatus.FAILED.value)
    )
    t.agent_claimed_success = verified or fp
    t.oracle_verified_success = verified
    t.false_positive = fp
    t.duration_seconds = duration
    t.tool_calls = 12
    t.model_calls = 8
    t.total_tokens = 1500
    t.estimated_cost = 0.0031
    t.sandbox = SandboxSnapshot(enabled=True, required=True)
    t.target = TargetSnapshot(host="127.0.0.1", ports=[8080])
    t.telemetry = TrialTelemetry(model_calls=8, total_tokens=1500, estimated_cost=0.0031, tool_calls=12)
    t.ended_at = datetime.now(timezone.utc).isoformat()
    if not verified and not fp:
        t.failure_category = FailureCategory.NO_EXPLOIT_PATH.value
    return t


def seed(run_id: str, scenarios: list[str], verified_flags: list[bool], fp_flags: list[bool], stamp: str) -> None:
    config = RunConfig(
        suite="xben",
        scenario_ids=scenarios,
        tags=[],
        trials=1,
        timeout_seconds=1800,
        model_alias="glm",
        reasoning_profile="",
        sandbox_required=True,
        save_baseline=False,
        check_regression=False,
        output_dir="reports/benchmarks",
    )
    trials = []
    for i, sc in enumerate(scenarios):
        trials.append(make_trial(run_id, sc, 0, verified_flags[i], fp_flags[i], 420 + 90 * i))
    summary = compute_run_summary(trials, run_id=run_id, suite="xben")
    summary.timestamp = stamp
    STORAGE.finalize_run(
        "xben",
        run_id,
        status="completed",
        trials=trials,
        summary=summary,
        config=config,
        environment=env_for(run_id),
        scenario_ids=scenarios,
        manifest={"replay_command": "python main.py --benchmark xben --replay " + run_id},
    )
    (STORAGE.run_dir("xben", run_id) / "events.jsonl").write_text(
        "\n".join(
            [
                '{"sequence":1,"timestamp":"'
                + stamp
                + '","elapsed_seconds":0.0,"run_id":"'
                + run_id
                + '","type":"run_start","level":"info","trial_id":"","scenario_id":"","agent":"","tool":"","target":"","payload":{"suite":"xben"}}',
                '{"sequence":2,"timestamp":"'
                + stamp
                + '","elapsed_seconds":12.5,"run_id":"'
                + run_id
                + '","type":"target_ready","level":"info","trial_id":"'
                + scenarios[0]
                + '#t1","scenario_id":"'
                + scenarios[0]
                + '","agent":"","tool":"","target":"127.0.0.1","payload":{"host":"127.0.0.1","ports":[8080]}}',
                '{"sequence":3,"timestamp":"'
                + stamp
                + '","elapsed_seconds":420.0,"run_id":"'
                + run_id
                + '","type":"oracle_result","level":"info","trial_id":"'
                + scenarios[0]
                + '#t1","scenario_id":"'
                + scenarios[0]
                + '","agent":"","tool":"","target":"127.0.0.1","payload":{"verified":'
                + ("true" if verified_flags[0] else "false")
                + ',"flags_captured":1,"flags_total":1}}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    print("seeded", run_id, "solved", summary.solved, "/", summary.trials_total)


seed(
    "20260829_120000_00001",
    ["xben-dvwa", "xben-juice-shop", "xben-metasploitable2", "xben-vulnerable-k8s"],
    [True, False, True, False],
    [False, False, False, False],
    "2026-08-29T12:05:00+00:00",
)
seed(
    "20260830_120000_00002",
    ["xben-dvwa", "xben-juice-shop", "xben-metasploitable2", "xben-vulnerable-k8s"],
    [True, True, True, False],
    [False, False, False, False],
    "2026-08-30T12:05:00+00:00",
)
