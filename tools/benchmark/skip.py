"""Persist honest benchmark reports when a required model credential is absent."""

from __future__ import annotations

import argparse
import html
import os
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import yaml

from tools.benchmark.envinfo import config_hash
from tools.benchmark.events import BenchmarkEventLogger
from tools.benchmark.metrics import compute_run_summary
from tools.benchmark.models import RunConfig, RunEnvironment
from tools.benchmark.report import render_report_html, render_report_markdown
from tools.benchmark.storage import BenchmarkStorage
from tools.benchmark.xben.adapter import XbenProvider


def _model_metadata(config: dict[str, Any]) -> tuple[str, str, str, str]:
    models = config.get("models", {})
    models = models if isinstance(models, dict) else {}
    provider = str(models.get("provider", "") or "unknown")
    providers = config.get("providers", {})
    providers = providers if isinstance(providers, dict) else {}
    provider_config = providers.get(provider, {})
    provider_config = provider_config if isinstance(provider_config, dict) else {}
    key_name = str(provider_config.get("api_key_env", "") or "").strip()
    if not key_name:
        raise ValueError(f"configured model provider {provider!r} does not declare an api_key_env")
    if os.environ.get(key_name, "").strip():
        raise ValueError(f"provider credential {key_name} is present; refusing to write a missing-key skip report")

    alias = str(models.get("default_alias", "") or "unknown")
    registry = models.get("registry", {})
    registry = registry if isinstance(registry, dict) else {}
    entry = registry.get(alias)
    if isinstance(entry, str):
        model_id = entry.strip() or "unknown"
    elif isinstance(entry, dict):
        candidate = entry.get("model") or entry.get("model_id") or entry.get("name")
        model_id = str(candidate or "unknown").strip() or "unknown"
    else:
        model_id = "unknown"
    model_version = model_id.split(":", 1)[1] if ":" in model_id else "unknown"
    return provider, alias, model_id, model_version


def write_skipped_benchmark_report(
    config: dict[str, Any],
    *,
    suite: str,
    trials: int,
    reason: str,
    output_dir: Path | str | None = None,
    scenario_ids: list[str] | None = None,
    run_id: str = "",
) -> Path:
    """Persist a SKIPPED run without provisioning targets or contacting a provider.

    The configured provider credential must be absent. The resulting run and
    summary are indexed like ordinary reports, but record zero attempted
    trials and explicitly state that no target containers were started.
    """
    if trials < 1:
        raise ValueError("trials must be positive")
    reason = str(reason or "").strip()
    if not reason:
        raise ValueError("skip reason must not be empty")
    provider, alias, model_id, model_version = _model_metadata(config)

    if scenario_ids is None:
        if suite != "xben":
            raise ValueError("scenario_ids are required for suites other than xben")
        scenario_ids = [scenario.scenario_id for scenario in XbenProvider().load_scenarios()]

    benchmark_config = config.get("benchmark", {})
    benchmark_config = benchmark_config if isinstance(benchmark_config, dict) else {}
    root = output_dir or benchmark_config.get("output_dir") or "reports/benchmarks"
    storage = BenchmarkStorage(root)
    resolved_run_id = run_id or datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_") + uuid4().hex[:8]
    timestamp = datetime.now(timezone.utc).isoformat()
    run_config = RunConfig(
        suite=suite,
        scenario_ids=list(scenario_ids),
        trials=trials,
        model_alias=alias,
        sandbox_required=True,
        output_dir=str(root),
    )
    sandbox_config = config.get("sandbox", {})
    sandbox_config = sandbox_config if isinstance(sandbox_config, dict) else {}
    git_sha = str(os.environ.get("GITHUB_SHA", "") or "").strip()
    if len(git_sha) != 40 or any(char not in "0123456789abcdefABCDEF" for char in git_sha):
        git_sha = "unknown"
    environment = RunEnvironment(
        git_sha=git_sha,
        git_dirty=False if os.environ.get("GITHUB_ACTIONS") == "true" else None,
        git_branch=str(os.environ.get("GITHUB_REF_NAME", "") or "unknown"),
        model_provider=provider,
        model_alias=alias,
        model_id=model_id,
        model_version=model_version,
        config_hash=config_hash(config),
        benchmark_config_hash=config_hash(benchmark_config),
        sandbox_enabled=bool(sandbox_config.get("enabled", False)),
        sandbox_required=True,
        target_images={scenario_id: "unknown" for scenario_id in scenario_ids},
        platform=f"{platform.system()}/{platform.release()}",
        python_version=sys.version.split(" ", 1)[0],
    )
    summary = compute_run_summary([], run_id=resolved_run_id, suite=suite)
    run_dir = storage.init_run(suite, resolved_run_id, run_config, environment, scenario_ids)
    storage.finalize_run(
        suite,
        resolved_run_id,
        status="SKIPPED",
        trials=[],
        summary=summary,
        config=run_config,
        environment=environment,
        scenario_ids=scenario_ids,
        skip_reason=reason,
    )

    events = BenchmarkEventLogger(path=run_dir / "events.jsonl", run_id=resolved_run_id)
    events.log("run_start", {"suite": suite, "scenarios": scenario_ids, "trials": trials})
    events.log(
        "run_skipped",
        {"reason": reason, "provider": provider, "attempted_trials": 0, "targets_started": 0},
        level="warn",
    )
    events.log("run_end", {"status": "SKIPPED", "trials_total": 0, "targets_started": 0}, level="warn")

    stored_run = storage.load_run(suite, resolved_run_id) or {}
    stored_summary = storage.load_summary(suite, resolved_run_id)
    markdown = render_report_markdown(stored_run, stored_summary)
    markdown += (
        "\n## Run status\n\n"
        f"**SKIPPED** — {reason}\n\n"
        "No model requests or benchmark trials ran. No target containers were started.\n"
    )
    report_html = render_report_html(stored_run, stored_summary)
    status_html = (
        "<section><h2>Run status: SKIPPED</h2>"
        f"<p>{html.escape(reason)}</p>"
        "<p>No model requests or benchmark trials ran. No target containers were started.</p></section>"
    )
    storage.write_report(suite, resolved_run_id, markdown, report_html.replace("</body>", f"{status_html}</body>"))
    return run_dir


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write an explicit SKIPPED benchmark report without starting targets.")
    parser.add_argument("--config", type=Path, default=Path("config.yaml"))
    parser.add_argument("--suite", default="xben")
    parser.add_argument("--trials", type=int, default=5)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--output-dir", type=Path, default=None)
    args = parser.parse_args(argv)

    config = yaml.safe_load(args.config.read_text(encoding="utf-8"))
    if not isinstance(config, dict):
        parser.error("config must contain a YAML object")
    run_dir = write_skipped_benchmark_report(
        config,
        suite=args.suite,
        trials=args.trials,
        reason=args.reason,
        output_dir=args.output_dir,
    )
    try:
        print(run_dir.relative_to(Path.cwd()))
    except ValueError:
        print(run_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
