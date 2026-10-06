"""Oracle-backed paired benchmark harness for Flow A.

The legacy ``--eval`` (``tools/eval_harness.py``) is a single-run smoke report:
it self-scores the system's own regex-derived ``outcome_summary``, does not
enable the smart features it claims to evaluate (adaptive exploits, Flow A
outcome judgment, skills, long-session), has no baseline/treatment comparison,
and ``success_rate`` is compromise-events-per-action, not run-success
probability.

This module adds a paired-comparison benchmark that:

  * Enables the smart features (``adaptive_exploits``,
    ``outcome_judgment.flow_a``, ``skills.enabled``, ``long_session``) so
    the treatment actually exercises the intelligence layer.
  * Runs paired baseline-vs-treatment trials against resettable lab
    scenarios.
  * Scores each trial with a **target-side oracle** -- a caller-supplied
    verifier that confirms the objective independently of the agent's own
    claims. A success counts ONLY when the oracle confirms.
  * Computes a verified success rate (``mean(Y)``) per condition and a
    paired risk ratio ``RR = mean(Y_treatment) / mean(Y_baseline)``.
  * Records per-trial metadata: model ID, config hash, target snapshot ID,
    actions, tokens, time-to-first-verified-success.

The oracle is a callable ``Oracle(target_ip, scenario) -> bool`` the operator
supplies (e.g. "did a known proof file get read?", "did a callback reach the
verifier?", "do the seeded credentials match?"). The agent's own text, exit
code, and ``OutcomeJudge`` verdict are NOT sufficient -- that is the whole
point.

Usage::

    from tools.eval_benchmark import BenchmarkConfig, run_benchmark
    cfg = BenchmarkConfig(
        scenarios=[...],
        oracle=my_oracle,
        conditions=["baseline", "treatment"],
        trials_per_scenario=4,
    )
    report = await run_benchmark(cfg)
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import statistics
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Protocol

from tools.eval.metrics import _count_outcome
from tools.exceptions import _EXC_GROUP_CATCH, _is_exception_group, _log_nested_exceptions

__all__ = [
    "Oracle",
    "Scenario",
    "BenchmarkConfig",
    "TargetResetError",
    "TrialResult",
    "BenchmarkReport",
    "run_benchmark",
    "DEFAULT_BASELINE_CONFIG",
    "DEFAULT_TREATMENT_CONFIG",
]


# ── Types ──────────────────────────────────────────────────────────────────


class Oracle(Protocol):
    """Target-side verifier. Returns True ONLY when the objective is
    independently confirmed on the target (not from agent text)."""

    def __call__(self, target_ip: str, scenario: "Scenario") -> bool: ...


@dataclass
class Scenario:
    """One resettable lab scenario."""

    scenario_id: str
    target_ip: str
    goal_name: str  # e.g. "initial_access", "backdoor"
    description: str = ""
    target_snapshot_id: str = ""  # identifies the target image for reset
    expected_duration_seconds: float = 300.0
    metadata: dict[str, Any] = field(default_factory=dict)


class TargetResetError(RuntimeError):
    """A target could not be reset, so benchmark results would be contaminated."""

    def __init__(self, scenario_id: str, condition: str, trial_index: int) -> None:
        self.scenario_id = scenario_id
        self.condition = condition
        self.trial_index = trial_index
        self.partial_report: BenchmarkReport | None = None
        self.report_path: Path | None = None
        super().__init__(
            "target reset failed before "
            f"scenario={scenario_id!r}, condition={condition!r}, trial={trial_index}; "
            "aborting benchmark to avoid scoring a contaminated target"
        )


@dataclass
class TrialResult:
    """One trial's outcome."""

    scenario_id: str
    condition: str  # "baseline" | "treatment"
    trial_index: int
    verified_success: bool | None  # None means the oracle did not produce a verdict
    agent_claimed_success: bool  # the agent's own verdict (for contrast)
    total_actions: int
    duration_seconds: float
    oracle_before_status: str = "pending"  # verified | not_verified | error
    oracle_status: str = "pending"  # verified | not_verified | preexisting | unattributed | error
    oracle_error: str = ""
    # No online oracle polling exists, so this remains unknown for post-run checks.
    time_to_first_verified_success: float | None = None
    model_id: str = ""
    config_hash: str = ""
    error: str = ""
    # D5: throughput + token-cost telemetry. ``total_tokens`` is the trial's
    # LLM token spend (prompt+completion); ``token_cost`` is an optional
    # operator-supplied cost in any currency unit (USD, credits, etc.) so the
    # benchmark can compute token_cost_per_finding without hardcoding a
    # pricing model. Both default to 0 -- the real run_session can populate
    # them from model_telemetry; the mock path leaves them at 0.
    total_tokens: int = 0
    token_cost: float = 0.0


@dataclass
class BenchmarkReport:
    """Aggregated benchmark results."""

    conditions: list[str]
    trials: list[TrialResult]
    verified_success_rate: dict[str, float | None]  # None when condition measurements are incomplete
    risk_ratio: float | None  # treatment / baseline
    risk_ratio_ci_low: float | None  # bootstrap 95% lower
    risk_ratio_ci_high: float | None  # bootstrap 95% upper
    false_positive_rate: dict[str, float | None]  # None when condition measurements are incomplete
    actions_per_verified_success: dict[str, float | None]
    time_to_first_verified_success: dict[str, float | None]
    # D5: throughput + cost efficiency. ``findings_per_hour`` is
    # verified-successes per hour of wall time; ``token_cost_per_finding`` is
    # the mean token cost per verified success (None when no successes or no
    # cost data). Both are per condition.
    findings_per_hour: dict[str, float | None] = field(default_factory=dict)
    token_cost_per_finding: dict[str, float | None] = field(default_factory=dict)
    timestamp: str = ""
    status: str = "completed"  # completed | completed_with_errors | completed_with_unscored_trials | aborted
    error: str = ""
    oracle_measurements: dict[str, dict[str, int]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "conditions": self.conditions,
            "trials": [t.__dict__ for t in self.trials],
            "verified_success_rate": self.verified_success_rate,
            "risk_ratio": self.risk_ratio,
            "risk_ratio_ci_low": self.risk_ratio_ci_low,
            "risk_ratio_ci_high": self.risk_ratio_ci_high,
            "false_positive_rate": self.false_positive_rate,
            "actions_per_verified_success": self.actions_per_verified_success,
            "time_to_first_verified_success": self.time_to_first_verified_success,
            "findings_per_hour": self.findings_per_hour,
            "token_cost_per_finding": self.token_cost_per_finding,
            "timestamp": self.timestamp,
            "status": self.status,
            "error": self.error,
            "oracle_measurements": self.oracle_measurements,
        }


@dataclass
class BenchmarkConfig:
    """Benchmark configuration."""

    scenarios: list[Scenario]
    oracle: Oracle
    conditions: list[str] = field(default_factory=lambda: ["baseline", "treatment"])
    trials_per_scenario: int = 4
    output_dir: Path = Path("reports/eval_benchmark")
    reset_target_between_trials: Callable[[Scenario], None] | None = None
    # Per-condition config overrides merged onto the base config.yaml.
    # ``DEFAULT_BASELINE_CONFIG`` disables smart features; ``DEFAULT_TREATMENT_CONFIG``
    # enables them. The operator can supply custom overrides.
    condition_configs: dict[str, dict[str, Any]] = field(default_factory=dict)
    # The run-session callable -- injected so the benchmark can be tested
    # without a live MCP server. When None, the real run_exploit_session is used.
    run_session: Callable[..., Any] | None = None


# ── Default condition configs ──────────────────────────────────────────────

DEFAULT_BASELINE_CONFIG: dict[str, Any] = {
    # Smart features OFF -- the floor.
    "adaptive_exploits": {"enabled": False},
    "outcome_judgment": {"flow_a": False},
    "skills": {"enabled": False},
    "long_session": {"enabled": False},
    "reasoning": {"llm_reflection": False, "critic_enabled": False},
    "multi_model": {"enabled": False},
    "memory": {"semantic_enabled": False, "attack_memory_enabled": False},
}

DEFAULT_TREATMENT_CONFIG: dict[str, Any] = {
    # Smart features ON -- the intelligence layer the 4x claim is about.
    "adaptive_exploits": {"enabled": True, "max_mutations": 5},
    "outcome_judgment": {"flow_a": True},
    "skills": {"enabled": True},
    "long_session": {"enabled": True, "attack_max_rounds": 200},
    "reasoning": {"llm_reflection": True, "critic_enabled": True, "reflection_every_n_actions": 10},
    "multi_model": {"enabled": True},
    "memory": {"semantic_enabled": True, "attack_memory_enabled": True, "cross_mission_learning": True},
}


# ── Harness ────────────────────────────────────────────────────────────────


def _config_hash(config: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(config, sort_keys=True, default=str).encode()).hexdigest()[:16]


def _merge_config(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Deep-merge ``override`` onto ``base`` (override wins)."""
    merged = json.loads(json.dumps(base, default=str))
    for key, val in override.items():
        if isinstance(val, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_config(merged[key], val)
        else:
            merged[key] = val
    return merged


async def _run_one_trial(
    *,
    scenario: Scenario,
    condition: str,
    trial_index: int,
    config: dict[str, Any],
    config_hash: str,
    run_session: Callable[..., Any] | None,
) -> tuple[TrialResult, dict[str, Any]]:
    """Run one trial. Returns (result, agent_final_result_dict)."""
    from tools.exploit_agent import ExploitPermission, ExploitSettings
    from tools.goal_engine import GoalEngine

    start = time.monotonic()
    error = ""
    agent_result: dict[str, Any] = {}
    agent_claimed = False

    workspace_root = Path(f"reports/eval_benchmark/{scenario.scenario_id}/{condition}/t{trial_index}")
    workspace_root.mkdir(parents=True, exist_ok=True)

    settings = ExploitSettings(
        enabled=True,
        mode="attack",
        permission=ExploitPermission.FULL_ACCESS,
        attack_mode=True,
        attack_max_rounds=int(config.get("long_session", {}).get("attack_max_rounds", 50)),
        workspace_root=workspace_root,
        target_ip=scenario.target_ip,
        # Enable the smart features from the condition config.
        adaptive_exploits_enabled=bool(config.get("adaptive_exploits", {}).get("enabled", False)),
        outcome_judgment_flow_a=bool(config.get("outcome_judgment", {}).get("flow_a", False)),
    )
    goal = GoalEngine().get(scenario.goal_name, risk_profile="high_authorized_testing")

    try:
        if run_session is not None:
            agent_result = await run_session(
                target_ip=scenario.target_ip,
                mode="attack",
                goal=goal,
                exploit_settings=settings,
                config=config,
                reports_dir=workspace_root,
            )
        else:
            from tools.config_cli import load_config
            from tools.exploit_session import run_exploit_session
            from tools.model_router import build_router

            base_config = load_config(Path("config.yaml"))
            merged = _merge_config(base_config, config)
            ollama_host = merged.get("ollama", {}).get("host", "https://api.ollama.com")
            registry = merged.get("models", {}).get("registry")
            from tools.config_manager import get_ai_provider, get_chatgpt_config, get_opencode_go_config

            provider = get_ai_provider(merged)
            if provider == "chatgpt":
                router = build_router(
                    registry,
                    host=ollama_host,
                    provider="chatgpt",
                    chatgpt_config=get_chatgpt_config(merged),
                    config=merged,
                )
            elif provider == "opencode_go":
                router = build_router(
                    registry,
                    host=ollama_host,
                    provider="opencode_go",
                    opencode_go_config=get_opencode_go_config(merged),
                    config=merged,
                )
            else:
                router = build_router(registry, host=ollama_host)
            model_alias = merged.get("models", {}).get("default_alias", "glm")
            if provider == "opencode_go":
                model_alias = str(get_opencode_go_config(merged).get("default_model") or "muse-spark-1.2-contributor")
            try:
                model_client = router.get_client(model_alias)
            except KeyError:
                if provider in ("chatgpt", "opencode_go"):
                    from tools.model_router import build_model_client_for_provider

                    router.register(
                        model_alias,
                        build_model_client_for_provider(
                            merged,
                            model_alias,
                            request_timeout_seconds=None,
                        ),
                    )
                else:
                    from tools.model_router import _build_model_client

                    router.register(
                        model_alias,
                        _build_model_client(
                            model_alias,
                            host=ollama_host,
                            request_timeout_seconds=None,
                        ),
                    )
                model_client = router.get_client(model_alias)

            agent_result = await run_exploit_session(
                client=model_client,
                model=model_alias,
                target_ip=scenario.target_ip,
                mode="attack",
                goal=goal,
                exploit_settings=settings,
                config_path=Path("config.yaml"),
                config_override=merged,
                reports_dir=workspace_root,
            )
        # The agent's own claim (for false-positive rate).
        outcome_summary = str(agent_result.get("outcome_summary", "") or "")
        agent_claimed = any(
            _count_outcome(outcome_summary, label) > 0 for label in ("compromises", "cred dumps", "unverified claims")
        )
    except Exception as exc:
        error = str(exc)[:500]

    duration = time.monotonic() - start
    total_actions = int(agent_result.get("total_actions", 0) or 0)
    # D5: token spend + cost from the run. The real run_session can populate
    # these from model_telemetry; absence -> 0 (the mock path leaves them at 0
    # so the existing tests stay green).
    total_tokens = int(agent_result.get("total_tokens", 0) or 0)
    token_cost = float(agent_result.get("token_cost", 0.0) or 0.0)

    result = TrialResult(
        scenario_id=scenario.scenario_id,
        condition=condition,
        trial_index=trial_index,
        verified_success=False,  # set by the oracle below
        agent_claimed_success=agent_claimed,
        total_actions=total_actions,
        # ponytail: round to 6 decimals (microseconds) instead of 3 (ms) so
        # sub-millisecond mock durations don't collapse to 0.0 -- the
        # findings/hour aggregation divides by this and a 0.0 would yield
        # ZeroDivisionError or a misleading 0.0/hour. Real trials are
        # seconds-to-minutes so the extra precision is harmless.
        duration_seconds=round(duration, 6),
        model_id=str(config.get("models", {}).get("default_alias", "")),
        config_hash=config_hash,
        error=error,
        total_tokens=total_tokens,
        token_cost=token_cost,
    )
    return result, agent_result


def _persist_report(report: BenchmarkReport, output_dir: Path) -> Path:
    """Persist a complete or partial report atomically and return its path."""
    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / f"benchmark_{report.timestamp.replace(':', '-')}.json"
    temp_path = out_path.with_suffix(out_path.suffix + ".tmp")
    temp_path.write_text(json.dumps(report.to_dict(), indent=2, default=str), encoding="utf-8")
    temp_path.replace(out_path)
    return out_path


def _oracle_observation(target_ip: str, scenario: Scenario, oracle: Oracle) -> tuple[bool | None, str]:
    """Read one strict boolean oracle verdict without leaking exception text."""
    try:
        verdict = oracle(target_ip, scenario)
    except _EXC_GROUP_CATCH as exc:
        if _is_exception_group(exc):
            _log_nested_exceptions(exc)
        return None, f"{type(exc).__name__}: oracle check failed"
    if type(verdict) is not bool:
        return None, f"oracle returned {type(verdict).__name__}; expected bool"
    return verdict, ""


def _canonical_target(value: Any) -> str:
    text = str(value or "").strip().strip("[]").rstrip(".")
    try:
        return ipaddress.ip_address(text).compressed
    except ValueError:
        return text.lower()


def _has_attributed_target_exploit(agent_result: dict[str, Any], target_ip: str) -> bool:
    """Require an approved exploit record with normalized target-bound proof."""
    if not isinstance(agent_result, dict):
        return False
    records = agent_result.get("records")
    if not isinstance(records, list):
        return False
    expected_target = _canonical_target(target_ip)
    from tools.exploit_agent.outcome_truth import _EXPLOIT_VALIDATION_TOOLS

    for record in records:
        if not isinstance(record, dict):
            continue
        action = str(record.get("action", "") or "").strip().lower()
        if (
            action not in _EXPLOIT_VALIDATION_TOOLS
            or str(record.get("status", "") or "").lower() not in {"completed", "executed"}
            or record.get("approved") is not True
            or _canonical_target(record.get("target_ip")) != expected_target
            or record.get("exit_code") not in (None, 0)
            or record.get("exploit_outcome") not in {"compromise", "cred_dump"}
        ):
            continue
        evidence = record.get("outcome_evidence")
        if not isinstance(evidence, list) or not any(isinstance(item, str) and item.strip() for item in evidence):
            continue
        detail = record.get("detail")
        try:
            arguments = json.loads(detail) if isinstance(detail, str) else {}
        except json.JSONDecodeError:
            continue
        if not isinstance(arguments, dict):
            continue
        if any(_canonical_target(arguments.get(key)) == expected_target for key in ("target", "target_ip", "host")):
            return True
    return False


def _build_benchmark_report(
    cfg: BenchmarkConfig,
    trials: list[TrialResult],
    *,
    status: str = "completed",
    error: str = "",
) -> BenchmarkReport:
    """Aggregate only complete oracle measurements; expose missing data as None."""
    conditions = list(cfg.conditions)
    expected_per_condition = len(cfg.scenarios) * max(0, cfg.trials_per_scenario)
    verified_rate: dict[str, float | None] = {}
    false_pos_rate: dict[str, float | None] = {}
    actions_per_success: dict[str, float | None] = {}
    # Before/after oracle observations can bound a transition but do not give
    # an exact discovery timestamp.
    time_to_first: dict[str, float | None] = {condition: None for condition in conditions}
    findings_per_hour: dict[str, float | None] = {}
    token_cost_per_finding: dict[str, float | None] = {}
    oracle_measurements: dict[str, dict[str, int]] = {}
    complete_by_condition: dict[str, bool] = {}

    for condition in conditions:
        condition_trials = [trial for trial in trials if trial.condition == condition]
        verified = [trial for trial in condition_trials if trial.oracle_status == "verified"]
        not_verified = [trial for trial in condition_trials if trial.oracle_status == "not_verified"]
        preexisting = [trial for trial in condition_trials if trial.oracle_status == "preexisting"]
        unattributed = [trial for trial in condition_trials if trial.oracle_status == "unattributed"]
        errors = [trial for trial in condition_trials if trial.oracle_status == "error"]
        complete = (
            expected_per_condition > 0
            and len(condition_trials) == expected_per_condition
            and len(verified) + len(not_verified) == expected_per_condition
        )
        complete_by_condition[condition] = complete
        oracle_measurements[condition] = {
            "expected": expected_per_condition,
            "attempted": len(condition_trials),
            "verified": len(verified),
            "not_verified": len(not_verified),
            "preexisting": len(preexisting),
            "unattributed": len(unattributed),
            "error": len(errors),
            "unmeasured": max(
                0,
                expected_per_condition
                - len(verified)
                - len(not_verified)
                - len(preexisting)
                - len(unattributed)
                - len(errors),
            ),
        }

        # An aborted run keeps every completed trial for diagnosis, but none of
        # its partial aggregates should look like a finished benchmark score.
        scoreable = complete and status != "aborted"
        if not scoreable:
            verified_rate[condition] = None
            false_pos_rate[condition] = None
            actions_per_success[condition] = None
            findings_per_hour[condition] = None
            token_cost_per_finding[condition] = None
            continue

        measured = verified + not_verified
        verified_rate[condition] = len(verified) / len(measured)
        false_pos_rate[condition] = sum(
            1 for trial in measured if trial.agent_claimed_success and trial.oracle_status == "not_verified"
        ) / len(measured)
        actions_per_success[condition] = (
            statistics.mean(trial.total_actions for trial in verified) if verified else None
        )
        elapsed_seconds = sum(trial.duration_seconds for trial in condition_trials)
        findings_per_hour[condition] = (len(verified) / elapsed_seconds) * 3600.0 if elapsed_seconds > 0 else 0.0
        token_cost_per_finding[condition] = (
            statistics.mean(trial.token_cost for trial in verified) if verified else None
        )

    rr: float | None = None
    rr_low: float | None = None
    rr_high: float | None = None
    if (
        status != "aborted"
        and complete_by_condition.get("baseline", False)
        and complete_by_condition.get("treatment", False)
    ):
        base_rate = verified_rate["baseline"]
        treatment_rate = verified_rate["treatment"]
        if base_rate is not None and treatment_rate is not None and base_rate > 0:
            rr = treatment_rate / base_rate
            # Cluster bootstrap: keep all repeated trials for each resampled
            # scenario, then divide by the number of sampled trials.
            import random

            rng = random.Random(42)
            rr_samples: list[float] = []
            scenario_ids = [scenario.scenario_id for scenario in cfg.scenarios]
            for _ in range(1000):
                resampled = [rng.choice(scenario_ids) for _ in scenario_ids]
                baseline_trials = [
                    trial
                    for sid in resampled
                    for trial in trials
                    if trial.condition == "baseline" and trial.scenario_id == sid
                ]
                treatment_trials = [
                    trial
                    for sid in resampled
                    for trial in trials
                    if trial.condition == "treatment" and trial.scenario_id == sid
                ]
                if not baseline_trials or not treatment_trials:
                    continue
                baseline_rate = sum(t.oracle_status == "verified" for t in baseline_trials) / len(baseline_trials)
                sampled_treatment_rate = sum(t.oracle_status == "verified" for t in treatment_trials) / len(
                    treatment_trials
                )
                if baseline_rate > 0:
                    rr_samples.append(sampled_treatment_rate / baseline_rate)
            if rr_samples:
                rr_samples.sort()
                rr_low = rr_samples[int(0.025 * len(rr_samples))]
                rr_high = rr_samples[min(len(rr_samples) - 1, int(0.975 * len(rr_samples)))]

    return BenchmarkReport(
        conditions=conditions,
        trials=trials,
        verified_success_rate=verified_rate,
        risk_ratio=rr,
        risk_ratio_ci_low=rr_low,
        risk_ratio_ci_high=rr_high,
        false_positive_rate=false_pos_rate,
        actions_per_verified_success=actions_per_success,
        time_to_first_verified_success=time_to_first,
        findings_per_hour=findings_per_hour,
        token_cost_per_finding=token_cost_per_finding,
        timestamp=datetime.now(timezone.utc).isoformat(),
        status=status,
        error=error,
        oracle_measurements=oracle_measurements,
    )


async def run_benchmark(cfg: BenchmarkConfig) -> BenchmarkReport:
    """Run the paired benchmark and return an aggregated report.

    For each scenario × condition × trial:
      1. Reset the target (if ``reset_target_between_trials`` is supplied).
      2. Record the oracle state before the agent runs.
      3. Run the exploit session with the condition's config.
      4. Recheck the oracle and require a successful approved target action.
      5. Record the trial result. Pre-existing or unattributed objectives are
         reported separately and excluded from success-rate aggregates.

    Then aggregate per condition: verified success rate, false-positive
    rate, actions per verified success, and a bootstrap risk-ratio CI.
    """
    condition_configs = cfg.condition_configs or {
        "baseline": DEFAULT_BASELINE_CONFIG,
        "treatment": DEFAULT_TREATMENT_CONFIG,
    }
    trials: list[TrialResult] = []
    oracle_errors = 0

    for scenario in cfg.scenarios:
        for condition in cfg.conditions:
            cond_cfg = condition_configs.get(condition, {})
            chash = _config_hash(cond_cfg)
            for trial_idx in range(cfg.trials_per_scenario):
                if cfg.reset_target_between_trials is not None:
                    try:
                        cfg.reset_target_between_trials(scenario)
                    except _EXC_GROUP_CATCH as exc:
                        if _is_exception_group(exc):
                            _log_nested_exceptions(exc)
                        reset_error = TargetResetError(scenario.scenario_id, condition, trial_idx)
                        partial = _build_benchmark_report(
                            cfg,
                            trials,
                            status="aborted",
                            error=f"{reset_error} (cause type: {type(exc).__name__})",
                        )
                        reset_error.partial_report = partial
                        reset_error.report_path = _persist_report(partial, cfg.output_dir)
                        raise reset_error from exc

                before_verdict, before_error = _oracle_observation(scenario.target_ip, scenario, cfg.oracle)

                result, agent_result = await _run_one_trial(
                    scenario=scenario,
                    condition=condition,
                    trial_index=trial_idx,
                    config=cond_cfg,
                    config_hash=chash,
                    run_session=cfg.run_session,
                )
                result.oracle_before_status = (
                    "error" if before_verdict is None else ("verified" if before_verdict else "not_verified")
                )
                if before_verdict is None:
                    result.verified_success = None
                    result.oracle_status = "error"
                    result.oracle_error = before_error
                    oracle_errors += 1
                elif before_verdict:
                    # A positive state that predates this trial cannot be
                    # attributed to the agent, even if it remains present.
                    result.verified_success = None
                    result.oracle_status = "preexisting"
                else:
                    after_verdict, after_error = _oracle_observation(scenario.target_ip, scenario, cfg.oracle)
                    if after_verdict is None:
                        result.verified_success = None
                        result.oracle_status = "error"
                        result.oracle_error = after_error
                        oracle_errors += 1
                    elif not after_verdict:
                        result.verified_success = False
                        result.oracle_status = "not_verified"
                    elif result.error:
                        result.verified_success = None
                        result.oracle_status = "unattributed"
                    elif _has_attributed_target_exploit(agent_result, scenario.target_ip):
                        result.verified_success = True
                        result.oracle_status = "verified"
                    else:
                        result.verified_success = None
                        result.oracle_status = "unattributed"

                trials.append(result)

    unscored_trials = sum(t.oracle_status in {"preexisting", "unattributed"} for t in trials)
    report_status = (
        "completed_with_errors"
        if oracle_errors
        else "completed_with_unscored_trials"
        if unscored_trials
        else "completed"
    )
    report_error = (
        f"{oracle_errors} oracle measurement(s) unavailable"
        if oracle_errors
        else f"{unscored_trials} trial(s) lack attributable objective evidence"
        if unscored_trials
        else ""
    )

    report = _build_benchmark_report(
        cfg,
        trials,
        status=report_status,
        error=report_error,
    )
    _persist_report(report, cfg.output_dir)
    return report
