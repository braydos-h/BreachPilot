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
import json
import statistics
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Protocol

__all__ = [
    "Oracle",
    "Scenario",
    "BenchmarkConfig",
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
    goal_name: str                 # e.g. "initial_access", "backdoor"
    description: str = ""
    target_snapshot_id: str = ""   # identifies the target image for reset
    expected_duration_seconds: float = 300.0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class TrialResult:
    """One trial's outcome."""

    scenario_id: str
    condition: str                  # "baseline" | "treatment"
    trial_index: int
    verified_success: bool         # oracle-confirmed
    agent_claimed_success: bool     # the agent's own verdict (for contrast)
    total_actions: int
    duration_seconds: float
    time_to_first_verified_success: float | None = None
    model_id: str = ""
    config_hash: str = ""
    error: str = ""


@dataclass
class BenchmarkReport:
    """Aggregated benchmark results."""

    conditions: list[str]
    trials: list[TrialResult]
    verified_success_rate: dict[str, float]       # condition -> rate
    risk_ratio: float | None                       # treatment / baseline
    risk_ratio_ci_low: float | None                # bootstrap 95% lower
    risk_ratio_ci_high: float | None               # bootstrap 95% upper
    false_positive_rate: dict[str, float]          # agent-claimed but not verified
    actions_per_verified_success: dict[str, float]
    time_to_first_verified_success: dict[str, float | None]
    timestamp: str = ""

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
            "timestamp": self.timestamp,
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
    return hashlib.sha256(
        json.dumps(config, sort_keys=True, default=str).encode()
    ).hexdigest()[:16]


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
            from tools.config_manager import get_ai_provider, get_chatgpt_config
            provider = get_ai_provider(merged)
            if provider == "chatgpt":
                router = build_router(
                    registry, host=ollama_host, provider="chatgpt",
                    chatgpt_config=get_chatgpt_config(merged), config=merged,
                )
            else:
                router = build_router(registry, host=ollama_host)
            model_alias = merged.get("models", {}).get("default_alias", "glm")
            try:
                model_client = router.get_client(model_alias)
            except KeyError:
                if provider == "chatgpt":
                    from tools.model_router import build_model_client_for_provider
                    router.register(model_alias, build_model_client_for_provider(
                        merged, model_alias, request_timeout_seconds=None,
                    ))
                else:
                    from tools.model_router import _build_model_client
                    router.register(model_alias, _build_model_client(
                        model_alias, host=ollama_host, request_timeout_seconds=None,
                    ))
                model_client = router.get_client(model_alias)

            agent_result = await run_exploit_session(
                client=model_client,
                model=model_alias,
                target_ip=scenario.target_ip,
                mode="attack",
                goal=goal,
                exploit_settings=settings,
                config_path=Path("config.yaml"),
                reports_dir=workspace_root,
            )
        # The agent's own claim (for false-positive rate).
        outcome_summary = str(agent_result.get("outcome_summary", "") or "")
        agent_claimed = "compromises: " in outcome_summary and "compromises: 0" not in outcome_summary
    except Exception as exc:
        error = str(exc)[:500]

    duration = time.monotonic() - start
    total_actions = int(agent_result.get("total_actions", 0) or 0)

    result = TrialResult(
        scenario_id=scenario.scenario_id,
        condition=condition,
        trial_index=trial_index,
        verified_success=False,  # set by the oracle below
        agent_claimed_success=agent_claimed,
        total_actions=total_actions,
        duration_seconds=round(duration, 3),
        model_id=str(config.get("models", {}).get("default_alias", "")),
        config_hash=config_hash,
        error=error,
    )
    return result, agent_result


async def run_benchmark(cfg: BenchmarkConfig) -> BenchmarkReport:
    """Run the paired benchmark and return an aggregated report.

    For each scenario × condition × trial:
      1. Reset the target (if ``reset_target_between_trials`` is supplied).
      2. Run the exploit session with the condition's config.
      3. Call the oracle to verify the objective independently.
      4. Record the trial result.

    Then aggregate per condition: verified success rate, false-positive
    rate, actions per verified success, and a bootstrap risk-ratio CI.
    """
    condition_configs = cfg.condition_configs or {
        "baseline": DEFAULT_BASELINE_CONFIG,
        "treatment": DEFAULT_TREATMENT_CONFIG,
    }
    trials: list[TrialResult] = []

    for scenario in cfg.scenarios:
        for condition in cfg.conditions:
            cond_cfg = condition_configs.get(condition, {})
            chash = _config_hash(cond_cfg)
            for trial_idx in range(cfg.trials_per_scenario):
                if cfg.reset_target_between_trials is not None:
                    try:
                        cfg.reset_target_between_trials(scenario)
                    except Exception:
                        pass  # best-effort; a reset failure doesn't abort the trial

                result, agent_result = await _run_one_trial(
                    scenario=scenario,
                    condition=condition,
                    trial_index=trial_idx,
                    config=cond_cfg,
                    config_hash=chash,
                    run_session=cfg.run_session,
                )
                # Oracle verification -- the ONLY source of verified_success.
                try:
                    result.verified_success = bool(cfg.oracle(scenario.target_ip, scenario))
                except Exception:
                    result.verified_success = False

                if result.verified_success and result.time_to_first_verified_success is None:
                    result.time_to_first_verified_success = result.duration_seconds

                trials.append(result)

    # ── Aggregate ──
    conditions = cfg.conditions
    verified_rate: dict[str, float] = {}
    false_pos_rate: dict[str, float] = {}
    actions_per_success: dict[str, float] = {}
    time_to_first: dict[str, float | None] = {}

    for cond in conditions:
        cond_trials = [t for t in trials if t.condition == cond]
        n = len(cond_trials)
        if n == 0:
            continue
        verified = [t for t in cond_trials if t.verified_success]
        claimed_not_verified = [
            t for t in cond_trials
            if t.agent_claimed_success and not t.verified_success
        ]
        verified_rate[cond] = len(verified) / n
        false_pos_rate[cond] = len(claimed_not_verified) / n
        success_actions = [t.total_actions for t in verified]
        actions_per_success[cond] = (
            statistics.mean(success_actions) if success_actions else 0.0
        )
        first_times = [t.time_to_first_verified_success for t in verified if t.time_to_first_verified_success is not None]
        time_to_first[cond] = (
            statistics.mean(first_times) if first_times else None
        )

    # Risk ratio (treatment / baseline) + bootstrap CI.
    rr = None
    rr_low = None
    rr_high = None
    if "baseline" in verified_rate and "treatment" in verified_rate:
        base_rate = verified_rate["baseline"]
        treat_rate = verified_rate["treatment"]
        if base_rate > 0:
            rr = treat_rate / base_rate
            # Paired bootstrap: resample scenarios with replacement.
            import random
            rng = random.Random(42)
            rr_samples: list[float] = []
            scenario_ids = [s.scenario_id for s in cfg.scenarios]
            for _ in range(1000):
                # Resample scenarios (cluster bootstrap).
                resampled = [rng.choice(scenario_ids) for _ in scenario_ids]
                b_wins = t_wins = 0
                for sid in resampled:
                    b_trials = [t for t in trials if t.condition == "baseline" and t.scenario_id == sid]
                    t_trials = [t for t in trials if t.condition == "treatment" and t.scenario_id == sid]
                    b_wins += sum(1 for t in b_trials if t.verified_success)
                    t_wins += sum(1 for t in t_trials if t.verified_success)
                b_rate = b_wins / max(1, len([t for t in trials if t.condition == "baseline"]))
                t_rate = t_wins / max(1, len([t for t in trials if t.condition == "treatment"]))
                if b_rate > 0:
                    rr_samples.append(t_rate / b_rate)
            if rr_samples:
                rr_samples.sort()
                rr_low = rr_samples[int(0.025 * len(rr_samples))]
                rr_high = rr_samples[int(0.975 * len(rr_samples))]

    report = BenchmarkReport(
        conditions=conditions,
        trials=trials,
        verified_success_rate=verified_rate,
        risk_ratio=rr,
        risk_ratio_ci_low=rr_low,
        risk_ratio_ci_high=rr_high,
        false_positive_rate=false_pos_rate,
        actions_per_verified_success=actions_per_success,
        time_to_first_verified_success=time_to_first,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )

    # Persist.
    cfg.output_dir.mkdir(parents=True, exist_ok=True)
    out_path = cfg.output_dir / f"benchmark_{report.timestamp.replace(':', '-')}.json"
    out_path.write_text(json.dumps(report.to_dict(), indent=2, default=str), encoding="utf-8")

    return report
