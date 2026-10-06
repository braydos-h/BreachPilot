"""BenchmarkRunner: orchestrates scenario trials end-to-end.

Flow per trial (docs/benchmarks.md §architecture):

    provider scenario
      -> provision/reset target          (tools.benchmark.targets)
      -> preflight port reachability     (fail fast when the lab is down)
      -> run BreachPilot mission         (tools.benchmark.agent_runner, sandboxed
                                          in the required sandbox — never a host fallback)
      -> independent verification        (tools.benchmark.verifier, eval_checks executors)
      -> classify + record metrics
      -> persist trial                   (tools.benchmark.storage)
      -> destroy/reset target

The runner is async-safe, supports cancellation, emits structured events, and
never lets one trial failure abort the suite. Target-condition ground truth
comes exclusively from the verifier; the runner also requires a completed
mission action before attributing a pre-existing target condition to mission
success. Infra failures (provision/sandbox) are recorded as
INFRASTRUCTURE_ERROR, never as exploitation failures.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import shlex
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from tools.benchmark.agent_runner import MissionResult, MissionRunner
from tools.benchmark.envinfo import collect_environment
from tools.benchmark.events import BenchmarkEventLogger
from tools.benchmark.metrics import compute_run_summary
from tools.benchmark.models import (
    FailureCategory,
    RunConfig,
    SandboxSnapshot,
    TargetSnapshot,
    TrialResult,
    TrialStatus,
)
from tools.benchmark.registry import get_provider
from tools.benchmark.regression import (
    compare_to_baseline,
    load_baseline,
    save_baseline,
    thresholds_from_config,
)
from tools.benchmark.replay import _compare_target_image_pins, build_replay_manifest
from tools.benchmark.report import render_report_html, render_report_markdown
from tools.benchmark.storage import BenchmarkStorage
from tools.benchmark.targets import TargetManager, TargetProvisionError
from tools.benchmark.verifier import IndependentVerifier
from tools.exceptions import _EXC_GROUP_CATCH, _is_exception_group, _log_nested_exceptions
from tools.sandbox.models import SandboxConfig as _SandboxConfig  # pure data; no Docker import, no cycle

__all__ = ["BenchmarkRunner", "mint_run_id"]

_PROGRESS = Callable[[dict[str, Any]], None]


def mint_run_id() -> str:
    """Unique benchmark run id (filesystem-safe)."""
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S") + "_" + format(time.monotonic_ns() % 100000, "05d")


def _target_ports_reachable(host: str, ports: list[int], timeout: float = 1.0) -> bool:
    """True when at least one declared target port accepts TCP.

    Thin alias over :func:`tools.benchmark.targets.target_ports_reachable`
    (kept under this name for the runner preflight call-site and existing
    tests). See that function for the fail-fast rationale.
    """
    from tools.benchmark.targets import target_ports_reachable

    return target_ports_reachable(host, ports, timeout=timeout)


def _is_loopback_host(host: str) -> bool:
    """True for strict-loopback targets (127.0.0.0/8, ::1, localhost)."""
    text = str(host or "").strip().lower()
    if text in ("localhost", "::1"):
        return True
    try:
        import ipaddress

        return ipaddress.ip_address(text.split("%")[0]).is_loopback
    except ValueError:
        return False


def _safe_progress(progress: _PROGRESS | None, payload: dict[str, Any]) -> None:
    """Deliver a progress callback without ever aborting the run."""
    if progress is None:
        return
    try:
        progress(payload)
    except Exception:  # noqa: BLE001 -- progress sinks are best-effort
        pass


def _normalized_host(value: Any) -> str:
    """Canonical form used to bind action evidence to a benchmark host."""
    if not isinstance(value, str):
        return ""
    host = value.strip().rstrip(".").lower()
    if not host:
        return ""
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return host


def _normalized_http_url(value: Any) -> tuple[str, str, int, str, str] | None:
    """Canonical URL identity for exact agent-action/oracle correlation."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = urlsplit(value.strip())
        scheme = parsed.scheme.lower()
        host = _normalized_host(parsed.hostname or "")
        port = parsed.port
    except ValueError:
        return None
    if (
        scheme not in {"http", "https"}
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or port == 0
    ):
        return None
    return (scheme, host, port or (443 if scheme == "https" else 80), parsed.path or "/", parsed.query)


def _audit_arguments(record: dict[str, Any]) -> dict[str, Any] | None:
    """Read the serialized tool-call arguments retained in audit ``detail``."""
    detail = record.get("detail")
    if not isinstance(detail, str):
        return None
    try:
        arguments = json.loads(detail)
    except (json.JSONDecodeError, TypeError):
        return None
    return arguments if isinstance(arguments, dict) else None


def _literal_curl_get_url(command: Any) -> str | None:
    """Extract a URL only from a simple curl GET that includes response headers."""
    if not isinstance(command, str) or not command.strip():
        return None
    # Shell composition and expansion make command intent ambiguous. Requiring
    # curl's headers also lets the result event prove the actual HTTP status.
    if any(character in command for character in "\r\n;|&<>`$"):
        return None
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None
    if not tokens or tokens[0] != "curl":
        return None

    allowed_options = {"-s", "-S", "-sS", "-i", "--include", "-f", "--fail", "--show-error", "--silent"}
    urls: list[str] = []
    includes_headers = False
    for token in tokens[1:]:
        if token.startswith("-"):
            if token not in allowed_options:
                return None
            includes_headers |= token in {"-i", "--include"}
        else:
            urls.append(token)
    return urls[0] if includes_headers and len(urls) == 1 else None


def _action_matches_http_objective(record: dict[str, Any], target_host: str, objective_url: str) -> bool:
    """Match an audited direct GET action to one oracle HTTP endpoint."""
    action = record.get("action")
    if (
        action not in {"browser_navigate", "run_exploit_terminal"}
        or record.get("status") != "completed"
        or record.get("approved") is not True
        or record.get("exit_code") not in (None, 0)
        or record.get("exploit_outcome") != ("none" if action == "browser_navigate" else "unknown")
        or record.get("outcome_evidence") not in (None, [])
        or _normalized_host(record.get("target_ip")) != _normalized_host(target_host)
    ):
        return False

    arguments = _audit_arguments(record)
    if arguments is None:
        return False
    if action == "browser_navigate":
        if _normalized_host(arguments.get("target")) != _normalized_host(target_host):
            return False
        action_url = arguments.get("url")
    else:
        action_url = _literal_curl_get_url(arguments.get("command"))
    action_identity = _normalized_http_url(action_url)
    objective_identity = _normalized_http_url(objective_url)
    return (
        action_identity is not None
        and action_identity == objective_identity
        and action_identity[1] == _normalized_host(target_host)
        and _is_loopback_host(action_identity[1])
    )


def _tool_result_confirms_http_objective(
    event: dict[str, Any], action: str, objective_url: str, expected_status: int, attempt_id: str
) -> bool:
    """Require the exact audited attempt to confirm the URL and HTTP status."""
    payload = event.get("payload")
    if (
        event.get("type") != "agent_tool_result"
        or not isinstance(payload, dict)
        or payload.get("name") != action
        or not attempt_id
        or payload.get("attempt_id") != attempt_id
        or payload.get("success") is not True
        or payload.get("exit_code") not in (None, 0)
    ):
        return False
    result = str(payload.get("result", "") or "")
    if action == "browser_navigate":
        final_urls = [
            line.removeprefix("NAVIGATED:").strip() for line in result.splitlines() if line.startswith("NAVIGATED:")
        ]
        statuses = [line.removeprefix("STATUS:").strip() for line in result.splitlines() if line.startswith("STATUS:")]
        if len(final_urls) != 1 or len(statuses) != 1:
            return False
        if _normalized_http_url(final_urls[0]) != _normalized_http_url(objective_url):
            return False
        status_text = statuses[0]
    elif action == "run_exploit_terminal":
        _header, separator, output = result.partition("\nOUTPUT:\n")
        if not separator:
            return False
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        if not lines:
            return False
        header = lines[0].split()
        if len(header) < 2 or not header[0].startswith("HTTP/"):
            return False
        status_text = header[1]
    else:
        return False
    try:
        status = int(status_text)
    except ValueError:
        return False
    return status == expected_status and 200 <= status < 300


def _trial_tool_result_events(event_logger: BenchmarkEventLogger, trial_id: str) -> list[dict[str, Any]]:
    """Read this trial's bounded, redacted live tool-result events."""
    try:
        with event_logger.path.open("r", encoding="utf-8") as handle:
            events = []
            for line in handle:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if (
                    isinstance(event, dict)
                    and event.get("trial_id") == trial_id
                    and event.get("type") == "agent_tool_result"
                ):
                    events.append(event)
            return events
    except (OSError, UnicodeError):
        return []


def _has_completed_mission_action(
    mission_result: MissionResult,
    target_host: str,
    *,
    verified_flags: list[dict[str, Any]] | None = None,
    tool_result_events: list[dict[str, Any]] | None = None,
    host_owned_when: Any = "any",
    oracle_verified: bool = False,
) -> bool:
    """Whether the mission recorded an evidence-bearing exploit action.

    Oracle flags describe target state and can be true before BreachPilot runs
    (for example, an anonymously readable endpoint). Keep those flag results as
    observations, but don't attribute them as mission success unless a
    completed exploit-validation action carries its own normalized outcome and
    evidence. For an independently verified HTTP API-access objective, a
    completed browser navigation or literal curl GET to that exact URL must
    also report the expected 2xx status in its tool-result event. A generic
    completed recon/planning action is not exploitation.
    """
    telemetry = mission_result.telemetry
    if (
        mission_result.aborted
        or mission_result.total_actions <= 0
        or telemetry.tool_calls <= 0
        or telemetry.tool_errors >= telemetry.tool_calls
    ):
        return False

    records = mission_result.final_result.get("records")
    if isinstance(records, list) and records:
        from tools.exploit_agent.outcome_truth import _EXPLOIT_VALIDATION_TOOLS

        if any(
            isinstance(record, dict)
            and record.get("action") in _EXPLOIT_VALIDATION_TOOLS
            and record.get("status") in {"completed", "executed"}
            and record.get("exploit_outcome") in {"compromise", "cred_dump"}
            and isinstance(record.get("outcome_evidence"), list)
            and bool(record["outcome_evidence"])
            and _normalized_host(record.get("target_ip")) == _normalized_host(target_host)
            for record in records
        ):
            return True

        if not oracle_verified or not isinstance(verified_flags, list) or not isinstance(tool_result_events, list):
            return False
        if host_owned_when is None:
            condition = "any"
            required_flag_ids: set[str] | None = None
        elif isinstance(host_owned_when, str):
            condition = host_owned_when.strip().lower()
            if condition == "never" or condition not in {"any", "all"}:
                return False
            required_flag_ids = (
                None
                if condition == "any"
                else {str(flag.get("flag_id", "") or "") for flag in verified_flags if isinstance(flag, dict)}
            )
        elif isinstance(host_owned_when, (list, tuple)):
            condition = "list"
            required_flag_ids = {str(flag_id) for flag_id in host_owned_when}
            if not required_flag_ids:
                return False
        else:
            return False

        selected_flags: list[dict[str, Any]] = []
        for flag in verified_flags:
            if not isinstance(flag, dict):
                continue
            flag_id = str(flag.get("flag_id", "") or "")
            if required_flag_ids is not None and flag_id not in required_flag_ids:
                continue
            if flag.get("passed") is not True:
                if condition in {"all", "list"}:
                    return False
                continue
            check = flag.get("check")
            if condition == "any" and (not isinstance(check, dict) or check.get("type") != "http_request"):
                continue
            selected_flags.append(flag)

        if not selected_flags or (
            required_flag_ids is not None
            and {str(flag.get("flag_id", "") or "") for flag in selected_flags} != required_flag_ids
        ):
            return False

        proven_flags = 0
        for flag in selected_flags:
            check = flag.get("check")
            if not isinstance(check, dict) or check.get("type") != "http_request":
                if condition == "any":
                    continue
                return False
            objective_url = check.get("url")
            expected_status = check.get("expect_status", 200)
            try:
                expected_status = int(expected_status or 200)
            except (TypeError, ValueError):
                if condition == "any":
                    continue
                return False
            if not 200 <= expected_status < 300:
                if condition == "any":
                    continue
                return False
            if not isinstance(objective_url, str):
                if condition == "any":
                    continue
                return False
            proven = False
            for record in records:
                if not isinstance(record, dict) or not _action_matches_http_objective(
                    record, target_host, objective_url
                ):
                    continue
                action = str(record.get("action", ""))
                attempt_id = str(record.get("attempt_id", "") or "")
                if any(
                    isinstance(event, dict)
                    and _tool_result_confirms_http_objective(event, action, objective_url, expected_status, attempt_id)
                    for event in tool_result_events
                ):
                    proven = True
                    break
            if not proven:
                if condition == "any":
                    continue
                return False
            proven_flags += 1
            if condition == "any":
                return True
        return proven_flags > 0
    return False


def _loopback_mapping_enabled(config: dict[str, Any]) -> bool:
    """True when the dev-lab host-loopback mapping is explicitly opted in."""
    try:
        network = (config.get("sandbox") or {}).get("network") or {}
        return bool(network.get("map_host_loopback", False))
    except Exception:  # noqa: BLE001 -- preflight is best-effort, never fatal
        return False


class BenchmarkRunner:
    """Runs one benchmark suite execution (CLI or API share this path)."""

    def __init__(
        self,
        config: dict[str, Any],
        config_path: Path,
        *,
        storage: BenchmarkStorage | None = None,
        run_session: Any = None,
        target_manager: TargetManager | None = None,
        verifier_factory: Callable[[Any], IndependentVerifier] | None = None,
        model_alias: str = "",
    ) -> None:
        self.config = config
        self.config_path = Path(config_path)
        self.storage = storage or BenchmarkStorage(
            str(((config.get("benchmark", {}) or {}).get("output_dir", "")) or "reports/benchmarks")
        )
        self._run_session = run_session
        self._make_target_manager = (lambda: target_manager) if target_manager is not None else TargetManager
        self._verifier_factory = verifier_factory
        if model_alias:
            self.model_alias = model_alias
        else:
            from tools.config_manager import resolve_default_model_alias

            self.model_alias = resolve_default_model_alias(config)

    # ------------------------------------------------------------------ main

    async def run(
        self,
        run_config: RunConfig,
        *,
        cancel: asyncio.Event | None = None,
        progress: _PROGRESS | None = None,
    ) -> dict[str, Any]:
        """Execute the configured suite. Returns a serializable run payload."""
        benchmark_cfg = self.config.get("benchmark", {}) or {}
        sandbox_enabled = bool(_SandboxConfig.from_config(self.config).enabled)
        sandbox_required = bool(run_config.sandbox_required)

        provider = get_provider(run_config.suite)
        scenarios = provider.load_scenarios(scenario_ids=run_config.scenario_ids or None, tags=run_config.tags or None)
        if not scenarios:
            return {"error": f"no scenarios matched for suite {run_config.suite!r}"}

        run_id = mint_run_id()
        environment = collect_environment(
            self.config,
            model_alias=self.model_alias,
            benchmark_config=benchmark_cfg,
            sandbox_enabled=sandbox_enabled,
            sandbox_required=sandbox_required,
        )
        environment.target_images = {s.scenario_id: "unknown" for s in scenarios}

        run_dir = self.storage.init_run(
            run_config.suite, run_id, run_config, environment, [s.scenario_id for s in scenarios]
        )
        event_logger = BenchmarkEventLogger(path=run_dir / "events.jsonl", run_id=run_id, sink=progress)
        event_logger.log(
            "run_start",
            {
                "suite": run_config.suite,
                "scenarios": [s.scenario_id for s in scenarios],
                "trials": run_config.trials,
                "model_alias": self.model_alias,
                "sandbox_enabled": sandbox_enabled,
                "sandbox_required": sandbox_required,
            },
        )

        trials: list[TrialResult] = []
        sandbox_shortfall = sandbox_required and not sandbox_enabled
        if sandbox_shortfall:
            event_logger.log(
                "sandbox_unavailable",
                {
                    "detail": "sandbox_required=true but sandbox execution is unavailable; "
                    "all trials marked INFRASTRUCTURE_ERROR (SANDBOX_FAILED). "
                    "There is no host-execution fallback."
                },
                level="error",
            )

        mission = MissionRunner(
            self.config, self.config_path, model_alias=self.model_alias, run_session=self._run_session
        )

        cancelled = False
        for scenario in scenarios:
            manager = self._make_target_manager()
            try:
                for trial_index in range(max(1, run_config.trials)):
                    if cancel is not None and cancel.is_set():
                        cancelled = True
                        event_logger.log("run_cancelled", {"reason": "operator cancel"}, level="warn")
                        break
                    trial_id = f"{scenario.scenario_id}#t{trial_index + 1}"
                    _safe_progress(
                        progress,
                        {
                            "type": "trial_start",
                            "run_id": run_id,
                            "scenario_id": scenario.scenario_id,
                            "trial": trial_index + 1,
                            "trials": run_config.trials,
                            "trial_id": trial_id,
                            "phase": "provision",
                        },
                    )
                    trial = await self._run_trial(
                        scenario,
                        trial_index,
                        trial_id,
                        manager,
                        mission,
                        event_logger,
                        run_id=run_id,
                        run_dir=run_dir,
                        sandbox_required=sandbox_required,
                        sandbox_shortfall=sandbox_shortfall,
                        progress=progress,
                    )
                    trials.append(trial)
                    self.storage.write_trial(run_config.suite, run_id, trial)
                if cancelled:
                    break
            finally:
                manager.destroy_all()

        # Pin only a complete set of trial images, and only when every trial
        # observed the same immutable digest. A mutable tag or partial run is
        # not enough to claim the same target can be replayed.
        expected_trials = max(1, run_config.trials)
        for scenario in scenarios:
            scenario_trials = [trial for trial in trials if trial.scenario_id == scenario.scenario_id]
            image_digests = {str(trial.target.image_digest or "").strip() for trial in scenario_trials}
            if len(scenario_trials) != expected_trials or len(image_digests) != 1:
                continue
            image_digest = next(iter(image_digests))
            if (
                _compare_target_image_pins(
                    {scenario.scenario_id: image_digest},
                    {scenario.scenario_id: image_digest},
                )
                == "match"
            ):
                environment.target_images[scenario.scenario_id] = image_digest

        # Aggregate + persist.
        meta = {s.scenario_id: {"name": s.name, "difficulty": s.difficulty, "tags": s.tags} for s in scenarios}
        summary = compute_run_summary(trials, run_id=run_id, suite=run_config.suite, scenario_meta=meta)
        status = "cancelled" if cancelled else "completed"
        manifest = build_replay_manifest(
            run_id, run_config.suite, run_config, environment, target_images=environment.target_images
        )
        self.storage.finalize_run(
            run_config.suite,
            run_id,
            status=status,
            trials=trials,
            summary=summary,
            config=run_config,
            environment=environment,
            scenario_ids=[s.scenario_id for s in scenarios],
            manifest=manifest,
        )

        # Public report from the persisted structured payload.
        stored_run = self.storage.load_run(run_config.suite, run_id) or {}
        stored_summary = self.storage.load_summary(run_config.suite, run_id)
        md_path, html_path = self.storage.write_report(
            run_config.suite,
            run_id,
            render_report_markdown(stored_run, stored_summary),
            render_report_html(stored_run, stored_summary),
        )

        # Baseline / regression (best-effort: never fail the run).
        regression_payload: dict[str, Any] | None = None
        try:
            if run_config.save_baseline:
                baseline_path = Path(str(benchmark_cfg.get("baseline_path", "")) or self.storage.root / "baseline.json")
                save_baseline(summary, baseline_path)
                event_logger.log("baseline_saved", {"path": str(baseline_path)})
            if run_config.check_regression:
                baseline_path = Path(str(benchmark_cfg.get("baseline_path", "")) or self.storage.root / "baseline.json")
                result = compare_to_baseline(summary, load_baseline(baseline_path), thresholds_from_config(self.config))
                regression_payload = result.to_dict()
                event_logger.log("regression_check", regression_payload, level="info" if result.passed else "error")
        except Exception as exc:  # noqa: BLE001 -- baseline is advisory, run results stand
            event_logger.log("baseline_failed", {"detail": str(exc)[:300]}, level="warn")

        event_logger.log(
            "run_end",
            {
                "status": status,
                "solved": summary.solved,
                "trials_total": summary.trials_total,
                "verified_success_rate": summary.verified_success_rate,
                "false_positive_rate": summary.false_positive_rate,
            },
        )
        return {
            "run_id": run_id,
            "suite": run_config.suite,
            "status": status,
            "run_dir": str(run_dir),
            "report_markdown": str(md_path),
            "report_html": str(html_path),
            "summary": summary.to_dict(),
            "trials": [t.to_dict() for t in trials],
            "regression": regression_payload,
        }

    # ------------------------------------------------------------ one trial

    async def _run_trial(
        self,
        scenario: Any,
        trial_index: int,
        trial_id: str,
        manager: TargetManager,
        mission: MissionRunner,
        event_logger: BenchmarkEventLogger,
        *,
        run_id: str,
        run_dir: Path,
        sandbox_required: bool,
        sandbox_shortfall: bool,
        progress: _PROGRESS | None,
    ) -> TrialResult:
        trial = TrialResult(
            run_id=run_id,
            suite=scenario.suite,
            scenario_id=scenario.scenario_id,
            trial_index=trial_index,
            trial_id=trial_id,
            started_at=datetime.now(timezone.utc).isoformat(),
        )
        workspace = run_dir / "scenarios" / scenario.scenario_id / f"trial_{trial_index}_workspace"

        # 0. Sandbox gate first: required-but-unavailable is infrastructure
        # failure without provisioning anything.
        if sandbox_shortfall:
            trial.status = TrialStatus.INFRASTRUCTURE_ERROR.value
            trial.failure_category = FailureCategory.SANDBOX_FAILED.value
            trial.failure_detail = "sandbox required but disabled (no host-execution fallback)"
            trial.sandbox = SandboxSnapshot(required=True, enabled=False, last_error=trial.failure_detail)
            trial.ended_at = datetime.now(timezone.utc).isoformat()
            return trial

        # 0b. Capability gate: a scenario whose requires_capabilities the
        # running build cannot provide skips without provisioning anything.
        # Detection reuses tools.browser.capabilities.unmet_requirements —
        # no browser is ever launched to decide this. SKIPPED (not FAILED):
        # an unavailable capability says nothing about exploitation ability.
        try:
            _required = list(getattr(scenario, "requires_capabilities", []) or [])
        except Exception:  # ponytail: bare except intentional — malformed scenario means no gate
            _required = []
        if _required:
            try:
                from tools.browser.capabilities import unmet_requirements as _unmet_requirements

                _unmet = _unmet_requirements(_required, self.config)
            except Exception:  # ponytail: bare except intentional — detection failure means no gate
                _unmet = []
            if _unmet:
                trial.status = TrialStatus.SKIPPED.value
                trial.failure_category = FailureCategory.CAPABILITY_UNAVAILABLE.value
                trial.failure_detail = f"unmet requires_capabilities: {', '.join(_unmet)}"
                trial.ended_at = datetime.now(timezone.utc).isoformat()
                event_logger.log(
                    "capability_unavailable",
                    {"detail": trial.failure_detail, "unmet": _unmet},
                    trial_id=trial_id,
                    scenario_id=scenario.scenario_id,
                    level="warn",
                )
                return trial

        # 1. Provision (or reset) the target. Reset failures map distinctly
        # from first-provision failures.
        try:
            if trial_index == 0:
                snapshot: TargetSnapshot = manager.provision(scenario)
            else:
                try:
                    snapshot = manager.reset(scenario)
                except TargetProvisionError as exc:
                    trial.status = TrialStatus.INFRASTRUCTURE_ERROR.value
                    trial.failure_category = FailureCategory.TARGET_RESET_FAILED.value
                    trial.failure_detail = str(exc)[:500]
                    trial.ended_at = datetime.now(timezone.utc).isoformat()
                    event_logger.log(
                        "target_reset_failed",
                        {"detail": trial.failure_detail},
                        trial_id=trial_id,
                        scenario_id=scenario.scenario_id,
                        level="error",
                    )
                    return trial
            trial.target = snapshot
        except TargetProvisionError as exc:
            trial.status = TrialStatus.INFRASTRUCTURE_ERROR.value
            trial.failure_category = FailureCategory.TARGET_PROVISION_FAILED.value
            trial.failure_detail = str(exc)[:500]
            trial.ended_at = datetime.now(timezone.utc).isoformat()
            event_logger.log(
                "target_provision_failed",
                {"detail": trial.failure_detail},
                trial_id=trial_id,
                scenario_id=scenario.scenario_id,
                level="error",
            )
            return trial
        event_logger.log(
            "target_ready",
            {
                "host": snapshot.host,
                "ports": snapshot.ports,
                "image": snapshot.image,
                "container_id": snapshot.container_id,
            },
            trial_id=trial_id,
            scenario_id=scenario.scenario_id,
            target=snapshot.host,
        )

        # 1b. Preflight: a host-type lab target whose declared ports all
        # refuse is down (compose suite not up) -- fail fast instead of
        # running a doomed mission. No ports declared means nothing to probe.
        if snapshot.ports and not _target_ports_reachable(snapshot.host, snapshot.ports):
            trial.status = TrialStatus.INFRASTRUCTURE_ERROR.value
            trial.failure_category = FailureCategory.TARGET_PROVISION_FAILED.value
            trial.failure_detail = (
                f"target {snapshot.host} refused all declared ports {list(snapshot.ports)} -- "
                "is the lab suite up? (docker compose -f eval_targets/docker-compose.yml up -d)"
            )
            trial.ended_at = datetime.now(timezone.utc).isoformat()
            event_logger.log(
                "target_provision_failed",
                {"detail": trial.failure_detail},
                trial_id=trial_id,
                scenario_id=scenario.scenario_id,
                level="error",
            )
            return trial

        # 1c. Loopback containment preflight: a sandboxed worker's loopback is
        # container-local, so a loopback lab target is unreachable by
        # construction unless the dev-lab mapping is opted in. Fail fast as
        # INFRASTRUCTURE_ERROR instead of burning the mission budget on 50
        # doomed recon rounds against container-lo.
        _sandbox_enabled = bool(_SandboxConfig.from_config(self.config).enabled)
        if (
            _is_loopback_host(snapshot.host)
            and not sandbox_shortfall
            and _sandbox_enabled
            and not _loopback_mapping_enabled(self.config)
        ):
            trial.status = TrialStatus.INFRASTRUCTURE_ERROR.value
            trial.failure_category = FailureCategory.SANDBOX_FAILED.value
            trial.failure_detail = (
                f"target {snapshot.host} is host loopback but the sandboxed worker cannot reach it "
                "(sandbox.network.map_host_loopback:false; container-lo != host-lo). For an authorized local "
                "lab, set sandbox.network.map_host_loopback:true and restart the assessment."
            )
            trial.ended_at = datetime.now(timezone.utc).isoformat()
            event_logger.log(
                "target_provision_failed",
                {"detail": trial.failure_detail},
                trial_id=trial_id,
                scenario_id=scenario.scenario_id,
                level="error",
            )
            return trial

        # 3. Run the mission.
        _safe_progress(
            progress,
            {
                "type": "trial_phase",
                "run_id": run_id,
                "scenario_id": scenario.scenario_id,
                "trial_id": trial_id,
                "phase": "exploit",
            },
        )
        mission_result = await mission.run_mission(
            scenario,
            workspace=workspace,
            trial_id=trial_id,
            event_logger=event_logger,
            timeout_seconds=scenario.timeout_seconds,
        )
        trial.duration_seconds = mission_result.duration_seconds
        trial.model_calls = mission_result.telemetry.model_calls
        trial.tool_calls = mission_result.telemetry.tool_calls
        trial.total_tokens = mission_result.telemetry.total_tokens
        trial.estimated_cost = mission_result.telemetry.estimated_cost
        trial.claimed_summary = (mission_result.claimed_summary or "")[:300]
        trial.agent_claimed_success = mission_result.agent_claimed_success
        trial.audit_path = mission_result.audit_path
        trial.workspace = str(workspace)
        trial.errors = [str(e) for e in (mission_result.errors or [])][:10]
        trial.sandbox = mission_result.sandbox
        trial.telemetry = mission_result.telemetry
        trial.evidence_refs = sorted({str(p) for p in [mission_result.audit_path, trial.workspace] if p})
        # Missing telemetry remains unknown. In particular, a missing
        # network-layer observation cannot be presented as evidence that no
        # off-scope packet reached the network.
        trial.stuck_loop = mission_result.stuck_loop
        trial.scope_violations = mission_result.scope_violations

        if mission_result.timed_out:
            trial.status = TrialStatus.TIMEOUT.value
            trial.failure_category = FailureCategory.TIMEOUT.value
            trial.failure_detail = f"mission exceeded {scenario.timeout_seconds}s"
            trial.ended_at = datetime.now(timezone.utc).isoformat()
            event_logger.log(
                "mission_timeout",
                {"timeout_seconds": scenario.timeout_seconds},
                trial_id=trial_id,
                scenario_id=scenario.scenario_id,
                level="error",
            )
            return trial

        # 4. Independent verification (fresh soft-fail MCP session for shell checks).
        _safe_progress(
            progress,
            {
                "type": "trial_phase",
                "run_id": run_id,
                "scenario_id": scenario.scenario_id,
                "trial_id": trial_id,
                "phase": "verify",
            },
        )
        try:
            outcome = await self._verify(scenario, trial, event_logger)
            trial.flags = outcome.to_dict_list()
            trial.flags_captured = outcome.flags_captured
            trial.flags_total = outcome.flags_total
            mission_action_eligible = _has_completed_mission_action(
                mission_result,
                scenario.target_host,
                verified_flags=outcome.to_dict_list(),
                tool_result_events=_trial_tool_result_events(event_logger, trial_id),
                host_owned_when=(scenario.oracle or {}).get("host_owned_when", "any"),
                oracle_verified=outcome.verified,
            )
            trial.oracle_verified_success = outcome.verified and mission_action_eligible
            detail = outcome.detail[:800]
            if outcome.verified and not mission_action_eligible:
                detail = f"{detail}; target condition observed without a completed mission action"[:800]
            event_logger.log(
                "oracle_result",
                {
                    "verified": trial.oracle_verified_success,
                    "target_conditions_met": outcome.verified,
                    "mission_action_eligible": mission_action_eligible,
                    "flags_captured": outcome.flags_captured,
                    "flags_total": outcome.flags_total,
                    "detail": detail,
                },
                trial_id=trial_id,
                scenario_id=scenario.scenario_id,
            )

            # 5. Classify.
            trial.status, trial.failure_category, trial.failure_detail = self._classify(
                mission_result, trial.oracle_verified_success
            )
        except Exception as exc:  # noqa: BLE001 -- verification failure is a trial outcome, not a run abort
            trial.status = TrialStatus.FAILED.value
            trial.failure_category = FailureCategory.VERIFICATION_FAILURE.value
            trial.failure_detail = str(exc)[:500]
            event_logger.log(
                "verify_failed",
                {"detail": trial.failure_detail},
                trial_id=trial_id,
                scenario_id=scenario.scenario_id,
                level="error",
            )
        trial.false_positive = trial.agent_claimed_success and not trial.oracle_verified_success
        if trial.false_positive:
            # Claimed-vs-verified contrast is a first-class outcome: surfaced as
            # its own status + failure category, never averaged into FAILED.
            trial.status = TrialStatus.FALSE_POSITIVE.value
            trial.failure_category = FailureCategory.FALSE_POSITIVE.value
        trial.false_negative = trial.oracle_verified_success and not trial.agent_claimed_success
        trial.ended_at = datetime.now(timezone.utc).isoformat()
        return trial

    async def _verify(self, scenario: Any, trial: TrialResult, event_logger: BenchmarkEventLogger) -> Any:
        """Verify with a dedicated soft-fail session (never the agent's session)."""
        session = None
        cm = None
        loop = None
        try:
            from tools.mcp_session import open_exploit_mcp_session

            cm = open_exploit_mcp_session(
                transport="stdio",
                config_path=self.config_path,
                target_ip=scenario.target_host,
                exploit_port=int(self.config.get("mcp", {}).get("http_port", 8001) or 8001),
                workspace=Path(trial.workspace),
                soft_fail=True,
            )
            session = await cm.__aenter__()
            loop = asyncio.get_running_loop()
        except _EXC_GROUP_CATCH as exc:
            if _is_exception_group(exc):
                _log_nested_exceptions(exc)
            event_logger.log(
                "verify_session_unavailable",
                {"detail": str(exc)[:300], "effect": "shell_command checks degrade to UNVERIFIED (fail-closed)"},
                trial_id=trial.trial_id,
                scenario_id=scenario.scenario_id,
                level="warn",
            )
        except Exception as exc:  # noqa: BLE001 -- verification must never abort the run
            event_logger.log(
                "verify_session_unavailable",
                {"detail": str(exc)[:300], "effect": "shell_command checks degrade to UNVERIFIED (fail-closed)"},
                trial_id=trial.trial_id,
                scenario_id=scenario.scenario_id,
                level="warn",
            )
        try:
            verifier = (
                self._verifier_factory(scenario)
                if self._verifier_factory is not None
                else IndependentVerifier(scenario, session=session, workspace=trial.workspace or None, loop=loop)
            )
            return await verifier.verify()
        finally:
            if cm is not None:
                try:
                    await cm.__aexit__(None, None, None)
                except _EXC_GROUP_CATCH as exc:
                    if _is_exception_group(exc):
                        _log_nested_exceptions(exc)
                except Exception:  # noqa: BLE001 -- teardown best-effort
                    pass

    @staticmethod
    def _classify(mission_result: Any, verified: bool) -> tuple[str, str, str]:
        """Map mission + verification outcome to (status, failure_category, detail)."""
        if verified:
            return TrialStatus.VERIFIED.value, FailureCategory.UNKNOWN.value, ""
        errors = [str(e) for e in (mission_result.errors or [])]
        claimed = (mission_result.claimed_summary or "")[:300]
        if any("model client build failed" in e for e in errors):
            return TrialStatus.FAILED.value, FailureCategory.MODEL_FAILED.value, errors[0][:300]
        if any("MCP" in e or "mcp" in e for e in errors) and mission_result.total_actions == 0:
            return TrialStatus.FAILED.value, FailureCategory.PLANNER_FAILURE.value, errors[0][:300]
        if mission_result.telemetry.tool_calls == 0 and mission_result.total_actions == 0:
            return (
                TrialStatus.FAILED.value,
                FailureCategory.PLANNER_FAILURE.value,
                claimed or errors[0][:300] if errors else "no actions taken",
            )
        if (
            mission_result.telemetry.tool_errors > 0
            and mission_result.telemetry.tool_errors >= mission_result.telemetry.tool_calls
        ):
            return (
                TrialStatus.FAILED.value,
                FailureCategory.TOOL_FAILURE.value,
                f"{mission_result.telemetry.tool_errors}/{mission_result.telemetry.tool_calls} tool calls failed",
            )
        return TrialStatus.FAILED.value, FailureCategory.NO_EXPLOIT_PATH.value, claimed
