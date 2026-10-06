"""Integration-style tests for the BenchmarkRunner (fully mocked execution)."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from tools.benchmark import BenchmarkScenario, seed_fake_suite
from tools.benchmark.agent_runner import MissionResult, SandboxSnapshot, TrialTelemetry
from tools.benchmark.models import FailureCategory, RunConfig, TargetSnapshot, TrialResult, TrialStatus
from tools.benchmark.runner import BenchmarkRunner, _has_completed_mission_action
from tools.benchmark.targets import TargetProvisionError
from tools.exploit_agent.outcome_truth import normalize_action_result


def _scenario(scenario_id: str = "s1", *, oracle_flags: list[dict] | None = None, **kw) -> BenchmarkScenario:
    return BenchmarkScenario(
        suite="fake",
        scenario_id=scenario_id,
        name=f"Scenario {scenario_id}",
        target_type="host",
        target_host="127.0.0.1",
        tags=["web"],
        oracle={
            "flags": oracle_flags if oracle_flags is not None else [{"id": "f1", "check": {}}],
            "host_owned_when": "any",
        },
        **kw,
    )


def _config(tmp_path: Path, **bm) -> dict[str, Any]:
    # Execution is mocked in these tests, but configuration must retain the
    # production containment invariant.
    return {
        "benchmark": {"output_dir": str(tmp_path / "bench"), "sandbox_required": False, **bm},
        "models": {"default_alias": "glm"},
        "mcp": {"http_port": 8001},
        # The fake suite targets host loopback, so allow its worker network
        # mapping explicitly while keeping execution contained.
        "sandbox": {"enabled": True, "network": {"map_host_loopback": True}},
    }


class _FakeMission:
    """MissionRunner stand-in returning canned MissionResults."""

    def __init__(self, outcomes: list[MissionResult]) -> None:
        self.outcomes = list(outcomes)
        self.calls: list[str] = []

    async def run_mission(self, scenario, *, workspace, trial_id, event_logger=None, goal=None, timeout_seconds=None):
        self.calls.append(trial_id)
        workspace.mkdir(parents=True, exist_ok=True)
        outcome = self.outcomes.pop(0) if self.outcomes else MissionResult()
        return outcome


def _verified_mission(**kw) -> MissionResult:
    base = dict(
        total_actions=5,
        telemetry=TrialTelemetry(model_calls=10, tool_calls=8, total_tokens=1000),
        final_result={
            "records": [
                {
                    "action": "run_exploit_terminal",
                    "target_ip": "127.0.0.1",
                    "status": "completed",
                    "exploit_outcome": "compromise",
                    "outcome_evidence": ["shell:uid-zero"],
                }
            ]
        },
    )
    base.update(kw)
    return MissionResult(**base)


@pytest.mark.parametrize(
    "marker",
    [
        "COMPROMISE: xz_backdoor_suspected target=10.0.0.50 openssh=9.8p1",
        "COMPROMISE: regresshion_vulnerable target=10.0.0.50 version=9.6p1",
        "COMPROMISE: panos_cmd_injection_sent target=10.0.0.50",
    ],
)
def test_generated_detection_markers_do_not_qualify_benchmark_mission(marker: str) -> None:
    """Tool-authored claims cannot turn pre-existing oracle flags into mission success."""
    normalized = normalize_action_result(tool_name="run_attack_module", result_text=marker)
    mission = MissionResult(
        total_actions=1,
        telemetry=TrialTelemetry(tool_calls=1),
        final_result={
            "records": [
                {
                    "action": "run_attack_module",
                    "status": "completed",
                    "exploit_outcome": normalized.exploit_outcome,
                    "outcome_evidence": normalized.evidence,
                }
            ]
        },
    )

    assert _has_completed_mission_action(mission, "127.0.0.1") is False


def test_completed_action_must_match_benchmark_target():
    mission = _verified_mission(
        final_result={
            "records": [
                {
                    "action": "run_exploit_terminal",
                    "target_ip": "192.0.2.88",
                    "status": "completed",
                    "exploit_outcome": "compromise",
                    "outcome_evidence": ["shell:uid-zero"],
                }
            ]
        }
    )

    assert _has_completed_mission_action(mission, "127.0.0.1") is False
    assert _has_completed_mission_action(mission, "192.0.2.88") is True


def _api_flag(
    url: str, *, flag_id: str = "api_access", passed: bool = True, expect_status: int = 200
) -> dict[str, Any]:
    return {
        "flag_id": flag_id,
        "passed": passed,
        "check": {"type": "http_request", "url": url, "expect_status": expect_status},
    }


def _api_action_record(url: str, *, action: str = "browser_navigate", **overrides) -> dict[str, Any]:
    arguments = (
        {"target": "127.0.0.1", "session_id": "browser-session", "url": url}
        if action == "browser_navigate"
        else {"command": f"curl -s -i {url}"}
    )
    record = {
        "attempt_id": "attempt-1",
        "action": action,
        "target_ip": "127.0.0.1",
        "approved": True,
        "status": "completed",
        "exit_code": None,
        "exploit_outcome": "none" if action == "browser_navigate" else "unknown",
        "outcome_evidence": [],
        "detail": json.dumps(arguments),
    }
    record.update(overrides)
    return record


def _api_mission(record: dict[str, Any]) -> MissionResult:
    return MissionResult(
        total_actions=1,
        telemetry=TrialTelemetry(tool_calls=1),
        final_result={"records": [record]},
    )


def _browser_result_event(
    url: str, *, status: int = 200, name: str = "browser_navigate", attempt_id: str = "attempt-1"
) -> dict[str, Any]:
    return {
        "type": "agent_tool_result",
        "payload": {
            "name": name,
            "attempt_id": attempt_id,
            "success": True,
            "exit_code": None,
            "result": f"NAVIGATED: {url}\nSTATUS: {status}\nNEXT: browser_observe",
        },
    }


def _terminal_result_event(status: int = 200, *, attempt_id: str = "attempt-1") -> dict[str, Any]:
    return {
        "type": "agent_tool_result",
        "payload": {
            "name": "run_exploit_terminal",
            "attempt_id": attempt_id,
            "success": True,
            "exit_code": None,
            "result": f"TERMINAL_RESULT: success\nOUTPUT:\nHTTP/1.1 {status} OK\n",
        },
    }


def test_api_objective_needs_verified_matching_direct_get_action():
    url = "http://127.0.0.1:8083/version"
    mission = _api_mission(_api_action_record(url))

    assert (
        _has_completed_mission_action(
            mission,
            "127.0.0.1",
            verified_flags=[_api_flag(url)],
            tool_result_events=[_browser_result_event(url)],
            host_owned_when="any",
            oracle_verified=True,
        )
        is True
    )


def test_api_all_condition_requires_direct_evidence_for_every_required_endpoint():
    first_url = "http://127.0.0.1:8083/version"
    second_url = "http://127.0.0.1:8083/admin"
    first_record = _api_action_record(first_url)
    second_record = _api_action_record(second_url, attempt_id="attempt-2")
    mission = _api_mission(first_record)
    mission.final_result["records"].append(second_record)
    mission.total_actions = 2
    mission.telemetry.tool_calls = 2
    flags = [_api_flag(first_url, flag_id="version"), _api_flag(second_url, flag_id="admin")]
    events = [
        _browser_result_event(first_url),
        _browser_result_event(second_url, attempt_id="attempt-2"),
    ]

    assert (
        _has_completed_mission_action(
            mission,
            "127.0.0.1",
            verified_flags=flags,
            tool_result_events=events,
            host_owned_when="all",
            oracle_verified=True,
        )
        is True
    )

    assert (
        _has_completed_mission_action(
            mission,
            "127.0.0.1",
            verified_flags=flags,
            tool_result_events=events[:1],
            host_owned_when="all",
            oracle_verified=True,
        )
        is False
    )


def test_api_list_condition_requires_every_named_flag_but_any_uses_one_http_objective():
    version_url = "http://127.0.0.1:8083/version"
    admin_url = "http://127.0.0.1:8083/admin"
    mission = _api_mission(_api_action_record(version_url))
    flags = [
        {"flag_id": "unrelated", "passed": True, "check": {"type": "tcp_port", "port": 8083}},
        _api_flag(version_url, flag_id="version"),
        _api_flag(admin_url, flag_id="admin"),
    ]
    events = [_browser_result_event(version_url)]

    assert (
        _has_completed_mission_action(
            mission,
            "127.0.0.1",
            verified_flags=flags,
            tool_result_events=events,
            host_owned_when="any",
            oracle_verified=True,
        )
        is True
    )
    assert (
        _has_completed_mission_action(
            mission,
            "127.0.0.1",
            verified_flags=flags,
            tool_result_events=events,
            host_owned_when=["version", "admin"],
            oracle_verified=True,
        )
        is False
    )


def test_api_objective_must_be_on_the_benchmark_target_host():
    url = "http://localhost:8083/version"
    mission = _api_mission(_api_action_record(url))

    assert (
        _has_completed_mission_action(
            mission,
            "127.0.0.1",
            verified_flags=[_api_flag(url)],
            tool_result_events=[_browser_result_event(url)],
            host_owned_when="any",
            oracle_verified=True,
        )
        is False
    )


@pytest.mark.parametrize(
    ("record", "flag", "oracle_verified", "host_owned_when"),
    [
        (_api_action_record("http://127.0.0.1:8083/other"), _api_flag("http://127.0.0.1:8083/version"), True, "any"),
        (
            _api_action_record("http://127.0.0.1:8083/version", action="web_search"),
            _api_flag("http://127.0.0.1:8083/version"),
            True,
            "any",
        ),
        (
            _api_action_record(
                "http://127.0.0.1:8083/version",
                exploit_outcome="unverified_claim",
                outcome_evidence=["claim:COMPROMISE:admin_access"],
            ),
            _api_flag("http://127.0.0.1:8083/version"),
            True,
            "any",
        ),
        (
            _api_action_record("http://127.0.0.1:8083/version"),
            _api_flag("http://127.0.0.1:8083/version", passed=False),
            True,
            "any",
        ),
        (
            _api_action_record("http://127.0.0.1:8083/version"),
            _api_flag("http://127.0.0.1:8083/version", expect_status=401),
            True,
            "any",
        ),
        (_api_action_record("http://127.0.0.1:8083/version"), _api_flag("http://127.0.0.1:8083/version"), False, "any"),
        (
            _api_action_record("http://127.0.0.1:8083/version"),
            _api_flag("http://127.0.0.1:8083/version"),
            True,
            ["other_flag"],
        ),
        (
            _api_action_record("http://127.0.0.1:8083/version"),
            _api_flag("http://127.0.0.1:8083/version"),
            True,
            "never",
        ),
    ],
    ids=[
        "wrong-endpoint",
        "generic-action",
        "unverified-claim",
        "oracle-failed",
        "non-access-status",
        "oracle-unverified",
        "flag-not-in-ownership-condition",
        "negative-control",
    ],
)
def test_api_objective_rejects_unbound_or_unverified_actions(record, flag, oracle_verified, host_owned_when):
    assert (
        _has_completed_mission_action(
            _api_mission(record),
            "127.0.0.1",
            verified_flags=[flag],
            tool_result_events=[_browser_result_event("http://127.0.0.1:8083/version")],
            host_owned_when=host_owned_when,
            oracle_verified=oracle_verified,
        )
        is False
    )


def test_api_objective_does_not_trust_arbitrary_http_200_text():
    url = "http://127.0.0.1:8083/version"
    terminal_event = _terminal_result_event()
    terminal_event["payload"]["result"] = "TERMINAL_RESULT: success\nOUTPUT:\nHTTP 200 OK\n"
    mission = _api_mission(
        _api_action_record(
            url,
            action="run_exploit_terminal",
            detail=json.dumps({"command": "printf 'HTTP 200 OK'"}),
        )
    )

    assert (
        _has_completed_mission_action(
            mission,
            "127.0.0.1",
            verified_flags=[_api_flag(url)],
            tool_result_events=[terminal_event],
            host_owned_when="any",
            oracle_verified=True,
        )
        is False
    )


def test_api_objective_does_not_pair_another_attempts_http_output():
    url = "http://127.0.0.1:8083/version"
    curl_record = _api_action_record(
        url,
        action="run_exploit_terminal",
        attempt_id="curl-attempt",
        detail=json.dumps({"command": f"curl -s -i {url}"}),
    )
    unrelated_record = _api_action_record(
        url,
        action="run_exploit_terminal",
        attempt_id="printf-attempt",
        detail=json.dumps({"command": "printf 'HTTP/1.1 200 OK'"}),
    )
    mission = _api_mission(curl_record)
    mission.total_actions = 2
    mission.final_result["records"].append(unrelated_record)
    mission.telemetry.tool_calls = 2

    assert (
        _has_completed_mission_action(
            mission,
            "127.0.0.1",
            verified_flags=[_api_flag(url)],
            tool_result_events=[_terminal_result_event(attempt_id="printf-attempt")],
            host_owned_when="any",
            oracle_verified=True,
        )
        is False
    )


@pytest.mark.parametrize(
    ("command", "status", "expected"),
    [
        ("curl -s -i http://127.0.0.1:8083/version", 200, True),
        ("curl -s http://127.0.0.1:8083/version", 200, False),
        ("curl -s -i http://127.0.0.1:8083/version", 401, False),
    ],
    ids=["direct-success", "status-header-required", "non-success-status"],
)
def test_api_objective_accepts_only_literal_curl_get_with_matching_status(command, status, expected):
    url = "http://127.0.0.1:8083/version"
    mission = _api_mission(
        _api_action_record(
            url,
            action="run_exploit_terminal",
            detail=json.dumps({"command": command}),
        )
    )

    assert (
        _has_completed_mission_action(
            mission,
            "127.0.0.1",
            verified_flags=[_api_flag(url)],
            tool_result_events=[_terminal_result_event(status)],
            host_owned_when="any",
            oracle_verified=True,
        )
        is expected
    )


@pytest.mark.parametrize(
    ("event", "expected"),
    [
        (_browser_result_event("http://127.0.0.1:8083/version", status=401), False),
        (_browser_result_event("http://127.0.0.1:8083/other"), False),
        (_browser_result_event("http://127.0.0.1:8083/version"), True),
    ],
    ids=["non-success-status", "redirected-away", "matching-response"],
)
def test_api_objective_requires_matching_browser_response(event, expected):
    url = "http://127.0.0.1:8083/version"
    mission = _api_mission(_api_action_record(url))

    assert (
        _has_completed_mission_action(
            mission,
            "127.0.0.1",
            verified_flags=[_api_flag(url)],
            tool_result_events=[event],
            host_owned_when="any",
            oracle_verified=True,
        )
        is expected
    )


def _make_runner(tmp_path, config, mission, *, verifier_factory=None, target_manager=None):
    runner = BenchmarkRunner(
        config, Path("config.yaml"), verifier_factory=verifier_factory, target_manager=target_manager
    )
    runner._make_mission = lambda: mission  # type: ignore[attr-defined]
    return runner


def test_verify_opens_independent_session_in_trial_workspace(monkeypatch, tmp_path):
    workspace = tmp_path / "trial-workspace"
    workspace.mkdir()
    session_sentinel = object()
    result = object()
    session_args = {}

    class _SessionContext:
        async def __aenter__(self):
            return session_sentinel

        async def __aexit__(self, *_args):
            return False

    def _open_session(**kwargs):
        session_args.update(kwargs)
        return _SessionContext()

    class _Verifier:
        def __init__(self, _scenario, *, session, workspace, loop):
            assert session is session_sentinel
            assert workspace == str(tmp_path / "trial-workspace")
            assert loop is not None

        async def verify(self):
            return result

    monkeypatch.setattr("tools.mcp_session.open_exploit_mcp_session", _open_session)
    monkeypatch.setattr("tools.benchmark.runner.IndependentVerifier", _Verifier)
    runner = BenchmarkRunner(_config(tmp_path), Path("config.yaml"))
    trial = TrialResult(
        run_id="run-1",
        suite="fake",
        scenario_id="s1",
        trial_index=0,
        trial_id="s1#t0",
        workspace=str(workspace),
    )
    outcome = asyncio.run(runner._verify(_scenario(), trial, event_logger=object()))

    assert outcome is result
    assert session_args["workspace"] == workspace
    assert session_args["soft_fail"] is True


@pytest.fixture
def runner_cls_patched(monkeypatch):
    """Patch runner module's MissionRunner seam to route through our factory."""
    registry: dict[str, Any] = {}

    def install(outcomes: list[MissionResult]) -> _FakeMission:
        mission = _FakeMission(outcomes)
        registry["mission"] = mission
        return mission

    monkeypatch.setattr("tools.benchmark.runner.MissionRunner", lambda *a, **kw: registry["mission"])
    return install


def _pass_executor(check):
    return True, "ok"


def _fail_executor(check):
    return False, "not present"


# ---------------------------------------------------------------------------
# Outcomes
# ---------------------------------------------------------------------------


def test_verified_success(tmp_path, runner_cls_patched, monkeypatch):
    seed_fake_suite([_scenario("s1")])
    runner_cls_patched([_verified_mission(agent_claimed_success=True, claimed_summary="compromises: 1")])
    runner = BenchmarkRunner(_config(tmp_path), Path("config.yaml"), verifier_factory=lambda s: _v(s, _pass_executor))
    payload = asyncio.run(runner.run(RunConfig(suite="fake", scenario_ids=["s1"], trials=1, sandbox_required=False)))
    trial = payload["trials"][0]
    assert trial["status"] == "VERIFIED"
    assert trial["oracle_verified_success"] is True
    assert trial["false_positive"] is False
    assert payload["summary"]["verified_success_rate"] == 1.0
    assert payload["summary"]["false_positive_rate"] == 0.0
    # Persistence: run.json + summary.json + report + events exist.
    run_dir = Path(payload["run_dir"])
    assert (run_dir / "summary.json").exists()
    assert (run_dir / "report.md").exists()
    assert (run_dir / "report.html").exists()
    assert (run_dir / "events.jsonl").exists()
    assert "oracle_result" in (run_dir / "events.jsonl").read_text(encoding="utf-8")


def test_verified_api_access_action_counts_as_objective_success(tmp_path, runner_cls_patched):
    url = "http://127.0.0.1:8083/version"
    flag = {
        "id": "api_access",
        "check": {"type": "http_request", "url": url, "expect_status": 200},
    }
    scenario = _scenario("api", oracle_flags=[flag])
    seed_fake_suite([scenario])
    mission = runner_cls_patched([_api_mission(_api_action_record(url))])
    run_mission = mission.run_mission

    async def run_mission_with_browser_result(*args, **kwargs):
        result = await run_mission(*args, **kwargs)
        kwargs["event_logger"].log(
            "agent_tool_result",
            {
                "name": "browser_navigate",
                "action": 1,
                "attempt_id": "attempt-1",
                "success": True,
                "exit_code": None,
                "result": f"NAVIGATED: {url}\nSTATUS: 200\nNEXT: browser_observe",
            },
            trial_id=kwargs["trial_id"],
            scenario_id=scenario.scenario_id,
            agent="exploit",
            tool="browser_navigate",
        )
        return result

    mission.run_mission = run_mission_with_browser_result  # type: ignore[method-assign]

    class _FakeTargets:
        def provision(self, provision_scenario):
            return TargetSnapshot(host=provision_scenario.target_host)

        def reset(self, provision_scenario):
            return TargetSnapshot(host=provision_scenario.target_host)

        def destroy_all(self):
            pass

    runner = BenchmarkRunner(
        _config(tmp_path),
        Path("config.yaml"),
        target_manager=_FakeTargets(),
        verifier_factory=lambda s: _v(s, _pass_executor),
    )
    payload = asyncio.run(runner.run(RunConfig(suite="fake", scenario_ids=["api"], trials=1, sandbox_required=False)))

    trial = payload["trials"][0]
    assert trial["status"] == TrialStatus.VERIFIED.value
    assert trial["oracle_verified_success"] is True
    assert trial["false_negative"] is True


def _v(scenario, executor):
    from tools.benchmark.verifier import IndependentVerifier

    v = IndependentVerifier.__new__(IndependentVerifier)
    v.scenario = scenario
    v._executor = executor
    v._session = None
    v._workspace = None
    v._loop = None
    return v


def test_false_positive(tmp_path, runner_cls_patched):
    """Agent claims success, oracle says no -> FALSE_POSITIVE trial."""
    seed_fake_suite([_scenario("s1")])
    runner_cls_patched([_verified_mission(agent_claimed_success=True, claimed_summary="compromises: 1")])
    runner = BenchmarkRunner(_config(tmp_path), Path("config.yaml"), verifier_factory=lambda s: _v(s, _fail_executor))
    payload = asyncio.run(runner.run(RunConfig(suite="fake", scenario_ids=["s1"], trials=1, sandbox_required=False)))
    trial = payload["trials"][0]
    assert trial["status"] == "FALSE_POSITIVE"
    assert trial["failure_category"] == FailureCategory.FALSE_POSITIVE.value
    assert trial["false_positive"] is True
    assert payload["summary"]["false_positive_rate"] == 1.0


@pytest.mark.parametrize(
    ("mission", "expected_failure"),
    [
        (
            MissionResult(total_actions=0, telemetry=TrialTelemetry()),
            FailureCategory.PLANNER_FAILURE.value,
        ),
        (
            MissionResult(
                total_actions=1,
                telemetry=TrialTelemetry(tool_calls=1, tool_errors=1),
                final_result={"records": [{"action": "run_exploit_terminal", "status": "error"}]},
            ),
            FailureCategory.TOOL_FAILURE.value,
        ),
        (
            MissionResult(
                total_actions=1,
                telemetry=TrialTelemetry(tool_calls=1),
                final_result={"records": [{"action": "run_exploit_terminal", "status": "executed"}]},
            ),
            FailureCategory.NO_EXPLOIT_PATH.value,
        ),
        (
            MissionResult(
                total_actions=1,
                telemetry=TrialTelemetry(tool_calls=1),
                final_result={"records": [{"action": "web_search", "status": "completed"}]},
            ),
            FailureCategory.NO_EXPLOIT_PATH.value,
        ),
    ],
    ids=["no-op", "all-tool-calls-failed", "exploit-action-unverified", "completed-recon-only"],
)
def test_baseline_oracle_observation_does_not_verify_failed_mission(
    tmp_path, runner_cls_patched, mission, expected_failure
):
    """Keep passive flags visible, but don't attribute pre-existing target state to a failed mission."""
    seed_fake_suite([_scenario("s1")])
    runner_cls_patched([mission])
    runner = BenchmarkRunner(_config(tmp_path), Path("config.yaml"), verifier_factory=lambda s: _v(s, _pass_executor))

    payload = asyncio.run(runner.run(RunConfig(suite="fake", scenario_ids=["s1"], trials=1, sandbox_required=False)))

    trial = payload["trials"][0]
    assert trial["flags_captured"] == 1
    assert trial["flags"][0]["passed"] is True
    assert trial["oracle_verified_success"] is False
    assert trial["failure_category"] == expected_failure
    assert payload["summary"]["verified_success_rate"] == 0.0


def test_failed_trial_no_exploit_path(tmp_path, runner_cls_patched):
    seed_fake_suite([_scenario("s1")])
    runner_cls_patched([MissionResult(total_actions=4, telemetry=TrialTelemetry(tool_calls=4))])
    runner = BenchmarkRunner(_config(tmp_path), Path("config.yaml"), verifier_factory=lambda s: _v(s, _fail_executor))
    payload = asyncio.run(runner.run(RunConfig(suite="fake", scenario_ids=["s1"], trials=1, sandbox_required=False)))
    trial = payload["trials"][0]
    assert trial["status"] == "FAILED"
    assert trial["failure_category"] == FailureCategory.NO_EXPLOIT_PATH.value


def test_timeout_trial(tmp_path, runner_cls_patched):
    seed_fake_suite([_scenario("s1")])
    runner_cls_patched([MissionResult(timed_out=True, errors=["mission timeout after 30s"])])
    runner = BenchmarkRunner(_config(tmp_path), Path("config.yaml"), verifier_factory=lambda s: _v(s, _pass_executor))
    payload = asyncio.run(runner.run(RunConfig(suite="fake", scenario_ids=["s1"], trials=1, sandbox_required=False)))
    trial = payload["trials"][0]
    assert trial["status"] == TrialStatus.TIMEOUT.value
    assert trial["failure_category"] == FailureCategory.TIMEOUT.value
    # Timeout is a failure, not an infrastructure error.
    assert payload["summary"]["timeout_count"] == 1
    assert payload["summary"]["infra_error_count"] == 0


def test_provision_failure_is_infrastructure_error(tmp_path, runner_cls_patched):
    seed_fake_suite([_scenario("s1")])
    runner_cls_patched([_verified_mission()])

    class _BadTargetManager:
        def provision(self, scenario):
            raise TargetProvisionError("docker run failed")

        def reset(self, scenario):
            raise TargetProvisionError("docker run failed")

        def destroy_all(self):
            pass

    runner = BenchmarkRunner(_config(tmp_path), Path("config.yaml"), target_manager=_BadTargetManager())
    payload = asyncio.run(runner.run(RunConfig(suite="fake", scenario_ids=["s1"], trials=1, sandbox_required=False)))
    trial = payload["trials"][0]
    assert trial["status"] == TrialStatus.INFRASTRUCTURE_ERROR.value
    assert trial["failure_category"] == FailureCategory.TARGET_PROVISION_FAILED.value
    # Infrastructure failures are reported separately from exploitation failures.
    assert payload["summary"]["infra_error_count"] == 1
    assert payload["summary"]["verified_success_rate"] is None
    assert payload["summary"]["false_positive_rate"] is None


def test_disabled_sandbox_configuration_is_rejected(tmp_path):
    """Legacy host-execution config cannot enter the benchmark execution path."""
    seed_fake_suite([_scenario("s1")])
    config = _config(tmp_path, sandbox_required=True)
    config["sandbox"] = {"enabled": False}
    runner = BenchmarkRunner(config, Path("config.yaml"))
    with pytest.raises(ValueError, match="sandbox.enabled=false is unsafe"):
        asyncio.run(runner.run(RunConfig(suite="fake", scenario_ids=["s1"], trials=1, sandbox_required=True)))


def test_multiple_trials_and_cancellation(tmp_path, runner_cls_patched):
    """Repeated trials record per-scenario stats; cancel stops further trials."""
    seed_fake_suite([_scenario("s1"), _scenario("s2")])
    outcomes = [
        _verified_mission(),
        MissionResult(total_actions=1),
        _verified_mission(),
        MissionResult(total_actions=1),
    ]
    mission = runner_cls_patched(outcomes)
    runner = BenchmarkRunner(_config(tmp_path), Path("config.yaml"), verifier_factory=lambda s: _v(s, _pass_executor))
    cancel = asyncio.Event()

    # Deterministic cancel: the first mission sets the event, so the runner
    # observes it at the next trial boundary (no sleep-based timing race —
    # fake missions complete in microseconds, before any fixed sleep elapses).
    orig_run_mission = mission.run_mission

    async def _run_mission_once(*args, **kwargs):
        result = await orig_run_mission(*args, **kwargs)
        cancel.set()
        return result

    mission.run_mission = _run_mission_once  # type: ignore[method-assign]

    payload = asyncio.run(runner.run(RunConfig(suite="fake", trials=2, sandbox_required=False), cancel=cancel))
    assert payload["status"] == "cancelled"
    assert len(payload["trials"]) < 4  # cancelled before all trials ran


def test_run_records_reproducibility_metadata(tmp_path, runner_cls_patched, monkeypatch):
    seed_fake_suite([_scenario("s1", target_image="")])
    runner_cls_patched([_verified_mission()])
    monkeypatch.setattr("tools.benchmark.envinfo._git", lambda *a, **kw: "deadbeef" if a[0] == "rev-parse" else "")
    monkeypatch.setattr("tools.benchmark.envinfo.docker_image_digest", lambda image: "sha256:abc")
    runner = BenchmarkRunner(_config(tmp_path), Path("config.yaml"), verifier_factory=lambda s: _v(s, _pass_executor))
    payload = asyncio.run(runner.run(RunConfig(suite="fake", scenario_ids=["s1"], trials=1, sandbox_required=False)))
    run = json.loads((Path(payload["run_dir"]) / "run.json").read_text(encoding="utf-8"))
    env = run["environment"]
    assert env["git_sha"] == "deadbeef"
    assert env["model_alias"] == "glm"
    assert env["config_hash"] != "unknown"
    assert env["sandbox_image_digest"] == "sha256:abc"
    # Manifest carries the replay command + reproducibility pins.
    assert run["replay_manifest"]["replay_command"].startswith("python main.py --benchmark fake")
    assert run["replay_manifest"]["git_sha"] == "deadbeef"


def test_no_scenarios_match(tmp_path):
    from tools.benchmark import BenchmarkRunner as R

    seed_fake_suite([_scenario("s1")])
    runner = R(_config(tmp_path), Path("config.yaml"))
    payload = asyncio.run(
        runner.run(RunConfig(suite="fake", scenario_ids=["does-not-exist"], trials=1, sandbox_required=False))
    )
    assert "error" in payload


def test_benchmark_defaults_to_active_provider_model_not_stale_alias(tmp_path):
    config = {
        "models": {"provider": "opencode_go", "default_alias": "glm"},
        "opencode_go": {"default_model": "muse-spark-1.2-contributor"},
    }

    runner = BenchmarkRunner(config, Path("config.yaml"))
    from tools.benchmark.agent_runner import MissionRunner

    mission = MissionRunner(config, Path("config.yaml"))
    assert runner.model_alias == "muse-spark-1.2-contributor"
    assert mission.model_alias == "muse-spark-1.2-contributor"


def test_target_ports_reachable_helper() -> None:
    """Unit probe: an open loopback port is reachable; closed and empty are not."""
    import socket as _socket

    from tools.benchmark.runner import _target_ports_reachable

    srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    open_port = srv.getsockname()[1]
    try:
        assert _target_ports_reachable("127.0.0.1", [open_port]) is True
    finally:
        srv.close()
    assert _target_ports_reachable("127.0.0.1", [open_port]) is False
    assert _target_ports_reachable("127.0.0.1", []) is False


def test_unreachable_target_ports_is_infrastructure_error(tmp_path, runner_cls_patched):
    """A host-type scenario whose declared ports all refuse fails fast as
    INFRASTRUCTURE_ERROR/TARGET_PROVISION_FAILED (down lab) without running
    the mission -- the test.log waste was 50 recon rounds vs refused ports."""
    import socket as _socket

    probe = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    closed_port = probe.getsockname()[1]
    probe.close()

    seed_fake_suite([_scenario("s1", target_ports=[closed_port])])
    mission = runner_cls_patched([_verified_mission()])
    runner = BenchmarkRunner(_config(tmp_path), Path("config.yaml"), verifier_factory=lambda s: _v(s, _pass_executor))
    payload = asyncio.run(runner.run(RunConfig(suite="fake", scenario_ids=["s1"], trials=1, sandbox_required=False)))
    trial = payload["trials"][0]
    assert trial["status"] == TrialStatus.INFRASTRUCTURE_ERROR.value
    assert trial["failure_category"] == FailureCategory.TARGET_PROVISION_FAILED.value
    assert "up -d" in trial["failure_detail"]
    assert mission.calls == []  # mission never ran
    assert payload["summary"]["infra_error_count"] == 1
