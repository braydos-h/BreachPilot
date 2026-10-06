"""Lifecycle regressions for transport-neutral assessment execution."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tools.run_log import RunLog
from tools.run_service.execute import ExecuteMixin
from tools.run_service.models import RunPreview, RunRequest
from tools.run_service.prepare import Callables
from tools.run_service.providers import CancellationToken
from tools.run_service.service import AssessmentService


@pytest.mark.asyncio
async def test_run_log_detaches_when_initial_progress_delivery_fails(tmp_path: Path) -> None:
    reports_dir = tmp_path / "reports" / "run-1"
    request = RunRequest(target="192.0.2.10", config_path=tmp_path / "config.yaml", reports_dir=reports_dir)
    preview = RunPreview(
        run_id="run-1",
        reports_dir=reports_dir,
        config_path=request.config_path,
        target_ip="192.0.2.10",
        original_target="192.0.2.10",
        resolved_ip=None,
        resolved_domain=None,
        mode="attack",
        goal_name="test",
        goal_description="test run",
        model_alias="test",
        model_label="test",
        transport_summary="test",
        permission="authorized",
        attack_mode=True,
        swarm=False,
        parallel_swarm=False,
        multi_model=False,
        destructive=False,
        required_confirmation_text="",
    )

    class FailingEventSink:
        async def emit(self, _event: str, _payload: dict[str, object]) -> None:
            raise RuntimeError("progress transport disconnected")

    with pytest.raises(RuntimeError, match="progress transport disconnected"):
        await ExecuteMixin().execute(
            request,
            preview,
            decision_provider=object(),
            event_sink=FailingEventSink(),
            cancellation=object(),
            config={"skills": {"enabled": False}, "witness": {"enabled": False}},
        )

    assert RunLog._current_session() is None
    assert all(session.path != reports_dir / "run.log" for session in RunLog._sessions)
    assert (reports_dir / "run.log").is_file()


@pytest.mark.asyncio
async def test_cancelling_run_joins_swarm_started_after_setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports_dir = tmp_path / "reports" / "run-2"
    config_path = tmp_path / "config.yaml"
    request = RunRequest(
        target="192.0.2.10",
        goal_name="recon_only",
        recon_first=False,
        swarm=True,
        config_path=config_path,
        reports_dir=reports_dir,
    )
    preview = RunPreview(
        run_id="run-2",
        reports_dir=reports_dir,
        config_path=config_path,
        target_ip="192.0.2.10",
        original_target="192.0.2.10",
        resolved_ip=None,
        resolved_domain=None,
        mode="attack",
        goal_name="recon_only",
        goal_description="test run",
        model_alias="test",
        model_label="test",
        transport_summary="test",
        permission="authorized",
        attack_mode=True,
        swarm=True,
        parallel_swarm=False,
        multi_model=False,
        destructive=False,
        required_confirmation_text="",
    )
    session_started = asyncio.Event()
    swarm_started = asyncio.Event()
    swarm_stopped = asyncio.Event()
    swarm_tasks: list[asyncio.Task[None]] = []

    class EventSink:
        async def emit(self, _event: str, _payload: dict[str, object]) -> None:
            return None

    async def run_swarm() -> None:
        swarm_started.set()
        try:
            await asyncio.Event().wait()
        finally:
            swarm_stopped.set()

    async def setup_swarm(**_kwargs: object) -> tuple[object, asyncio.Task[None], Path]:
        task = asyncio.create_task(run_swarm())
        swarm_tasks.append(task)
        return object(), task, reports_dir / "swarm_workspace"

    async def run_session(**_kwargs: object) -> dict[str, object]:
        session_started.set()
        await asyncio.Event().wait()
        return {}

    monkeypatch.setattr("tools.skills_cli._build_runtime_skill_selection", lambda **_kwargs: None)
    monkeypatch.setattr("tools.skills_cli._apply_runtime_skill_selection", lambda *_args, **_kwargs: None)
    service = AssessmentService()
    monkeypatch.setattr(service, "_setup_swarm", setup_swarm)
    monkeypatch.setattr(service, "_run_session", run_session)

    execution = asyncio.create_task(
        service.execute(
            request,
            preview,
            decision_provider=object(),
            event_sink=EventSink(),
            cancellation=CancellationToken(),
            model_client=object(),
            config={"skills": {"enabled": False}, "witness": {"enabled": False}},
        )
    )
    await asyncio.wait_for(session_started.wait(), timeout=2)
    await asyncio.wait_for(swarm_started.wait(), timeout=2)
    execution.cancel()

    with pytest.raises(asyncio.CancelledError):
        await execution

    assert swarm_stopped.is_set()
    assert swarm_tasks[0].done()
    assert swarm_tasks[0].cancelled()


@pytest.mark.asyncio
async def test_completed_swarm_is_torn_down_once_after_primary_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports_dir = tmp_path / "reports" / "run-3"
    config_path = tmp_path / "config.yaml"
    request = RunRequest(
        target="192.0.2.10",
        goal_name="recon_only",
        recon_first=False,
        swarm=True,
        config_path=config_path,
        reports_dir=reports_dir,
    )
    preview = RunPreview(
        run_id="run-3",
        reports_dir=reports_dir,
        config_path=config_path,
        target_ip="192.0.2.10",
        original_target="192.0.2.10",
        resolved_ip=None,
        resolved_domain=None,
        mode="attack",
        goal_name="recon_only",
        goal_description="test run",
        model_alias="test",
        model_label="test",
        transport_summary="test",
        permission="authorized",
        attack_mode=True,
        swarm=True,
        parallel_swarm=False,
        multi_model=False,
        destructive=False,
        required_confirmation_text="",
    )

    class EventSink:
        async def emit(self, _event: str, _payload: dict[str, object]) -> None:
            return None

    class SwarmLoop:
        pass

    async def run_swarm() -> dict[str, int]:
        return {"tasks_completed": 0, "tasks_blocked": 0, "tasks_failed": 0, "findings_report_ready": 0}

    async def setup_swarm(**_kwargs: object) -> tuple[SwarmLoop, asyncio.Task[dict[str, int]], Path]:
        return SwarmLoop(), asyncio.create_task(run_swarm()), reports_dir / "swarm_workspace"

    async def run_session(**kwargs: Any) -> dict[str, Any]:
        session_complete = kwargs.get("swarm_session_complete")
        assert callable(session_complete)
        return await session_complete({})

    monkeypatch.setattr("tools.skills_cli._build_runtime_skill_selection", lambda **_kwargs: None)
    monkeypatch.setattr("tools.skills_cli._apply_runtime_skill_selection", lambda *_args, **_kwargs: None)
    service = AssessmentService()
    monkeypatch.setattr(service, "_setup_swarm", setup_swarm)
    monkeypatch.setattr(service, "_run_session", run_session)
    original_stop = service._stop_swarm_task
    stop_calls = 0

    async def count_stop(*, swarm_loop: Any, swarm_task: asyncio.Task[Any], swarm_bridge: Any, mode: str) -> None:
        nonlocal stop_calls
        stop_calls += 1
        await original_stop(swarm_loop=swarm_loop, swarm_task=swarm_task, swarm_bridge=swarm_bridge, mode=mode)

    monkeypatch.setattr(service, "_stop_swarm_task", count_stop)

    result = await service.execute(
        request,
        preview,
        decision_provider=object(),
        event_sink=EventSink(),
        cancellation=CancellationToken(),
        model_client=object(),
        config={"skills": {"enabled": False}, "witness": {"enabled": False}},
    )

    assert result.swarm_result == {
        "tasks_completed": 0,
        "tasks_blocked": 0,
        "tasks_failed": 0,
        "findings_report_ready": 0,
    }
    assert stop_calls == 1


@pytest.mark.asyncio
async def test_mcp_session_uses_the_run_config_snapshot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import tools.run_service.tasks as tasks_module

    config_path = tmp_path / "config.yaml"
    config_path.write_text("mcp:\n  http_port: 8999\n", encoding="utf-8")
    frozen_config = {
        "mcp": {"http_port": 8123},
        "exploit": {"allowed_targets": ["192.0.2.10"]},
    }
    captured: dict[str, Any] = {}

    async def capture_session(**kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        kwargs["config_override"]["mcp"]["http_port"] = 8000
        return {"total_actions": 0}

    class QuietUI:
        def __getattr__(self, _name: str) -> Any:
            return lambda *_args, **_kwargs: None

    monkeypatch.setattr(tasks_module, "ui", QuietUI())
    monkeypatch.setattr(
        tasks_module,
        "_config_cli_load",
        lambda _path: pytest.fail("the prepared run must not reload mutable configuration"),
    )
    service = AssessmentService(callables=Callables(run_session=capture_session))

    await service._run_session(
        model_client=object(),
        model_alias="fixture-model",
        target_ip="192.0.2.10",
        mode="attack",
        goal=SimpleNamespace(name="fixture-goal"),
        exploit_settings=SimpleNamespace(target_context={}),
        config_path=config_path,
        config=frozen_config,
        reports_dir=tmp_path / "reports" / "run-1",
        assessment=None,
        approval_prompt=None,
        approval_provider=None,
        swarm_attach=None,
        heartbeat=None,
        original_target=None,
        resolved_ip=None,
        recon_first=False,
        resume_state=None,
        event_sink=object(),
        cancellation=object(),
    )

    assert captured["exploit_port"] == 8123
    assert captured["config_override"]["exploit"]["allowed_targets"] == ["192.0.2.10"]
    assert frozen_config["mcp"]["http_port"] == 8123


@pytest.mark.asyncio
async def test_research_swarm_timeout_bounds_teardown_and_tracks_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    from tools.run_service import tasks as tasks_module

    release_worker = asyncio.Event()

    class SwarmLoop:
        stopped = False

        def stop(self) -> None:
            self.stopped = True

    class Bridge:
        stopped = False

        def stop(self) -> None:
            self.stopped = True

    async def blocked_worker() -> None:
        await release_worker.wait()

    swarm_loop = SwarmLoop()
    bridge = Bridge()
    worker = asyncio.create_task(blocked_worker())
    await asyncio.sleep(0)
    monkeypatch.setattr(tasks_module, "_SWARM_TEARDOWN_GRACE_SECONDS", 0.01)

    await tasks_module.TasksMixin()._stop_swarm_task(
        swarm_loop=swarm_loop,
        swarm_task=worker,
        swarm_bridge=bridge,
        mode="research",
    )

    assert swarm_loop.stopped
    assert bridge.stopped
    assert not worker.done()
    assert worker in tasks_module._DETACHED_SWARM_TASKS

    release_worker.set()
    await worker
    await asyncio.sleep(0)
    assert worker not in tasks_module._DETACHED_SWARM_TASKS


@pytest.mark.asyncio
async def test_swarm_wait_logs_nested_exception_group(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from tools.run_service import tasks as tasks_module

    logged: list[BaseException] = []

    async def failed_worker() -> None:
        raise BaseExceptionGroup("MCP session failed", [RuntimeError("connection closed")])

    class EventSink:
        async def emit(self, _event: str, _payload: dict[str, object]) -> None:
            return None

    monkeypatch.setattr(tasks_module, "_log_nested_exceptions", logged.append)
    worker = asyncio.create_task(failed_worker())
    await asyncio.sleep(0)
    result: dict[str, object] = {}

    await tasks_module.TasksMixin()._wait_swarm(
        swarm_loop=object(),
        swarm_task=worker,
        swarm_bridge=object(),
        swarm_workspace=tmp_path,
        mode="attack",
        config={},
        request=RunRequest(target="192.0.2.10"),
        result=result,
        event_sink=EventSink(),
    )

    assert isinstance(result.get("swarm_result"), dict)
    assert "MCP session failed" in str(result["swarm_result"])
    assert logged
    assert any(
        isinstance(exc, BaseExceptionGroup) and any("connection closed" in str(item) for item in exc.exceptions)
        for exc in logged
    )
