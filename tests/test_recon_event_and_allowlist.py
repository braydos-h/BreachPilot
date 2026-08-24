"""Regression tests for two WebUI-parity backend additions:

1. ``AssessmentService._recon_first`` emits an ``EVENT_RECON``
   (``"recon_assessment"``) event carrying ``assessment.to_dict()``
   so the WebUI can render the recon block the CLI prints.
2. ``RunManager._create_run_locked`` persists the interactive target to
   ``config.yaml exploit.allowed_targets`` (mirroring ``main.py:667-675``).
"""

from __future__ import annotations

import asyncio
import contextlib
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

# ── 1. recon_assessment event ──────────────────────────────────────────────


class _RecordingSink:
    """Minimal EventSink that records every (event_type, payload) pair."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    async def emit(self, event_type: str, payload: dict[str, Any]) -> None:
        self.events.append((event_type, payload))


class _StubDecisionProvider:
    """Returns a fixed goal name for every decision (goal_select)."""

    def __init__(self, answer: str = "recon_only") -> None:
        self._answer = answer

    async def request(self, decision: Any) -> str:
        return self._answer


def test_recon_first_emits_recon_assessment_event(tmp_path):
    """``_recon_first`` must emit ``recon_assessment`` before ``goal_suggestions``."""
    from tools.goal_engine import GoalEngine
    from tools.goal_suggester import ReconAssessment
    from tools.run_service import AssessmentService
    from tools.run_service.models import RunRequest
    from tools.run_service.providers import CancellationToken
    from tools.run_service.service import Callables

    assessment = ReconAssessment(
        target_ip="10.0.0.50",
        os_verdict="LINUX",
        os_hints=["Ubuntu 20.04"],
        open_ports=[22, 80, 443],
        services=[{"name": "ssh", "port": 22, "banner": "OpenSSH 8.2p1", "risk": 70}],
        cve_findings=[{"service": "ssh", "count": 3}],
        overall_risk_score=65,
    )

    @contextlib.asynccontextmanager
    async def _open_session(**_kw):
        yield MagicMock()  # non-None so run_recon_assessment is invoked

    async def _run_recon(**_kw):
        return assessment

    callables = Callables(open_session=_open_session, run_recon_assessment=_run_recon)
    service = AssessmentService(callables=callables)

    sink = _RecordingSink()
    config = {"mcp": {"http_port": 8001}}
    request = RunRequest(target="10.0.0.50", mode="recon", config_path=tmp_path / "config.yaml")

    async def _go():
        return await service._recon_first(
            request=request,
            config=config,
            config_path=tmp_path / "config.yaml",
            target_ip="10.0.0.50",
            original_target="10.0.0.50",
            resolved_ip=None,
            resolved_domain=None,
            reports_dir=tmp_path,
            model_client=MagicMock(),
            model_alias="glm",
            risk_profile="standard_authorized",
            goal_engine=GoalEngine(),
            decision_provider=_StubDecisionProvider("recon_only"),
            event_sink=sink,
            cancellation=CancellationToken(),
        )

    result_assessment, result_goal = asyncio.run(_go())

    types = [t for t, _ in sink.events]
    assert "recon_assessment" in types, f"recon_assessment event missing; got {types}"
    assert types.index("recon_assessment") < types.index("goal_suggestions"), (
        "recon_assessment must fire before goal_suggestions"
    )

    recon_payload = next(p for t, p in sink.events if t == "recon_assessment")
    assert recon_payload["assessment"] == assessment.to_dict()
    assert recon_payload["assessment"]["os_verdict"] == "LINUX"
    assert result_goal.name == "recon_only"


# ── 2. RunManager allowlist auto-save ──────────────────────────────────────


def test_run_manager_does_not_persist_target_to_allowlist(tmp_path, monkeypatch):
    """``RunManager._create_run_locked`` must NOT call ``add_target_to_allowlist``.

    The WebUI used to auto-save every entered target to config.yaml's
    exploit.allowed_targets, which accumulated stale targets and weakened
    the one-target lock. Target authorization now happens at runtime via
    EXPLOIT_TARGET env (set in tools/mcp_session.py), so the config write is
    both unnecessary and a safety regression. This test guards against
    re-adding it.
    """
    from tools.api.event_broker import EventBrokerRegistry
    from tools.api.persistence import ApiPersistence
    from tools.api.run_manager import RunManager
    from tools.run_service.models import RunPreview, RunRequest

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "ollama:\n  host: http://localhost:11434\n"
        "models:\n  default_alias: glm\n  registry:\n    glm: glm-5.2:cloud\n"
        "exploit:\n  permission: read_only\n"
        "api:\n  host: 127.0.0.1\n  port: 8765\n",
        encoding="utf-8",
    )

    class FakeService:
        def __init__(self, **kwargs):
            pass

        async def prepare(self, request):
            return RunPreview(
                run_id=f"run-{request.target}",
                reports_dir=tmp_path / "reports" / request.target,
                config_path=config_path,
                target_ip=request.target,
                original_target=request.target,
                resolved_ip=None,
                resolved_domain=None,
                mode="attack",
                goal_name="recon_only",
                goal_description="test",
                model_alias="glm",
                model_label="glm",
                transport_summary="http",
                permission="read_only",
                attack_mode=False,
                swarm=False,
                parallel_swarm=False,
                multi_model=False,
                destructive=False,
                required_confirmation_text="",
            )

    monkeypatch.setattr("tools.run_service.AssessmentService", FakeService)

    spy_calls: list[tuple] = []

    def _spy_add(path: Path, target_ip: str) -> bool:
        spy_calls.append((path, target_ip))
        return True

    monkeypatch.setattr("tools.config_cli.add_target_to_allowlist", _spy_add)

    persistence = ApiPersistence(tmp_path / "reports")
    manager = RunManager(
        persistence,
        EventBrokerRegistry(tmp_path / "reports"),
        config={},
        config_path=config_path,
    )

    async def _run():
        await manager.create_run(RunRequest(target="10.0.0.50"))
        await manager.cancel_run(manager.active.run_id)

    asyncio.run(_run())

    assert len(spy_calls) == 0, f"RunManager must not auto-persist targets to the allowlist (got {spy_calls})"


def test_run_manager_allowlist_failure_does_not_kill_run(tmp_path, monkeypatch):
    """The run proceeds normally; ``add_target_to_allowlist`` is never called
    (auto-persist was removed), so a raising stub has no effect on the run."""
    from tools.api.event_broker import EventBrokerRegistry
    from tools.api.persistence import ApiPersistence
    from tools.api.run_manager import RunManager
    from tools.run_service.models import RunPreview, RunRequest

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "ollama:\n  host: http://localhost:11434\n"
        "models:\n  default_alias: glm\n  registry:\n    glm: glm-5.2:cloud\n"
        "exploit:\n  permission: read_only\n"
        "api:\n  host: 127.0.0.1\n  port: 8765\n",
        encoding="utf-8",
    )

    class FakeService:
        def __init__(self, **kwargs):
            pass

        async def prepare(self, request):
            return RunPreview(
                run_id=f"run-{request.target}",
                reports_dir=tmp_path / "reports" / request.target,
                config_path=config_path,
                target_ip=request.target,
                original_target=request.target,
                resolved_ip=None,
                resolved_domain=None,
                mode="attack",
                goal_name="recon_only",
                goal_description="test",
                model_alias="glm",
                model_label="glm",
                transport_summary="http",
                permission="read_only",
                attack_mode=False,
                swarm=False,
                parallel_swarm=False,
                multi_model=False,
                destructive=False,
                required_confirmation_text="",
            )

    monkeypatch.setattr("tools.run_service.AssessmentService", FakeService)

    def _raising_add(path: Path, target_ip: str) -> bool:
        raise ValueError("simulated bad target")

    monkeypatch.setattr("tools.config_cli.add_target_to_allowlist", _raising_add)

    persistence = ApiPersistence(tmp_path / "reports")
    manager = RunManager(
        persistence,
        EventBrokerRegistry(tmp_path / "reports"),
        config={},
        config_path=config_path,
    )

    async def _run():
        await manager.create_run(RunRequest(target="10.0.0.50"))
        assert manager.has_active is True, "run must survive (allowlist is never called)"
        await manager.cancel_run(manager.active.run_id)

    asyncio.run(_run())  # must not raise
