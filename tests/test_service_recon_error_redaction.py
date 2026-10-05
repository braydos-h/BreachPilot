"""Recon fallback diagnostics must redact credentials on every output path."""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest


class _RecordingSink:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    async def emit(self, event_type: str, payload: dict[str, Any]) -> None:
        self.events.append((event_type, payload))


class _DecisionProvider:
    async def request(self, _decision: Any) -> str:
        return "recon_only"


@pytest.mark.parametrize("mode", ["recon", "fast"])
def test_recon_fallback_redacts_exception_from_logs_ui_and_events(
    mode: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from tools.goal_engine import GoalEngine
    from tools.run_service import AssessmentService
    from tools.run_service.models import RunRequest
    from tools.run_service.providers import CancellationToken
    from tools.run_service.service import Callables

    @asynccontextmanager
    async def _open_session(**_kwargs: Any):
        raise ExceptionGroup(
            "client_secret=groupsecret",
            [RuntimeError("password=nestedsecret")],
        )
        yield None

    warnings: list[str] = []
    monkeypatch.setattr("tools.run_service.tasks.ui.warning", warnings.append)
    service = AssessmentService(callables=Callables(open_session=_open_session))
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    sink = _RecordingSink()
    request = RunRequest(
        target="10.0.0.50",
        mode=mode,
        goal_name="recon_only",
        config_path=tmp_path / "config.yaml",
    )
    args = {
        "request": request,
        "config": {"mcp": {"http_port": 8001}, "exploit": {"workspace_dir": str(tmp_path / "workspace")}},
        "config_path": tmp_path / "config.yaml",
        "target_ip": "10.0.0.50",
        "original_target": "10.0.0.50",
        "resolved_ip": None,
        "resolved_domain": None,
        "reports_dir": reports_dir,
        "model_client": MagicMock(),
        "model_alias": "test",
        "risk_profile": "standard_authorized",
        "goal_engine": GoalEngine(),
        "decision_provider": _DecisionProvider(),
        "event_sink": sink,
        "cancellation": CancellationToken(),
    }

    if mode == "recon":
        asyncio.run(service._recon_first(**args))
    else:
        asyncio.run(service._fast_recon(**args))

    log_text = (reports_dir / "recon_first_error.log").read_text(encoding="utf-8")
    all_outputs = "\n".join(
        [
            log_text,
            json.dumps(warnings),
            capsys.readouterr().out,
            json.dumps(sink.events),
        ]
    )
    assert "groupsecret" not in all_outputs
    assert "nestedsecret" not in all_outputs
    assert "[REDACTED]" in log_text
    assert any("[REDACTED]" in warning for warning in warnings)
    assert any(event_type == "error" for event_type, _ in sink.events)
