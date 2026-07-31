"""Tests for the AssessmentService extraction (Phase 1 regression)."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from tools.run_service.models import (
    RunKind,
    RunMode,
    RunPreview,
    RunRequest,
    RunResult,
    RunState,
)
from tools.run_service.providers import (
    CancellationToken,
    TerminalApprovalProvider,
    TerminalDecisionProvider,
    TerminalEventSink,
)


# ── Models ───────────────────────────────────────────────────────────────────


def test_run_request_defaults():
    req = RunRequest(target="10.0.0.50")
    assert req.mode == "attack"
    assert req.swarm is False
    assert req.kind == RunKind.AGENT
    assert req.reports_dir == Path("reports")


def test_run_preview_serializable():
    p = RunPreview(
        run_id="test-run",
        reports_dir=Path("reports/test"),
        config_path=Path("config.yaml"),
        target_ip="10.0.0.50",
        original_target="10.0.0.50",
        resolved_ip=None,
        resolved_domain=None,
        mode="attack",
        goal_name="backdoor",
        goal_description="test",
        model_alias="glm",
        model_label="GLM-5.2",
        transport_summary="http on port 8001",
        permission="full_access",
        attack_mode=True,
        swarm=False,
        parallel_swarm=False,
        multi_model=False,
        destructive=True,
        required_confirmation_text="ALLOW 10.0.0.50",
    )
    assert p.destructive is True
    assert p.required_confirmation_text == "ALLOW 10.0.0.50"


def test_run_result_defaults():
    r = RunResult(run_id="x", target_ip="10.0.0.50", mode="recon", goal_name="recon", goal_description="d")
    assert r.total_actions == 0
    assert r.error == ""
    assert r.records == []


# ── Cancellation ──────────────────────────────────────────────────────────────


def test_cancellation_token():
    ct = CancellationToken()
    assert ct.cancelled is False
    ct.cancel()
    assert ct.cancelled is True


# ── Terminal providers ────────────────────────────────────────────────────────


def test_terminal_event_sink_noop():
    sink = TerminalEventSink()
    asyncio.run(sink.emit("test", {"key": "value"}))  # must not raise


def test_terminal_approval_provider_allow():
    calls = []
    def fake_prompt(text):
        calls.append(text)
        return "ALLOW 10.0.0.50"
    provider = TerminalApprovalProvider(fake_prompt)
    result = asyncio.run(provider.approve("test_action", "ls", "detail", "10.0.0.50"))
    assert result is True


def test_terminal_approval_provider_deny():
    def fake_prompt(text):
        return "no"
    provider = TerminalApprovalProvider(fake_prompt)
    result = asyncio.run(provider.approve("test_action", "ls", "detail", "10.0.0.50"))
    assert result is False


# ── AssessmentService.prepare ─────────────────────────────────────────────────


def test_prepare_resolves_target_ip(tmp_path):
    from tools.run_service import AssessmentService
    from tools.run_service.service import Callables
    from unittest.mock import MagicMock
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "ollama:\n  host: http://localhost:11434\n"
        "models:\n  default_alias: glm\n  registry:\n    glm: glm-5.2:cloud\n"
        "exploit:\n  permission: full_access\n"
        "api:\n  host: 127.0.0.1\n  port: 8765\n",
        encoding="utf-8",
    )
    class _FakeRouter:
        _clients = {"glm": MagicMock()}
        def get_client(self, name):
            return self._clients[name]
    callables = Callables(build_router=lambda *a, **kw: _FakeRouter())
    service = AssessmentService(callables=callables)
    req = RunRequest(target="10.0.0.50", mode="attack", goal_name="recon_only", config_path=config_path)
    preview = asyncio.run(service.prepare(req))
    assert preview.target_ip == "10.0.0.50"
    assert preview.mode == "attack"
    assert preview.permission == "full_access"
    assert preview.destructive is True


def test_prepare_rejects_invalid_target(tmp_path):
    from tools.run_service import AssessmentService
    from tools.run_service.service import Callables
    from unittest.mock import MagicMock
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "ollama:\n  host: http://localhost:11434\n"
        "models:\n  default_alias: glm\n  registry:\n    glm: glm-5.2:cloud\n",
        encoding="utf-8",
    )
    class _FakeRouter:
        _clients = {"glm": MagicMock()}
        def get_client(self, name):
            return self._clients[name]
    callables = Callables(build_router=lambda *a, **kw: _FakeRouter())
    service = AssessmentService(callables=callables)
    req = RunRequest(target="not-a-valid-target!!!", mode="attack", config_path=config_path)
    with pytest.raises(ValueError, match="Invalid target"):
        asyncio.run(service.prepare(req))


def test_prepare_recon_mode_not_destructive(tmp_path):
    from tools.run_service import AssessmentService
    from tools.run_service.service import Callables
    from unittest.mock import MagicMock
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "ollama:\n  host: http://localhost:11434\n"
        "models:\n  default_alias: glm\n  registry:\n    glm: glm-5.2:cloud\n"
        "exploit:\n  permission: read_only\n"
        "api:\n  host: 127.0.0.1\n  port: 8765\n",
        encoding="utf-8",
    )
    class _FakeRouter:
        _clients = {"glm": MagicMock()}
        def get_client(self, name):
            return self._clients[name]
    callables = Callables(build_router=lambda *a, **kw: _FakeRouter())
    service = AssessmentService(callables=callables)
    req = RunRequest(target="10.0.0.50", mode="recon", config_path=config_path)
    preview = asyncio.run(service.prepare(req))
    assert preview.destructive is False
    assert preview.required_confirmation_text == ""