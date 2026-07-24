"""Tests for swarm sub-agent UI visibility."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

import pytest


def test_orchestrator_emits_agent_started_and_complete():
    """SwarmOrchestrator should emit agent_started and agent_complete events."""
    from tools.swarm.orchestrator import SwarmOrchestrator
    from tools.swarm.base import Agent, AgentResult, AgentStatus

    class DummyAgent(Agent):
        def run(self, task: dict[str, Any], context: dict[str, Any]) -> AgentResult:
            return AgentResult(
                agent_type=self.agent_type,
                status=AgentStatus.COMPLETE,
                task_id=task.get("task_id", ""),
                output={"discovered_services": ["ssh"]},
            )

    events: list[tuple[str, dict[str, Any]]] = []

    def _capture(event_type: str, data: dict[str, Any]) -> None:
        events.append((event_type, data))

    orchestrator = SwarmOrchestrator(
        {},
        agent_registry={"recon": DummyAgent},
        event_callback=_capture,
    )

    result = orchestrator.route({"task_id": "T-1", "phase": "recon", "target": "10.0.0.1"})
    assert result.status == AgentStatus.COMPLETE

    types = [e[0] for e in events]
    assert "agent_started" in types
    assert "agent_complete" in types


def test_orchestrator_emits_blocked_when_critic_denies():
    """Critic deny decision should emit critic_decision and agent_blocked."""
    from tools.swarm.orchestrator import SwarmOrchestrator
    from tools.swarm.base import Agent, AgentResult, AgentStatus

    class DummyAgent(Agent):
        def run(self, task: dict[str, Any], context: dict[str, Any]) -> AgentResult:
            return AgentResult(
                agent_type=self.agent_type,
                status=AgentStatus.COMPLETE,
                task_id=task.get("task_id", ""),
            )

    class DenyCritic(Agent):
        def run(self, task: dict[str, Any], context: dict[str, Any]) -> AgentResult:
            return AgentResult(
                agent_type="critic",
                status=AgentStatus.COMPLETE,
                task_id=task.get("task_id", ""),
                output={"decision": "deny", "reasoning": "too risky"},
            )

    events: list[tuple[str, dict[str, Any]]] = []

    orchestrator = SwarmOrchestrator(
        {},
        agent_registry={"exploit": DummyAgent, "critic": DenyCritic},
        critic_enabled=True,
        event_callback=lambda t, d: events.append((t, d)),
    )

    result = orchestrator.route({"task_id": "T-2", "phase": "exploit", "target": "10.0.0.1"})
    assert result.status == AgentStatus.BLOCKED

    types = [e[0] for e in events]
    assert "critic_decision" in types
    assert "agent_blocked" in types


def test_orchestrator_persists_state_file():
    """SwarmOrchestrator should write swarm_state.json when state_path is set."""
    from tools.swarm.orchestrator import SwarmOrchestrator
    from tools.swarm.base import Agent, AgentResult, AgentStatus

    class DummyAgent(Agent):
        def run(self, task: dict[str, Any], context: dict[str, Any]) -> AgentResult:
            return AgentResult(
                agent_type=self.agent_type,
                status=AgentStatus.COMPLETE,
                task_id=task.get("task_id", ""),
                output={"access_achieved": True},
            )

    with tempfile.TemporaryDirectory() as tmpdir:
        state_path = Path(tmpdir) / "swarm_state.json"
        orchestrator = SwarmOrchestrator(
            {},
            agent_registry={"exploit": DummyAgent},
            state_path=state_path,
        )
        orchestrator.route({"task_id": "T-3", "phase": "exploit", "target": "10.0.0.1"})

        assert state_path.exists()
        data = json.loads(state_path.read_text(encoding="utf-8"))
        assert data["blackboard"]["access_achieved"] is True
        assert len(data["agents"]) == 1


def test_service_registry_reads_swarm_state():
    """ServiceRegistry.swarm should parse a valid swarm_state.json."""
    from tui.services import ServiceRegistry, SwarmStateSnapshot

    with tempfile.TemporaryDirectory() as tmpdir:
        swarm_ws = Path(tmpdir) / "swarm_workspace"
        swarm_ws.mkdir()
        state_path = swarm_ws / "swarm_state.json"
        state_path.write_text(
            json.dumps(
                {
                    "agents": [
                        {
                            "agent_id": "recon-abc123",
                            "agent_type": "recon",
                            "status": "running",
                            "task_id": "T-1",
                        }
                    ],
                    "blackboard": {"access_achieved": True, "discovered_services": ["ssh"]},
                    "battle_log_tail": [{"task_id": "T-1", "success": True}],
                    "last_reflection": {"recommended_strategy_shift": "focus on ssh"},
                    "strategy_shift": "focus on ssh",
                    "updated_at": 1234567890.0,
                }
            ),
            encoding="utf-8",
        )

        svc = ServiceRegistry(Path(tmpdir) / "research_workspace")
        state = svc.swarm
        assert isinstance(state, SwarmStateSnapshot)
        assert state.active is True
        assert len(state.agent_rows) == 1
        assert state.blackboard.get("access_achieved") is True
        assert state.strategy_shift == "focus on ssh"


def test_service_registry_swarm_state_missing():
    """ServiceRegistry.swarm should return an inactive snapshot when no state file exists."""
    from tui.services import ServiceRegistry, SwarmStateSnapshot

    with tempfile.TemporaryDirectory() as tmpdir:
        svc = ServiceRegistry(Path(tmpdir) / "research_workspace")
        state = svc.swarm
        assert isinstance(state, SwarmStateSnapshot)
        assert state.active is False
        assert "No swarm state file found" in state.error


def test_dashboard_stats_swarm_fields():
    """DashboardStats should include swarm fields with sensible defaults."""
    from tui.services import DashboardStats

    stats = DashboardStats()
    assert stats.swarm_active is False
    assert stats.swarm_agent_count == 0
    assert stats.swarm_running_count == 0
    assert stats.swarm_access_achieved is False


def test_agent_loop_persists_swarm_events():
    """AgentLoop._persist_event should append events to swarm_events.jsonl."""
    from agent_loop import AgentLoop

    with tempfile.TemporaryDirectory() as tmpdir:
        ws = Path(tmpdir) / "ws"
        ws.mkdir()
        loop = AgentLoop(
            mission_config={
                "program_name": "test",
                "objective": "test",
                "risk_profile": "low_noise_non_destructive",
                "allowed_assets": ["127.0.0.1"],
                "disallowed_assets": [],
                "forbidden_actions": [],
                "testing_modes": ["recon"],
                "rate_limits": {"default_requests_per_second": 10, "max_concurrent_requests": 1},
                "accounts": [],
                "use_swarm": False,
            },
            workspace_root=ws,
            tool_executor=lambda name, args: "ok",
        )
        loop._persist_event("agent_started", {"agent_type": "recon", "task_id": "T-1"})

        events_path = ws / "state" / "swarm_events.jsonl"
        assert events_path.exists()
        lines = events_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["event_type"] == "agent_started"
        assert record["data"]["agent_type"] == "recon"
