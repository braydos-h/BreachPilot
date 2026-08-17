"""Tests for the multi-agent swarm architecture."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from tools.swarm.base import Agent, AgentResult, AgentStatus
from tools.swarm.orchestrator import SwarmOrchestrator, _DEFAULT_AGENT_MAP
from tools.swarm.agents.recon_agent import ReconAgent
from tools.swarm.agents.vuln_agent import VulnAgent
from tools.swarm.agents.exploit_agent import ExploitAgent
from tools.swarm.agents.critic_agent import CriticAgent
from tools.swarm.agents.reflection_agent import ReflectionAgent


class DummyAgent(Agent):
    """Test agent that echoes back the task."""

    def run(self, task: dict, context: dict) -> AgentResult:
        self._set_status(AgentStatus.COMPLETE)
        return AgentResult(
            agent_type=self.agent_type,
            status=self.status,
            task_id=task.get("task_id", ""),
            output={"echo": task.get("objective", "")},
        )


class FailingAgent(Agent):
    """Test agent that always fails."""

    def run(self, task: dict, context: dict) -> AgentResult:
        self._set_status(AgentStatus.FAILED)
        return AgentResult(
            agent_type=self.agent_type,
            status=self.status,
            task_id=task.get("task_id", ""),
            error="Simulated failure",
        )


class BlockingCriticAgent(Agent):
    """Test critic that always blocks."""

    def run(self, task: dict, context: dict) -> AgentResult:
        self._set_status(AgentStatus.BLOCKED)
        return AgentResult(
            agent_type="critic",
            status=self.status,
            task_id=task.get("task_id", ""),
            output={"decision": "deny", "reasoning": "Test block"},
        )


# ── Base Agent Tests ─────────────────────────────────────────────────────


def test_agent_type_inference():
    assert DummyAgent().agent_type == "dummy"
    assert ReconAgent().agent_type == "recon"
    assert VulnAgent().agent_type == "vuln"
    assert ExploitAgent().agent_type == "exploit"
    assert CriticAgent().agent_type == "critic"
    assert ReflectionAgent().agent_type == "reflection"


def test_agent_status_lifecycle():
    agent = DummyAgent()
    assert agent.status == AgentStatus.IDLE
    result = agent.run({"task_id": "T-001", "objective": "test"}, {})
    assert agent.status == AgentStatus.COMPLETE
    assert result.status == AgentStatus.COMPLETE


# ── Orchestrator Tests ─────────────────────────────────────────────────────


def test_orchestrator_routes_to_correct_agent():
    registry = {"recon": DummyAgent, "test": DummyAgent}
    orch = SwarmOrchestrator(context={}, agent_registry=registry, critic_enabled=False)
    result = orch.route({"task_id": "T-001", "phase": "recon", "objective": "scan ports"})
    assert result.agent_type == "dummy"
    assert result.status == AgentStatus.COMPLETE
    assert result.output["echo"] == "scan ports"


def test_orchestrator_blocks_unknown_phase():
    orch = SwarmOrchestrator(context={}, critic_enabled=False)
    result = orch.route({"task_id": "T-001", "phase": "unknown_phase"})
    assert result.status == AgentStatus.FAILED
    assert "No agent registered" in result.error


def test_orchestrator_critic_blocks_high_risk():
    registry = {"test": DummyAgent, "critic": BlockingCriticAgent}
    orch = SwarmOrchestrator(
        context={},
        agent_registry=registry,
        critic_enabled=True,
    )
    result = orch.route({"task_id": "T-001", "phase": "test", "objective": "exploit", "risk_level": "high"})
    assert result.status == AgentStatus.BLOCKED


def test_orchestrator_critic_modifies_task():
    registry = {"test": DummyAgent}
    orch = SwarmOrchestrator(context={}, agent_registry=registry, critic_enabled=True)
    result = orch.route({"task_id": "T-001", "phase": "test", "objective": "scan", "risk_level": "high"})
    # Default critic downgrades high risk to medium in standard_authorized mode
    assert result.status == AgentStatus.COMPLETE


@pytest.mark.asyncio
async def test_orchestrator_parallel_routing():
    registry = {"recon": DummyAgent, "test": DummyAgent}
    orch = SwarmOrchestrator(context={}, agent_registry=registry, max_parallel=2, critic_enabled=False)
    tasks = [
        {"task_id": "T-001", "phase": "recon", "objective": "scan 1"},
        {"task_id": "T-002", "phase": "test", "objective": "scan 2"},
        {"task_id": "T-003", "phase": "recon", "objective": "scan 3"},
    ]
    results = await orch.route_parallel(tasks)
    assert len(results) == 3
    assert all(r.status == AgentStatus.COMPLETE for r in results)


def test_orchestrator_reflection():
    orch = SwarmOrchestrator(context={}, reflection_enabled=True)
    result = orch.reflect(
        battle_log=[{"tool": "nmap", "target": "10.0.0.1", "success": True}],
        session_state={"target_ip": "10.0.0.1"},
    )
    assert result.agent_type == "reflection"
    assert result.status == AgentStatus.COMPLETE
    assert "recommended_strategy_shift" in result.output


def test_orchestrator_reflection_disabled():
    orch = SwarmOrchestrator(context={}, reflection_enabled=False)
    result = orch.reflect([], {})
    assert result.status == AgentStatus.IDLE


# ── Integration with AgentLoop (smoke) ─────────────────────────────────────


def test_agent_loop_swarm_flag():
    """Verify AgentLoop accepts use_swarm in mission_config."""
    from agent_loop import AgentLoop
    from unittest.mock import MagicMock

    config = {
        "program_name": "Test",
        "objective": "test",
        "risk_profile": "low_noise_non_destructive",
        "allowed_assets": ["127.0.0.1"],
        "disallowed_assets": [],
        "forbidden_actions": [],
        "testing_modes": ["recon"],
        "use_swarm": True,
        "swarm_max_parallel": 2,
        "critic_enabled": False,
        "reflection_enabled": False,
    }
    mock_executor = MagicMock(return_value="ok")
    loop = AgentLoop(config, Path("test_workspace_swarm"), mock_executor)
    assert loop._use_swarm is True
    assert loop._swarm is not None
    assert loop._swarm._max_parallel == 2


def test_agent_loop_reads_nested_max_parallel_agents():
    """Tier 1.8: config.yaml's ``swarm.max_parallel_agents`` (the nested key)
    must be honored. Pre-1.8 agent_loop read a non-existent top-level
    ``swarm_max_parallel`` key, so the configured value was NEVER applied
    (always fell back to 3). This test would have caught that: it sets the
    nested key to 5 and asserts the orchestrator got 5, not the default 3."""
    from agent_loop import AgentLoop
    from unittest.mock import MagicMock

    config = {
        "program_name": "Test",
        "objective": "test",
        "risk_profile": "low_noise_non_destructive",
        "allowed_assets": ["127.0.0.1"],
        "disallowed_assets": [],
        "forbidden_actions": [],
        "testing_modes": ["recon"],
        "use_swarm": True,
        "swarm": {"max_parallel_agents": 5},  # the config.yaml key
        "critic_enabled": False,
        "reflection_enabled": False,
    }
    mock_executor = MagicMock(return_value="ok")
    loop = AgentLoop(config, Path("test_workspace_swarm_nested"), mock_executor)
    assert loop._swarm is not None
    assert loop._swarm._max_parallel == 5, (
        "nested swarm.max_parallel_agents not honored (pre-1.8 read the wrong key)"
    )


def test_agent_loop_nested_key_takes_precedence_over_legacy_top_level():
    """When BOTH the nested key and the legacy top-level key are present, the
    nested config.yaml key wins (it is the documented key)."""
    from agent_loop import AgentLoop
    from unittest.mock import MagicMock

    config = {
        "program_name": "Test",
        "objective": "test",
        "risk_profile": "low_noise_non_destructive",
        "allowed_assets": ["127.0.0.1"],
        "disallowed_assets": [],
        "forbidden_actions": [],
        "testing_modes": ["recon"],
        "use_swarm": True,
        "swarm": {"max_parallel_agents": 7},
        "swarm_max_parallel": 2,  # legacy top-level -- should be ignored
        "critic_enabled": False,
        "reflection_enabled": False,
    }
    mock_executor = MagicMock(return_value="ok")
    loop = AgentLoop(config, Path("test_workspace_swarm_prec"), mock_executor)
    assert loop._swarm._max_parallel == 7


def test_agent_loop_max_parallel_defaults_to_3_when_unconfigured():
    """No swarm config at all -> the documented default of 3 (not silently
    something else)."""
    from agent_loop import AgentLoop
    from unittest.mock import MagicMock

    config = {
        "program_name": "Test",
        "objective": "test",
        "risk_profile": "low_noise_non_destructive",
        "allowed_assets": ["127.0.0.1"],
        "disallowed_assets": [],
        "forbidden_actions": [],
        "testing_modes": ["recon"],
        "use_swarm": True,
        "critic_enabled": False,
        "reflection_enabled": False,
    }
    mock_executor = MagicMock(return_value="ok")
    loop = AgentLoop(config, Path("test_workspace_swarm_default"), mock_executor)
    assert loop._swarm._max_parallel == 3


# ── Tier 1.3: phase-relevant skill hint injection ────────────────────────


class _CapturingClient:
    """Fake model client that records the last user prompt and returns empty
    JSON so the agent's LLM path is exercised without parsing side effects."""

    def __init__(self) -> None:
        self.last_prompt = ""

    def chat(self, *, messages, tools=None, stream=False):
        self.last_prompt = messages[-1]["content"]
        return {"message": {"content": "{}"}}


def _phase_selection():
    """A selection with one skill per phase so we can assert phase filtering
    inside each agent's LLM prompt builder."""
    from tools.skill_selector import SkillActivation, SkillSelection

    def _act(name, tags):
        return SkillActivation(
            name=name, reason="r", source="test", matched_tags=tuple(tags),
            risk_level="advisory", score=1, signals=(),
        )

    return SkillSelection(activations=(
        _act("recon-skill", ["reconnaissance", "nmap", "network-security"]),
        _act("vuln-skill", ["cve", "vulnerability-scanning", "vulnerability-triage"]),
        _act("exploit-skill", ["exploit", "web", "api"]),
    ))


def test_vuln_agent_llm_prompt_carries_vuln_hints_only():
    agent = VulnAgent()
    client = _CapturingClient()
    agent._llm_analyze(
        client, "10.0.0.5",
        [{"service": "http", "confidence": 0.5}], [], [],
        skill_selection=_phase_selection(),
    )
    assert "vuln-skill" in client.last_prompt
    assert "recon-skill" not in client.last_prompt
    assert "exploit-skill" not in client.last_prompt
    assert "<untrusted_skill_guidance" not in client.last_prompt


def test_vuln_agent_parses_ollama_response_object():
    expected = {"recommended_exploit_path": [{"step": 1, "tool": "nuclei"}]}
    client = SimpleNamespace(chat=lambda **_: SimpleNamespace(
        message=SimpleNamespace(content='{"recommended_exploit_path": [{"step": 1, "tool": "nuclei"}]}')
    ))

    assert VulnAgent()._llm_analyze(client, "10.0.0.5", [], [], []) == expected


def test_critic_agent_llm_prompt_carries_full_set():
    agent = CriticAgent()
    client = _CapturingClient()
    agent._llm_review(
        client, {"phase": "exploit", "target": "10.0.0.5", "risk_level": "low"},
        {"risk_profile": "standard_authorized"}, {},
        skill_selection=_phase_selection(),
    )
    # Critic reviews the full active set.
    assert "recon-skill" in client.last_prompt
    assert "vuln-skill" in client.last_prompt
    assert "exploit-skill" in client.last_prompt


def test_critic_agent_parses_ollama_response_object():
    expected = {"decision": "deny", "reasoning": "duplicate action", "modifications": {}}
    client = SimpleNamespace(chat=lambda **_: SimpleNamespace(
        message=SimpleNamespace(
            content='{"decision": "deny", "reasoning": "duplicate action", "modifications": {}}'
        )
    ))

    assert CriticAgent()._llm_review(client, {}, {}, {}) == expected


def test_reflection_agent_llm_prompt_carries_full_set():
    agent = ReflectionAgent()
    client = _CapturingClient()
    agent._llm_reflect(
        client, [], {"target_ip": "10.0.0.5"}, {},
        skill_selection=_phase_selection(),
    )
    assert "recon-skill" in client.last_prompt
    assert "vuln-skill" in client.last_prompt
    assert "exploit-skill" in client.last_prompt


def test_reflection_agent_parses_ollama_response_object():
    expected = {"why": "tool mismatch", "confidence": 0.8}
    client = SimpleNamespace(chat=lambda **_: SimpleNamespace(
        message=SimpleNamespace(content='{"why": "tool mismatch", "confidence": 0.8}')
    ))

    assert ReflectionAgent()._llm_reflect(client, [], {}, {}) == expected


def test_reflection_agent_ignores_empty_response_without_parse_warning(capsys):
    client = SimpleNamespace(chat=lambda **_: SimpleNamespace(
        message=SimpleNamespace(content="")
    ))

    assert ReflectionAgent()._llm_reflect(client, [], {}, {}) is None
    assert "LLM reflection failed" not in capsys.readouterr().out


def test_agent_llm_prompt_no_hints_when_selection_empty():
    agent = VulnAgent()
    client = _CapturingClient()
    from tools.skill_selector import SkillSelection

    agent._llm_analyze(
        client, "10.0.0.5", [{"service": "http", "confidence": 0.5}], [], [],
        skill_selection=SkillSelection(),
    )
    assert "RUNTIME SKILL HINTS" not in client.last_prompt
