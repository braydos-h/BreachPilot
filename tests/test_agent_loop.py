"""Tests for agent_loop.py and autonomous_orchestrator.py — comprehensive coverage.

Tests:
- Agent loop initialization
- Task execution flow
- Autonomous orchestrator phases
- Attack state management
- Retry engine
- Exploit chaining
- Timeline recording
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tools.autonomous_orchestrator import (
    AggressionLevel,
    AttackModuleExecutor,
    AttackPhase,
    AttackState,
    AttackTask,
    AutonomousOrchestrator,
    RetryEngine,
    TaskStatus,
)
from tools.recon_pipeline import HostReconResult, ServiceInfo

# ── Fixtures ───────────────────────────────────────────────────────────────

@pytest.fixture
def mission_config() -> dict:
    return {
        "program_name": "Test Program",
        "risk_profile": "high_authorized_testing",
        "allowed_assets": ["10.0.0.50"],
        "disallowed_assets": [],
        "forbidden_actions": ["denial_of_service"],
        "testing_modes": ["recon", "analysis", "test", "exploit"],
        "max_cycles": 10,
        "max_aggression": "maximum",
    }


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    return tmp_path / "test_workspace"


@pytest.fixture
def sample_recon_result() -> HostReconResult:
    return HostReconResult(
        target_ip="10.0.0.50",
        os_family="Linux",
        open_ports=[22, 80, 445],
        services=[
            ServiceInfo(port=22, service="ssh", version="OpenSSH 8.5p1"),
            ServiceInfo(port=80, service="http"),
            ServiceInfo(port=445, service="microsoft-ds"),
        ],
    )


@pytest.fixture
def mock_scope_gate() -> MagicMock:
    gate = MagicMock()
    gate.check_scope.return_value = MagicMock(allowed=True, requires_human_approval=False)
    return gate


@pytest.fixture
def mock_risk_controller() -> MagicMock:
    ctrl = MagicMock()
    ctrl.can_proceed.return_value = True
    return ctrl


# ── AttackState Tests ────────────────────────────────────────────────────────

class TestAttackState:
    def test_initial_state(self) -> None:
        state = AttackState(target="10.0.0.50")
        assert state.target == "10.0.0.50"
        assert state.current_phase == AttackPhase.RECONNAISSANCE
        assert state.aggression == AggressionLevel.NORMAL
        assert state.privilege_level == "none"
        assert state.access_achieved is False

    def test_record_success(self) -> None:
        state = AttackState(target="10.0.0.50")
        state.record_success("TestModule", {
            "shell_type": "reverse",
            "privilege_level": "user",
            "credentials": [{"user": "admin", "pass": "password"}],
        })
        assert state.access_achieved is True
        assert state.shell_type == "reverse"
        assert state.privilege_level == "user"
        assert len(state.credentials_found) == 1
        assert "TestModule" in state.successful_exploits

    def test_record_failure(self) -> None:
        state = AttackState(target="10.0.0.50")
        state.record_failure("TestModule", "Connection refused")
        assert "TestModule" in state.failed_attempts
        assert len(state.failed_attempts["TestModule"]) == 1

    def test_escalate_aggression(self) -> None:
        state = AttackState(target="10.0.0.50")
        assert state.aggression == AggressionLevel.NORMAL
        state.escalate_aggression()
        assert state.aggression == AggressionLevel.AGGRESSIVE
        state.escalate_aggression()
        assert state.aggression == AggressionLevel.MAXIMUM
        state.escalate_aggression()
        assert state.aggression == AggressionLevel.MAXIMUM  # Stays at max

    def test_should_continue_no_access(self) -> None:
        state = AttackState(target="10.0.0.50")
        assert state.should_continue() is True

    def test_should_continue_with_access(self) -> None:
        state = AttackState(target="10.0.0.50")
        state.access_achieved = True
        state.privilege_level = "user"
        assert state.should_continue() is True  # Not at max privilege

    def test_should_continue_max_privilege(self) -> None:
        state = AttackState(target="10.0.0.50")
        state.access_achieved = True
        state.privilege_level = "root"
        assert state.should_continue() is False

    def test_should_continue_with_pivots(self) -> None:
        state = AttackState(target="10.0.0.50")
        state.access_achieved = True
        state.privilege_level = "root"
        state.pivot_targets = ["10.0.0.51"]
        assert state.should_continue() is True

    def test_timeline_events(self) -> None:
        state = AttackState(target="10.0.0.50")
        state.add_timeline_event("test", "Test event", {"key": "value"})
        assert len(state.timeline) == 1
        assert state.timeline[0]["event_type"] == "test"
        assert state.timeline[0]["description"] == "Test event"

    def test_to_dict(self) -> None:
        state = AttackState(target="10.0.0.50")
        state.record_success("Test", {"shell_type": "reverse"})
        d = state.to_dict()
        assert d["target"] == "10.0.0.50"
        assert d["access_achieved"] is True
        assert d["shell_type"] == "reverse"


# ── AttackTask Tests ─────────────────────────────────────────────────────────

class TestAttackTask:
    def test_task_creation(self) -> None:
        task = AttackTask(
            task_id="ATK-00001",
            phase=AttackPhase.EXPLOITATION,
            module_name="SSHBruteForce",
            target="10.0.0.50",
        )
        assert task.task_id == "ATK-00001"
        assert task.status == TaskStatus.PENDING
        assert task.retry_count == 0

    def test_task_to_dict(self) -> None:
        task = AttackTask(
            task_id="ATK-00001",
            phase=AttackPhase.EXPLOITATION,
            module_name="SSHBruteForce",
            target="10.0.0.50",
        )
        d = task.to_dict()
        assert d["task_id"] == "ATK-00001"
        assert d["phase"] == "exploit"


# ── RetryEngine Tests ──────────────────────────────────────────────────────────

class TestRetryEngine:
    def test_should_retry_transient_error(self) -> None:
        assert RetryEngine.should_retry("SSHBruteForce", "Connection timeout", 0, 3) is True

    def test_should_retry_permanent_error(self) -> None:
        assert RetryEngine.should_retry("SSHBruteForce", "Out of scope", 0, 3) is False

    def test_should_retry_max_attempts(self) -> None:
        assert RetryEngine.should_retry("SSHBruteForce", "Timeout", 3, 3) is False

    def test_should_retry_tool_not_found(self) -> None:
        assert RetryEngine.should_retry("SSHBruteForce", "Tool not found", 0, 3) is False

    def test_get_retry_parameters_ssh(self) -> None:
        params = RetryEngine.get_retry_parameters("SSHBruteForce", 0)
        assert "timeout" in params
        assert "threads" in params

    def test_get_retry_parameters_sql(self) -> None:
        params = RetryEngine.get_retry_parameters("SQLInjection", 1)
        assert "technique" in params
        assert "level" in params

    def test_get_retry_parameters_default(self) -> None:
        params = RetryEngine.get_retry_parameters("UnknownModule", 0)
        assert "timeout" in params

    def test_get_retry_parameters_exhausted(self) -> None:
        params = RetryEngine.get_retry_parameters("SSHBruteForce", 10)
        assert params["aggressive"] is True
        assert params["timeout"] > 60


# ── AttackModuleExecutor Tests ───────────────────────────────────────────────

class TestAttackModuleExecutor:
    @pytest.mark.asyncio
    async def test_execute_module_not_found(self, mock_scope_gate: MagicMock) -> None:
        executor = AttackModuleExecutor(mock_scope_gate)
        task = AttackTask(
            task_id="ATK-00001",
            phase=AttackPhase.EXPLOITATION,
            module_name="NonExistent",
            target="10.0.0.50",
        )
        state = AttackState(target="10.0.0.50")
        result = await executor.execute(task, state)
        assert result["success"] is False
        assert "not found" in result["error"]

    @pytest.mark.asyncio
    async def test_execute_scope_blocked(self, mock_scope_gate: MagicMock) -> None:
        mock_scope_gate.check_scope.return_value = MagicMock(
            allowed=False, reason="Out of scope"
        )
        executor = AttackModuleExecutor(mock_scope_gate)
        task = AttackTask(
            task_id="ATK-00001",
            phase=AttackPhase.EXPLOITATION,
            module_name="SSHBruteForce",
            target="10.0.0.50",
        )
        state = AttackState(target="10.0.0.50")
        result = await executor.execute(task, state)
        assert result["success"] is False
        assert result["blocked"] is True

    @pytest.mark.asyncio
    async def test_execute_risk_budget_exhausted(self, mock_scope_gate: MagicMock, mock_risk_controller: MagicMock) -> None:
        mock_risk_controller.can_proceed.return_value = False
        executor = AttackModuleExecutor(mock_scope_gate, mock_risk_controller)
        task = AttackTask(
            task_id="ATK-00001",
            phase=AttackPhase.EXPLOITATION,
            module_name="SSHBruteForce",
            target="10.0.0.50",
        )
        state = AttackState(target="10.0.0.50")
        result = await executor.execute(task, state)
        assert result["success"] is False
        assert "budget" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_execute_success(self, mock_scope_gate: MagicMock) -> None:
        executor = AttackModuleExecutor(mock_scope_gate)
        task = AttackTask(
            task_id="ATK-00001",
            phase=AttackPhase.EXPLOITATION,
            module_name="APIFuzzer",
            target="10.0.0.50",
        )
        state = AttackState(target="10.0.0.50")
        result = await executor.execute(task, state)
        assert result["success"] is True
        assert "result" in result

    @pytest.mark.asyncio
    async def test_execute_timeout(self, mock_scope_gate: MagicMock) -> None:
        with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError()):
            executor = AttackModuleExecutor(mock_scope_gate)
            task = AttackTask(
                task_id="ATK-00001",
                phase=AttackPhase.EXPLOITATION,
                module_name="APIFuzzer",
                target="10.0.0.50",
                parameters={"timeout": 1},
            )
            state = AttackState(target="10.0.0.50")
            result = await executor.execute(task, state)
            assert result["success"] is False
            assert result.get("timeout") is True


# ── AutonomousOrchestrator Tests ─────────────────────────────────────────────

class TestAutonomousOrchestrator:
    def test_initialization(self, mission_config: dict, workspace: Path) -> None:
        orchestrator = AutonomousOrchestrator(
            mission_config=mission_config,
            workspace_root=workspace,
        )
        assert orchestrator._workspace.exists()
        assert orchestrator._max_cycles == 10

    def test_get_state(self, mission_config: dict, workspace: Path) -> None:
        orchestrator = AutonomousOrchestrator(
            mission_config=mission_config,
            workspace_root=workspace,
        )
        state = orchestrator.get_state("10.0.0.50")
        assert state.target == "10.0.0.50"
        assert "10.0.0.50" in orchestrator._states

    def test_new_task_id(self, mission_config: dict, workspace: Path) -> None:
        orchestrator = AutonomousOrchestrator(
            mission_config=mission_config,
            workspace_root=workspace,
        )
        id1 = orchestrator._new_task_id()
        id2 = orchestrator._new_task_id()
        assert id1 != id2
        assert id1.startswith("ATK-")

    @pytest.mark.asyncio
    async def test_phase_reconnaissance(self, mission_config: dict, workspace: Path, sample_recon_result: HostReconResult) -> None:
        with patch("tools.recon_pipeline.ReconPipeline.recon_host", new_callable=AsyncMock) as mock_recon:
            mock_recon.return_value = sample_recon_result

            orchestrator = AutonomousOrchestrator(
                mission_config=mission_config,
                workspace_root=workspace,
            )
            state = orchestrator.get_state("10.0.0.50")
            await orchestrator._phase_reconnaissance(state)

            assert state.recon_result is not None
            assert len(state.recon_result.open_ports) == 3
            assert len(state.timeline) > 0

    @pytest.mark.asyncio
    async def test_phase_exploitation(self, mission_config: dict, workspace: Path, sample_recon_result: HostReconResult) -> None:
        with patch("tools.autonomous_orchestrator.AttackModuleExecutor.execute", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = {"success": True, "result": {"status": "exploited"}}

            orchestrator = AutonomousOrchestrator(
                mission_config=mission_config,
                workspace_root=workspace,
            )
            state = orchestrator.get_state("10.0.0.50")
            state.recon_result = sample_recon_result
            await orchestrator._phase_exploitation(state)

            assert state.current_phase == AttackPhase.EXPLOITATION
            assert mock_exec.called

    @pytest.mark.asyncio
    async def test_phase_privilege_escalation(self, mission_config: dict, workspace: Path) -> None:
        with patch("tools.autonomous_orchestrator.AttackModuleExecutor.execute", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = {"success": True, "result": {"privilege_level": "root"}}

            orchestrator = AutonomousOrchestrator(
                mission_config=mission_config,
                workspace_root=workspace,
            )
            state = orchestrator.get_state("10.0.0.50")
            state.access_achieved = True
            state.privilege_level = "user"
            state.recon_result = HostReconResult(
                target_ip="10.0.0.50",
                os_family="Linux",
            )
            await orchestrator._phase_privilege_escalation(state)

            assert state.current_phase == AttackPhase.PRIVILEGE_ESCALATION

    @pytest.mark.asyncio
    async def test_phase_lateral_movement(self, mission_config: dict, workspace: Path) -> None:
        with (
            patch("tools.autonomous_orchestrator.AttackModuleExecutor.execute", new_callable=AsyncMock) as mock_exec,
            patch.object(AutonomousOrchestrator, "_attack_target", new_callable=AsyncMock) as mock_attack,
        ):
            mock_exec.return_value = {"success": True}
            mock_attack.return_value = {"status": "complete"}

            # ponytail: the lab build defaults max_pivot_depth to 0 (no
            # host-pivoting, the one Path-B target-lock safety). This test
            # exercises the pivot-recursion mechanism itself, so it must opt
            # in: with the `_depth + 1 < max_pivot_depth` cap, depth-1 recursion
            # needs max_pivot_depth >= 2 (allows one pivot, blocks depth 2).
            mission_config["max_pivot_depth"] = 2
            orchestrator = AutonomousOrchestrator(
                mission_config=mission_config,
                workspace_root=workspace,
            )
            state = orchestrator.get_state("10.0.0.50")
            state.pivot_targets = ["10.0.0.51"]
            await orchestrator._phase_lateral_movement(state)

            assert state.current_phase == AttackPhase.LATERAL_MOVEMENT
            # _phase_lateral_movement recurses into _attack_target with the pivot
            # depth incremented (Tier 0 item 0.6a pivot cap); entering at depth 0
            # -> the new target is attacked at depth 1.
            mock_attack.assert_awaited_once_with("10.0.0.51", _depth=1)

    @pytest.mark.asyncio
    async def test_execute_task_batch(self, mission_config: dict, workspace: Path) -> None:
        with patch("tools.autonomous_orchestrator.AttackModuleExecutor.execute", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = {"success": True, "result": {"status": "exploited"}}

            orchestrator = AutonomousOrchestrator(
                mission_config=mission_config,
                workspace_root=workspace,
            )
            state = orchestrator.get_state("10.0.0.50")
            tasks = [
                AttackTask(
                    task_id=f"ATK-{i:05d}",
                    phase=AttackPhase.EXPLOITATION,
                    module_name="APIFuzzer",
                    target="10.0.0.50",
                )
                for i in range(3)
            ]
            await orchestrator._execute_task_batch(tasks, state)

            assert mock_exec.call_count == 3

    @pytest.mark.asyncio
    async def test_retry_failed_modules(self, mission_config: dict, workspace: Path) -> None:
        with patch("tools.autonomous_orchestrator.AttackModuleExecutor.execute", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = {"success": True, "result": {"status": "exploited"}}

            orchestrator = AutonomousOrchestrator(
                mission_config=mission_config,
                workspace_root=workspace,
            )
            state = orchestrator.get_state("10.0.0.50")
            state.record_failure("APIFuzzer", "Connection timeout")
            state.escalate_aggression()
            await orchestrator._retry_failed_modules(state)

            assert mock_exec.called

    def test_create_service_specific_tasks(self, mission_config: dict, workspace: Path, sample_recon_result: HostReconResult) -> None:
        orchestrator = AutonomousOrchestrator(
            mission_config=mission_config,
            workspace_root=workspace,
        )
        state = orchestrator.get_state("10.0.0.50")
        state.recon_result = sample_recon_result
        tasks = orchestrator._create_service_specific_tasks(state)

        assert len(tasks) > 0
        task_names = [t.module_name for t in tasks]
        assert "SSHBruteForce" in task_names
        assert "SMBRelay" in task_names
        assert "SMBNullSession" in task_names
        assert "WebShellUpload" in task_names
        assert "SQLInjection" in task_names

    def test_save_and_load_state(self, mission_config: dict, workspace: Path) -> None:
        orchestrator = AutonomousOrchestrator(
            mission_config=mission_config,
            workspace_root=workspace,
        )
        state = orchestrator.get_state("10.0.0.50")
        state.record_success("Test", {"shell_type": "reverse"})

        save_path = orchestrator.save_state()
        assert save_path.exists()

        # Verify saved content
        data = json.loads(save_path.read_text())
        assert "states" in data
        assert "10.0.0.50" in data["states"]

    @pytest.mark.asyncio
    async def test_full_campaign(self, mission_config: dict, workspace: Path, sample_recon_result: HostReconResult) -> None:
        with patch("tools.recon_pipeline.ReconPipeline.recon_host", new_callable=AsyncMock) as mock_recon:
            mock_recon.return_value = sample_recon_result

            with patch("tools.autonomous_orchestrator.AttackModuleExecutor.execute", new_callable=AsyncMock) as mock_exec:
                mock_exec.return_value = {"success": True, "result": {"status": "exploited", "shell_type": "reverse"}}

                orchestrator = AutonomousOrchestrator(
                    mission_config=mission_config,
                    workspace_root=workspace,
                )
                result = await orchestrator.run_autonomous_campaign(["10.0.0.50"])

                assert "targets" in result
                assert "results" in result
                assert result["targets"] == ["10.0.0.50"]
                assert result["successful_exploits"] >= 0

    def test_stop(self, mission_config: dict, workspace: Path) -> None:
        orchestrator = AutonomousOrchestrator(
            mission_config=mission_config,
            workspace_root=workspace,
        )
        assert orchestrator._running is True
        orchestrator.stop()
        assert orchestrator._running is False


# ── Swarm unification (Tier 0 item 0.6b): critic/reflection/blackboard ────────
#
# The autonomous attack path (AttackModuleExecutor.execute) previously ran
# modules with only inline scope/risk checks -- NO critic pre-check, NO
# reflection, NO shared blackboard. These tests pin the wiring: a wired
# CriticAgent denies/modifies before any module code runs; module outcomes are
# recorded to a shared blackboard so the critic's repeat-failure detection
# fires; reflection publishes back; and an UNWIRED executor behaves exactly as
# before (legacy callers / the rest of the suite).

from tools.swarm.agents.critic_agent import CriticAgent
from tools.swarm.agents.reflection_agent import ReflectionAgent
from tools.swarm.orchestrator import SwarmOrchestrator


def _allowing_scope_gate() -> MagicMock:
    """A scope gate whose check_scope always returns allowed=True (so the critic
    reaches its forbidden-action / risk-profile / repeat-failure layers)."""
    gate = MagicMock()
    gate.check_scope.return_value = MagicMock(allowed=True, requires_human_approval=False)
    return gate


class TestSwarmUnification:
    """Tier 0 item 0.6b -- wire critic/reflection/shared-blackboard into the
    autonomous attack path."""

    @pytest.mark.asyncio
    async def test_critic_deny_blocks_module_before_it_runs(self) -> None:
        # forbidden_actions includes the phase string "exploit" -> critic Layer 3
        # denies, and the module is never looked up.
        executor = AttackModuleExecutor(
            _allowing_scope_gate(),
            mission_config={"forbidden_actions": ["exploit"], "risk_profile": "high_authorized_testing"},
            critic_agent=CriticAgent(),
        )
        task = AttackTask(
            task_id="ATK-00001", phase=AttackPhase.EXPLOITATION,
            module_name="APIFuzzer", target="10.0.0.50",
        )
        state = AttackState(target="10.0.0.50")
        with patch("tools.autonomous_orchestrator.get_module") as mock_get:
            result = await executor.execute(task, state)
            mock_get.assert_not_called()  # critic deny short-circuits before lookup
        assert result["success"] is False
        assert result["blocked"] is True
        assert result["critic"]["decision"] == "deny"
        assert "POLICY" in result["critic"]["reasoning"]

    @pytest.mark.asyncio
    async def test_critic_modify_downgrades_max_aggression(self) -> None:
        # high-risk action (MAXIMUM aggression) in a standard_authorized profile
        # -> critic Layer 3b modifies risk_level to medium, which the executor
        # maps back to AGGRESSIVE. The run then proceeds with the mutated task.
        executor = AttackModuleExecutor(
            _allowing_scope_gate(),
            mission_config={"risk_profile": "standard_authorized"},
            critic_agent=CriticAgent(),
        )
        task = AttackTask(
            task_id="ATK-00001", phase=AttackPhase.EXPLOITATION,
            module_name="APIFuzzer", target="10.0.0.50",
            aggression=AggressionLevel.MAXIMUM,
        )
        state = AttackState(target="10.0.0.50")
        result = await executor.execute(task, state)
        assert result["success"] is True  # module still runs after a modify
        assert task.aggression == AggressionLevel.AGGRESSIVE
        assert task.parameters.get("critic_risk_downgrade") == "high->medium"

    @pytest.mark.asyncio
    async def test_critic_repeat_failure_sets_require_mutation(self) -> None:
        # A module already in the shared blackboard's failed_modules -> critic
        # Layer 4 returns modify with require_mutation, recorded on the task.
        blackboard = {"failed_modules": ["APIFuzzer"]}
        executor = AttackModuleExecutor(
            _allowing_scope_gate(),
            blackboard=blackboard,
            mission_config={"risk_profile": "high_authorized_testing"},
            critic_agent=CriticAgent(),
        )
        task = AttackTask(
            task_id="ATK-00001", phase=AttackPhase.EXPLOITATION,
            module_name="APIFuzzer", target="10.0.0.50",
        )
        state = AttackState(target="10.0.0.50")
        await executor.execute(task, state)
        assert task.parameters.get("critic_require_mutation") is True

    @pytest.mark.asyncio
    async def test_module_failure_recorded_on_shared_blackboard(self) -> None:
        # A timeout writes the module to the shared blackboard so a later critic
        # sees it as a repeat failure.
        blackboard = {"failed_modules": []}
        executor = AttackModuleExecutor(_allowing_scope_gate(), blackboard=blackboard)
        task = AttackTask(
            task_id="ATK-00001", phase=AttackPhase.EXPLOITATION,
            module_name="APIFuzzer", target="10.0.0.50", parameters={"timeout": 1},
        )
        state = AttackState(target="10.0.0.50")
        with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError()):
            result = await executor.execute(task, state)
        assert result["success"] is False
        assert "APIFuzzer" in blackboard["failed_modules"]

    @pytest.mark.asyncio
    async def test_critic_sees_prior_failure_on_shared_blackboard(self) -> None:
        # End-to-end of the unification: a first attempt times out and records
        # the failure on the shared blackboard; a second attempt with a wired
        # critic reads that blackboard and flags the repeat failure.
        blackboard: dict = {"failed_modules": []}
        executor = AttackModuleExecutor(
            _allowing_scope_gate(),
            blackboard=blackboard,
            mission_config={"risk_profile": "high_authorized_testing"},
            critic_agent=CriticAgent(),
        )
        first = AttackTask(
            task_id="ATK-1", phase=AttackPhase.EXPLOITATION,
            module_name="APIFuzzer", target="10.0.0.50", parameters={"timeout": 1},
        )
        with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError()):
            await executor.execute(first, AttackState(target="10.0.0.50"))
        assert blackboard["failed_modules"] == ["APIFuzzer"]
        second = AttackTask(
            task_id="ATK-2", phase=AttackPhase.EXPLOITATION,
            module_name="APIFuzzer", target="10.0.0.50",
        )
        await executor.execute(second, AttackState(target="10.0.0.50"))
        assert second.parameters.get("critic_require_mutation") is True

    @pytest.mark.asyncio
    async def test_module_success_clears_from_failed_on_blackboard(self) -> None:
        blackboard = {"failed_modules": ["APIFuzzer"], "successful_modules": []}
        executor = AttackModuleExecutor(_allowing_scope_gate(), blackboard=blackboard)
        task = AttackTask(
            task_id="ATK-00001", phase=AttackPhase.EXPLOITATION,
            module_name="APIFuzzer", target="10.0.0.50",
        )
        state = AttackState(target="10.0.0.50")
        await executor.execute(task, state)
        assert "APIFuzzer" not in blackboard["failed_modules"]
        assert "APIFuzzer" in blackboard["successful_modules"]

    @pytest.mark.asyncio
    async def test_reflection_publishes_to_blackboard_after_success(self) -> None:
        blackboard: dict = {}
        executor = AttackModuleExecutor(
            _allowing_scope_gate(), blackboard=blackboard, reflection_agent=ReflectionAgent(),
        )
        task = AttackTask(
            task_id="ATK-00001", phase=AttackPhase.EXPLOITATION,
            module_name="APIFuzzer", target="10.0.0.50",
        )
        state = AttackState(target="10.0.0.50")
        await executor.execute(task, state)
        # ReflectionAgent.run writes last_reflection / strategy_shift itself.
        assert "last_reflection" in blackboard
        assert isinstance(blackboard["last_reflection"].get("what_worked"), list)
        assert blackboard["strategy_shift"].startswith("ACCELERATE")

    @pytest.mark.asyncio
    async def test_legacy_executor_unwired_behaves_unchanged(self) -> None:
        # No blackboard / critic / reflection wired -> exactly the old behavior.
        executor = AttackModuleExecutor(_allowing_scope_gate())
        task = AttackTask(
            task_id="ATK-00001", phase=AttackPhase.EXPLOITATION,
            module_name="APIFuzzer", target="10.0.0.50",
        )
        state = AttackState(target="10.0.0.50")
        result = await executor.execute(task, state)
        assert result["success"] is True
        assert "critic" not in result            # no critic decision attached
        assert task.parameters.get("critic_require_mutation") is None
        assert task.parameters.get("critic_risk_downgrade") is None

    def test_autonomous_orchestrator_wires_blackboard_and_agents(self) -> None:
        blackboard = {"failed_modules": []}
        critic = CriticAgent()
        reflection = ReflectionAgent()
        orchestrator = AutonomousOrchestrator(
            mission_config={"risk_profile": "high_authorized_testing"},
            workspace_root=Path("reports/_swarm_test"),
            blackboard=blackboard,
            model_client=object(),
            critic_agent=critic,
            reflection_agent=reflection,
        )
        assert orchestrator._executor._blackboard is blackboard    # live ref
        assert orchestrator._executor._critic is critic
        assert orchestrator._executor._reflection is reflection
        assert orchestrator._executor._model_client is not None

    def test_share_blackboard_returns_live_reference(self) -> None:
        # share_blackboard() returns the SAME live top-level dict the swarm
        # mutates; top-level mutations are visible via get_blackboard().
        # get_blackboard() returns a distinct top-level dict (a shallow copy),
        # so a top-level add on the snapshot does not leak back to the live board.
        # (Nested list values are shared by reference either way -- that is the
        # existing shallow-copy behavior and not part of this contract.)
        swarm = SwarmOrchestrator(context={}, critic_enabled=False, reflection_enabled=False)
        live = swarm.share_blackboard()
        live["failed_modules"].append("SSHBruteForce")
        assert swarm.get_blackboard()["failed_modules"] == ["SSHBruteForce"]
        snapshot = swarm.get_blackboard()
        assert snapshot is not live  # get_blackboard returns a distinct top-level dict
        snapshot["__snapshot_only__"] = "leak-check"
        assert swarm.share_blackboard().get("__snapshot_only__") is None
