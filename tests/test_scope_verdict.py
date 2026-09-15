"""Regression tests for the single three-state scope verdict (P1 scope-approval-enum).

Covers:
1. ``verdict_for`` normalizes the frozen two-bool shape (and test doubles) to
   exactly one of DENY / ALLOW / REQUIRES_APPROVAL.
2. ``LabAutoApprovalPolicy`` centralizes the lab auto-approval mapping with an
   auditable record at one chokepoint.
3. ``AttackModuleExecutor`` requests approval instead of proceeding silently
   when the gate flags REQUIRES_APPROVAL (the exact misuse the audit found).
4. ``ExploitPolicy._enforce_mission_scope`` denies REQUIRES_APPROVAL under a
   non-lab profile and records an auditable auto-approval under the lab one.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

from tools.campaign.executor import AttackModuleExecutor
from tools.campaign.state import AggressionLevel, AttackPhase, AttackState, AttackTask
from tools.exploit_agent import ExploitPermission, ExploitPolicy, ExploitSettings
from tools.scope_verdict import LabAutoApprovalPolicy, ScopeVerdict, verdict_for


def _result(*, allowed: bool, approval: bool = False) -> SimpleNamespace:
    return SimpleNamespace(allowed=allowed, requires_human_approval=approval, reason="in scope")


# ── 1. verdict_for ───────────────────────────────────────────────────────────


def test_verdict_deny_wins_over_approval_flag():
    assert verdict_for(_result(allowed=False, approval=True)) is ScopeVerdict.DENY
    assert verdict_for(_result(allowed=False)) is ScopeVerdict.DENY


def test_verdict_requires_approval_on_explicit_flag():
    assert verdict_for(_result(allowed=True, approval=True)) is ScopeVerdict.REQUIRES_APPROVAL


def test_verdict_allow_without_flag():
    assert verdict_for(_result(allowed=True)) is ScopeVerdict.ALLOW


def test_verdict_mock_double_without_flag_stays_allow():
    """A MagicMock that only sets ``allowed`` must not newly block: the
    approval flag was never explicitly configured."""
    assert verdict_for(MagicMock(allowed=True)) is ScopeVerdict.ALLOW
    assert verdict_for(MagicMock(allowed=False)) is ScopeVerdict.DENY


# ── 2. LabAutoApprovalPolicy ─────────────────────────────────────────────────


def test_lab_policy_allow_needs_no_record():
    recorded: list[str] = []
    policy = LabAutoApprovalPolicy("standard_authorized", record=recorded.append)
    assert policy.decide(_result(allowed=True)) is True
    assert recorded == []


def test_lab_policy_deny_never_proceeds():
    for profile in ("standard_authorized", "high_authorized_testing"):
        recorded: list[str] = []
        policy = LabAutoApprovalPolicy(profile, record=recorded.append)
        assert policy.decide(_result(allowed=False)) is False
        assert recorded == []


def test_lab_policy_records_auto_approval_under_lab_profile():
    recorded: list[str] = []
    policy = LabAutoApprovalPolicy("high_authorized_testing", record=recorded.append)
    assert policy.decide(_result(allowed=True, approval=True), context="op ctx") is True
    assert len(recorded) == 1 and "op ctx" in recorded[0]


def test_lab_policy_blocks_approval_under_other_profiles():
    recorded: list[str] = []
    policy = LabAutoApprovalPolicy("standard_authorized", record=recorded.append)
    assert policy.decide(_result(allowed=True, approval=True)) is False
    assert recorded == []


# ── 3. AttackModuleExecutor requests approval instead of silent allow ────────


async def test_executor_blocks_on_requires_approval(tmp_path: Path, monkeypatch) -> None:
    """The audit-found misuse: the executor checked only ``allowed`` and
    dropped the approval flag. It must now block with an approval request."""
    gate = MagicMock()
    gate.check_scope.return_value = _result(allowed=True, approval=True)
    executor = AttackModuleExecutor(gate)
    state = AttackState(target="10.0.0.50")
    task = AttackTask(
        task_id="ATK-APPROVAL",
        phase=AttackPhase.EXPLOITATION,
        module_name="SSHBruteForce",
        target="10.0.0.50",
        aggression=AggressionLevel.NORMAL,
    )

    out = await executor.execute(task, state)

    assert out["success"] is False
    assert out["blocked"] is True
    assert out["approval_required"] is True
    assert "pproval" in out["error"]


async def test_executor_still_runs_on_plain_allow(tmp_path: Path, monkeypatch) -> None:
    """A clean ALLOW still proceeds to module dispatch (no behavior change)."""
    gate = MagicMock()
    gate.check_scope.return_value = _result(allowed=True)
    executor = AttackModuleExecutor(gate)
    state = AttackState(target="10.0.0.50")
    task = AttackTask(
        task_id="ATK-ALLOW",
        phase=AttackPhase.EXPLOITATION,
        module_name="SSHBruteForce",
        target="10.0.0.50",
        aggression=AggressionLevel.NORMAL,
    )

    class _OkModule:
        name = "SSHBruteForce"

        def run(self, ctx):
            return {"status": "info"}

    import tools.autonomous_orchestrator as orch_mod

    monkeypatch.setattr(orch_mod, "get_module", lambda name: _OkModule())
    out = await executor.execute(task, state)
    assert out.get("blocked") is not True or "approval" not in str(out.get("error", ""))


# ── 4. ExploitPolicy adapter ─────────────────────────────────────────────────


def _make_policy(tmp_path: Path, *, risk_profile: str, approval: bool) -> ExploitPolicy:
    target = "10.0.0.50"
    gate = MagicMock()
    gate._risk_profile = risk_profile
    gate.check_scope.return_value = _result(allowed=True, approval=approval)
    settings = ExploitSettings(
        enabled=True,
        mode="standalone",
        permission=ExploitPermission.FULL_ACCESS,
        attack_mode=True,
        target_ip=target,
        workspace_root=tmp_path,
    )
    policy = ExploitPolicy(settings, tmp_path, scope_gate=gate)
    policy._locked_ip = target
    policy._allowed_targets = [target]
    return policy


async def test_policy_denies_requires_approval_under_standard(tmp_path: Path) -> None:
    policy = _make_policy(tmp_path, risk_profile="standard_authorized", approval=True)
    assert await policy._enforce_mission_scope("run_exploit_terminal", "nmap -sV 10.0.0.50") is False
    denied = [r for r in policy._records if r.status == "SCOPE_DENIED"]
    assert denied and "requires_human_approval" in denied[0].detail


async def test_policy_auto_approves_with_audit_row_under_lab_profile(tmp_path: Path) -> None:
    policy = _make_policy(tmp_path, risk_profile="high_authorized_testing", approval=True)
    assert await policy._enforce_mission_scope("run_exploit_terminal", "nmap -sV 10.0.0.50") is True
    auto = [r for r in policy._records if r.status == "auto_approved"]
    assert auto, "expected an auditable auto_approved row"
    assert auto[0].approved is True
