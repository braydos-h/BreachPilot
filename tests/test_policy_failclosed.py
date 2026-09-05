"""Fail-closed policy tests (Flow A only)."""

from __future__ import annotations

from pathlib import Path

import pytest

from scope_gate import ScopeGate
from tools.exploit_agent import ExploitPermission, ExploitPolicy, ExploitSettings


def _policy(tmp_path: Path, target: str = "10.0.0.50", gate=None) -> ExploitPolicy:
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


@pytest.mark.asyncio
async def test_gate_none_denies(tmp_path: Path):
    policy = _policy(tmp_path, gate=None)
    approved = await policy.approve_action("run_exploit_terminal", "nmap -sV 10.0.0.50")
    assert approved is False
    assert any(r.status == "SCOPE_DENIED" for r in policy._records)


@pytest.mark.asyncio
async def test_requires_approval_denies_in_full_access(tmp_path: Path):
    target = "10.0.0.50"
    gate = ScopeGate(
        None,  # type: ignore[arg-type]
        "",
        allowed_assets=[target],
        risk_profile="standard_authorized",
    )
    policy = _policy(tmp_path, target, gate)
    approved = await policy.approve_action("run_exploit_terminal", f"nmap -sV {target}")
    assert approved is False
    assert any(r.status == "SCOPE_DENIED" for r in policy._records)


@pytest.mark.asyncio
async def test_allows_in_high_authorized_testing(tmp_path: Path):
    target = "10.0.0.50"
    gate = ScopeGate(
        None,  # type: ignore[arg-type]
        "",
        allowed_assets=[target],
        risk_profile="high_authorized_testing",
    )
    policy = _policy(tmp_path, target, gate)
    approved = await policy.approve_action("run_exploit_terminal", f"nmap -sV {target}")
    assert approved is True
