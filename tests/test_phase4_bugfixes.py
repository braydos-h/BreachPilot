"""Regression tests for the Phase 4 bug fixes (shrink-and-debug cleanup).

Each test pins one adversarially-verified bug from the Phase 4 list so it
cannot silently come back. Covers the safety-critical fixes that can be
exercised without a live MCP subprocess / Ollama:

- #1  scope_gate CIDR scope-escape (allow /24 approving /16)
- #5  command_analyzer pivot gate (lateral_exec/msf/kerberoast target_ip)
- #6  autonomous_orchestrator semaphore deadlock (recursive retry)
- #9  risk_controller ``chmod -R 777`` detection
- #11 persistent_session_manager start_http_server directory containment
- #12 persistent_session_manager job/listener name validation
- #13 credentials lateral_exec LM:NT (64-hex) hash rejection
- #15 risk_controller sensitive-system-path overwrite (>/etc, tee /etc)
- #17 mcp_shared _attempt_dir collision under concurrent dispatch

Bugs #2/#3/#7/#8/#10/#16/#18/#19/#20/#21 are covered by existing tests or
require a live MCP session / Ollama loop (swarm_result, swarm timeout, the
terminal PIPE drain, the boot spinner tail) and are left to the integration
smoke in the plan's end-to-end verification block.
"""

from __future__ import annotations

import asyncio
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest

from db import DatabaseManager, _new_id
from risk_controller import RiskController
from scope_gate import ScopeGate
from tools.command_analyzer import analysis_payload, analyze_command
from tools.mcp_shared import _attempt_dir
from tools.persistent_session_manager import (
    BackgroundJobHelper,
    ListenerHelper,
    PersistentSessionManager,
    _is_inside_workspace,
    _validate_name,
)


# ── #1: scope_gate CIDR scope-escape ───────────────────────────────────────


def _gate(tmp_path: Path, allowed: list[str]) -> ScopeGate:
    db = DatabaseManager(tmp_path / "scope.db")
    with db.connection(write=True) as conn:
        db.ensure_schema(conn)
    return ScopeGate(db, _new_id("M"), allowed_assets=allowed)


def test_cidr_overbroad_subnet_is_blocked(tmp_path: Path) -> None:
    """An allow of /24 must NOT approve a /16 (the prefix-strip escape)."""
    gate = _gate(tmp_path, ["10.0.0.0/24"])
    assert gate.is_asset_in_scope("10.0.0.0/16") is False
    # A narrower subnet of the allow is in-scope.
    assert gate.is_asset_in_scope("10.0.0.0/25") is True


def test_cidr_exact_and_bare_ip_matching(tmp_path: Path) -> None:
    gate = _gate(tmp_path, ["10.0.0.0/24"])
    assert gate.is_asset_in_scope("10.0.0.0/24") is True   # exact
    assert gate.is_asset_in_scope("10.0.0.5") is True      # bare IP in range
    assert gate.is_asset_in_scope("10.0.0.5/32") is True   # /32 host in range
    assert gate.is_asset_in_scope("10.0.1.5") is False     # bare IP outside
    assert gate.is_asset_in_scope("10.0.1.0/24") is False  # adjacent subnet


# ── #5: command_analyzer pivot gate ─────────────────────────────────────────


def _pivot(action: str, args: dict[str, Any], locked: str = "10.0.0.50") -> Any:
    return analyze_command(
        analysis_payload(action, args),
        language="shell",
        locked_ip=locked,
        allowed_targets=[],
    )


def test_lateral_exec_pivot_to_non_target_blocked() -> None:
    """lateral_exec(target_ip=<other>) with a benign command must be blocked."""
    res = _pivot("lateral_exec", {"target_ip": "10.0.0.99", "command": "whoami"})
    assert res.allowed is False
    assert any("10.0.0.99" in r for r in res.reasons)


def test_lateral_exec_to_locked_target_allowed() -> None:
    res = _pivot("lateral_exec", {"target_ip": "10.0.0.50", "command": "whoami"})
    assert res.allowed is True


def test_msf_module_pivot_blocked_even_with_options() -> None:
    """``options`` used to mask the ``target_ip`` arg from the egress scan."""
    res = _pivot(
        "run_msf_module",
        {"module": "auxiliary/scanner/smb/smb_version", "target_ip": "10.0.0.99", "options": "THREADS=1"},
    )
    assert res.allowed is False


def test_kerberoast_dc_ip_pivot_blocked() -> None:
    res = _pivot("kerberoast", {"target_ip": "10.0.0.50", "dc_ip": "10.0.0.99"})
    assert res.allowed is False


def test_generate_payload_allowlisted_lhost_allowed() -> None:
    """A quoted lhost in the repr must not break allowlist matching."""
    payload = analysis_payload(
        "generate_payload",
        {"payload_type": "windows/shell_reverse_tcp", "lhost": "10.0.0.99", "lport": 4444, "fmt": "exe"},
    )
    res = analyze_command(payload, language="shell", locked_ip="10.0.0.50", allowed_targets=["10.0.0.99"])
    # Allowlisted operator callback host -> not egress; reverse-shell callback
    # is allowlisted -> allowed.
    assert res.allowed is True


# ── #6: autonomous_orchestrator semaphore deadlock ──────────────────────────


class _StubExecutor:
    """Always-fails-retryable executor: triggers the retry path without IO."""

    def __init__(self) -> None:
        self.calls = 0

    async def execute(self, task: Any, state: Any) -> dict[str, Any]:
        self.calls += 1
        return {"success": False, "blocked": False, "error": "transient boom"}


@pytest.mark.asyncio
async def test_execute_task_batch_no_deadlock_with_many_retryable(tmp_path: Path) -> None:
    """≥3 failing retryable tasks must not deadlock the semaphore(3)."""
    from tools.autonomous_orchestrator import (
        AttackPhase,
        AttackState,
        AttackTask,
        AutonomousOrchestrator,
    )

    orch = AutonomousOrchestrator(
        mission_config={"max_cycles": 100, "max_pivot_depth": 3},
        workspace_root=tmp_path,
    )
    stub = _StubExecutor()
    orch._executor = stub  # type: ignore[attr-defined]

    # Instant backoff so the 2**retry_count sleeps don't slow the test.
    async def _nosleep(*_a: Any, **_k: Any) -> None:
        return None
    orig_sleep = asyncio.sleep
    asyncio.sleep = _nosleep  # type: ignore[assignment]
    try:
        tasks = [
            AttackTask(
                task_id=f"t{i}",
                phase=AttackPhase.EXPLOITATION,
                module_name=f"m{i}",
                target="10.0.0.5",
                max_retries=1,
            )
            for i in range(5)
        ]
        state = AttackState(target="10.0.0.5")
        # The old recursive-inside-semaphore code deadlocked here forever.
        await asyncio.wait_for(
            orch._execute_task_batch(tasks, state),  # type: ignore[attr-defined]
            timeout=5.0,
        )
    finally:
        asyncio.sleep = orig_sleep  # type: ignore[assignment]

    # max_retries=1 -> 1 initial + 1 retry = 2 executions per task.
    assert stub.calls == 10


# ── Phase 3 policy: pivot-depth 0 = single-IP lock ─────────────────────────


class _PivotStubExecutor:
    """Lateral-movement module always 'succeeds' so the recursion branch runs."""

    async def execute(self, task: Any, state: Any) -> dict[str, Any]:
        return {"success": True, "pivot_targets": []}


@pytest.mark.asyncio
async def test_pivot_depth_zero_default_no_recursion(tmp_path: Path) -> None:
    """Default max_pivot_depth is 0 (single-IP lock): pivots are discovered but
    never recursed into, matching CLAUDE.md 'target-locked to a single IP'."""
    from tools.autonomous_orchestrator import AttackState, AutonomousOrchestrator

    orch = AutonomousOrchestrator(mission_config={}, workspace_root=tmp_path)
    assert orch._max_pivot_depth == 0  # type: ignore[attr-defined]
    orch._executor = _PivotStubExecutor()  # type: ignore[attr-defined]

    recursed: list[tuple[str, int]] = []

    async def _fake_attack(target: str, *, _depth: int = 0) -> dict[str, Any]:
        recursed.append((target, _depth))
        return {}

    orch._attack_target = _fake_attack  # type: ignore[attr-defined]

    state = AttackState(target="10.0.0.5", pivot_targets=["10.0.0.99", "10.0.0.100"])
    await orch._phase_lateral_movement(state, _depth=0)  # type: ignore[attr-defined]
    assert recursed == [], f"depth=0 must not recurse into pivots, got {recursed}"


@pytest.mark.asyncio
async def test_pivot_depth_two_recurses_one_hop(tmp_path: Path) -> None:
    """Sanity contrast: with max_pivot_depth=2 the orchestrator DOES recurse
    one hop, proving the depth=0 test above is meaningful (not a broken stub)."""
    from tools.autonomous_orchestrator import AttackState, AutonomousOrchestrator

    orch = AutonomousOrchestrator(
        mission_config={"max_pivot_depth": 2}, workspace_root=tmp_path
    )
    assert orch._max_pivot_depth == 2  # type: ignore[attr-defined]
    orch._executor = _PivotStubExecutor()  # type: ignore[attr-defined]

    recursed: list[str] = []

    async def _fake_attack(target: str, *, _depth: int = 0) -> dict[str, Any]:
        recursed.append(target)
        return {}

    orch._attack_target = _fake_attack  # type: ignore[attr-defined]

    state = AttackState(target="10.0.0.5", pivot_targets=["10.0.0.99"])
    await orch._phase_lateral_movement(state, _depth=0)  # type: ignore[attr-defined]
    assert recursed == ["10.0.0.99"]


# ── #9: risk_controller chmod -R 777 ───────────────────────────────────────


def test_chmod_recursive_777_blocked() -> None:
    rc = RiskController()
    res = rc.assess_action("test", "chmod", "chmod -R 777 /var/www")
    assert res.allowed is False
    assert "destructive" in res.reason.lower() or "destructive" in " ".join(res.warnings).lower()


def test_chmod_777_blocked() -> None:
    rc = RiskController()
    assert rc.assess_action("test", "chmod", "chmod 777 /tmp/x").allowed is False


# ── #15: risk_controller sensitive-system-path overwrite ────────────────────


def test_redirect_overwrite_etc_blocked() -> None:
    rc = RiskController()
    res = rc.assess_action("test", "shell", "echo x > /etc/passwd")
    assert res.allowed is False


def test_tee_overwrite_etc_blocked() -> None:
    rc = RiskController()
    res = rc.assess_action("test", "tee", "echo x | tee /etc/cron.d/x")
    assert res.allowed is False


def test_chmod_recursive_777_etc_blocked() -> None:
    rc = RiskController()
    assert rc.assess_action("test", "chmod", "chmod -R 777 /etc").allowed is False


def test_cp_from_etc_not_blocked_by_overwrite_gate() -> None:
    """cp/mv have source-vs-destination ambiguity; the overwrite gate must not
    block a safe read like ``cp /etc/passwd /tmp/backup``."""
    rc = RiskController()
    # ``cp`` is not a destructive verb and the redirect/tee gate doesn't match
    # it, so this benign copy is allowed (not flagged as a system overwrite).
    res = rc.assess_action("test", "cp", "cp /etc/passwd /tmp/backup")
    assert res.allowed is True


# ── #11: start_http_server directory containment ───────────────────────────


def test_start_http_server_rejects_directory_outside_workspace(tmp_path: Path) -> None:
    helper = ListenerHelper(tmp_path / "ws")
    # /etc is not inside the workspace -> refused before any subprocess spawn.
    ok, pid = helper.start_http_server(name="srv", port=0, directory="/etc")
    assert ok is False and pid is None


def test_start_http_server_rejects_traversal_directory(tmp_path: Path) -> None:
    helper = ListenerHelper(tmp_path / "ws")
    ok, pid = helper.start_http_server(name="srv", port=0, directory="../../etc")
    assert ok is False and pid is None


def test_is_inside_workspace_boundary() -> None:
    ws = Path("/tmp/ai_nmap_ws_test")
    assert _is_inside_workspace(Path("/tmp/ai_nmap_ws_test/x"), ws) is True
    assert _is_inside_workspace(Path("/tmp/ai_nmap_ws_test"), ws) is True
    assert _is_inside_workspace(Path("/etc"), ws) is False
    assert _is_inside_workspace(Path("/tmp/ai_nmap_ws_test/../etc"), ws) is False


# ── #12: job/listener name validation ───────────────────────────────────────


@pytest.mark.parametrize("bad", ["../../etc/x", "a/b", "a\\b", "..", "", "a b", "a;b", "x" * 65])
def test_validate_name_rejects_unsafe(bad: str) -> None:
    with pytest.raises(ValueError):
        _validate_name(bad)


@pytest.mark.parametrize("good", ["revshell", "payload.1", "job-2", "a_b", "x" * 64])
def test_validate_name_accepts_safe(good: str) -> None:
    assert _validate_name(good) == good


def test_background_job_start_rejects_traversal_name(tmp_path: Path) -> None:
    helper = BackgroundJobHelper(tmp_path / "ws")
    ok, pid = helper.start(name="../../etc/evil", command="echo hi")
    assert ok is False and pid is None


def test_listener_start_rejects_traversal_name(tmp_path: Path) -> None:
    helper = ListenerHelper(tmp_path / "ws")
    ok, pid = helper.start_netcat(name="../../etc/evil", port=0)
    assert ok is False and pid is None


def test_persistent_session_manager_surfaces_rejection_reason(tmp_path: Path) -> None:
    mgr = PersistentSessionManager(tmp_path / "ws")
    # Bad name -> clear error string (not a generic "Failed to start").
    res = mgr.start_background_job(name="../evil", command="echo hi")
    assert res["success"] is False
    assert "invalid session name" in res["error"]


# ── #13: credentials lateral_exec LM:NT hash ───────────────────────────────


def _make_server(tmp_path: Path, *, require_allowlist: bool = False):
    from mcp_exploit_server import create_mcp_server
    from tools.cve_lookup import CVESearchSettings, NVDClient
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    config: dict[str, Any] = {
        "exploit": {"require_explicit_allowlist": require_allowlist, "allowed_targets": []}
    }
    return create_mcp_server(
        ExploitSearch(ExploitSearchSettings()),
        NVDClient(CVESearchSettings()),
        WebResearcher(WebResearcherSettings()),
        tmp_path,
        config,
    )


def _text(result) -> str:
    content = result[0] if isinstance(result, (list, tuple)) else result
    if hasattr(content, "content"):
        content = content.content
    parts = []
    for c in content:
        t = getattr(c, "text", None)
        if t is None and isinstance(c, dict):
            t = c.get("text")
        if t is None:
            t = str(c)
        parts.append(t)
    return "".join(parts)


def _stub_run_ok(*_a: Any, **_k: Any) -> tuple[int, str, str]:
    return (0, "ok output", "")


@pytest.mark.asyncio
async def test_lateral_exec_accepts_lm_nt_hash(monkeypatch, tmp_path: Path) -> None:
    """Bug #13: a valid LM:NT (64-hex with colon) hash was rejected before."""
    monkeypatch.setattr("tools.mcp_tools.credentials._run_with_pgrp_timeout", _stub_run_ok)
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool(
        "lateral_exec",
        {
            "target_ip": "10.0.0.1",
            "method": "psexec",
            "username": "admin",
            "ntlm_hash": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            "command": "whoami",
        },
    ))
    assert "ntlm_hash must be 32 hex chars" not in text
    assert "LATERAL_EXEC_RESULT: completed" in text


@pytest.mark.asyncio
async def test_lateral_exec_accepts_nt_only_hash(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("tools.mcp_tools.credentials._run_with_pgrp_timeout", _stub_run_ok)
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool(
        "lateral_exec",
        {
            "target_ip": "10.0.0.1",
            "method": "psexec",
            "username": "admin",
            "ntlm_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            "command": "whoami",
        },
    ))
    assert "ntlm_hash must be 32 hex chars" not in text


@pytest.mark.asyncio
async def test_lateral_exec_rejects_junk_hash(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool(
        "lateral_exec",
        {"target_ip": "10.0.0.1", "method": "psexec", "username": "admin", "ntlm_hash": "zzz"},
    ))
    assert "BLOCKED" in text and "ntlm_hash must be 32 hex chars" in text


# ── #17: _attempt_dir collision ────────────────────────────────────────────


def test_attempt_dir_unique_under_burst(tmp_path: Path) -> None:
    ids = set()
    for _ in range(2000):
        _d, aid = _attempt_dir(tmp_path / "ws")
        ids.add(aid)
    assert len(ids) == 2000
    # Each id must carry the random suffix (8 hex chars after the microsecond stamp).
    assert all(re.search(r"_[0-9a-f]{8}$", aid) for aid in ids)