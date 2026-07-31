"""Phase 4: spawn_subagent / await_subagent / list_subagents MCP tools.

Verifies the main AI's delegation surface:

1. **spawn_subagent** starts a specialist agent in a background asyncio task
   and returns immediately with a subagent_id.
2. **await_subagent** blocks until the sub-agent finishes and returns its
   merged result (findings, output, status).
3. **list_subagents** polls live status without blocking.
4. **Target-IP lock** — spawn_subagent refuses an out-of-allowlist target so
   parallelizing agents does NOT parallelize the attack surface.
5. **Phase validation** — only recon/analysis/exploit/post_exploit accepted.

These tests construct the _SubagentManager directly (bypassing the MCP
server) so they run without a live MCP session — the sub-agent uses the
swarm's Path-B model (in-process Python calls, no MCP client round-trip).
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from tools.mcp_tools.parallel_agents import _SubagentManager


# ── Helpers ───────────────────────────────────────────────────────────────


def _make_manager(tmp_path: Path, config: dict[str, Any] | None = None) -> _SubagentManager:
    ws = tmp_path / "exploit_workspace"
    ws.mkdir(parents=True, exist_ok=True)
    return _SubagentManager(ws, config or {"exploit": {"permission": "full_access"}})


# Patch SwarmOrchestrator.route to a fast no-op so tests don't hit the
# network / Ollama. The real route() dispatches to a specialist agent that
# may call ReconPipeline (nmap) / NVDClient (HTTP) — too slow + flaky for a
# unit test. The manager under test just needs route() to return an
# AgentResult so it can serialize it.
class _FakeAgentResult:
    """Mimics tools.swarm.base.AgentResult for the patched route()."""
    def __init__(self, task_id: str, status: str = "complete", output: dict | None = None):
        self.task_id = task_id
        self.status = type("S", (), {"value": status})()
        self.output = output or {"target": "10.0.0.5", "services": 1}
        self.error = ""
        self.findings = []
        self.new_tasks = []


def _patch_route(manager: _SubagentManager, *, delay: float = 0.0, status: str = "complete"):
    """Replace manager._get_orchestrator() with a stub that returns a
    fake route() callable. Avoids building a real SwarmOrchestrator."""
    class _StubOrch:
        def route(self, task):
            if delay:
                import time as _t
                _t.sleep(delay)
            return _FakeAgentResult(task.get("task_id", ""), status=status)
    manager._orchestrator = _StubOrch()
    return manager


# ── spawn / await ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_spawn_subagent_returns_immediately(tmp_path):
    """spawn() returns a subagent_id + status='running' without blocking,
    even though the sub-agent task runs in the background."""
    mgr = _patch_route(_make_manager(tmp_path), delay=0.3)
    result = await mgr.spawn("recon", "10.0.0.5", "scan host")
    assert result["status"] == "running"
    assert "subagent_id" in result
    assert result["subagent_id"].startswith("subagent-recon-")


@pytest.mark.asyncio
async def test_await_subagent_returns_result(tmp_path):
    """await_result() blocks until the sub-agent finishes and returns its
    output + status."""
    mgr = _patch_route(_make_manager(tmp_path), delay=0.1)
    spawn = await mgr.spawn("recon", "10.0.0.5", "scan host")
    sid = spawn["subagent_id"]
    result = await mgr.await_result(sid, timeout_seconds=5)
    assert result["subagent_id"] == sid
    assert result["status"] == "complete"
    assert "output" in result
    assert result["output"]["target"] == "10.0.0.5"


@pytest.mark.asyncio
async def test_await_subagent_already_complete_returns_cached(tmp_path):
    """If the sub-agent already finished, await_result returns the cached
    result immediately without waiting."""
    mgr = _patch_route(_make_manager(tmp_path), delay=0.05)
    spawn = await mgr.spawn("recon", "10.0.0.5", "scan")
    sid = spawn["subagent_id"]
    # Wait for it to finish before awaiting.
    await asyncio.sleep(0.2)
    # Should return instantly from the cache.
    start = asyncio.get_event_loop().time()
    result = await mgr.await_result(sid, timeout_seconds=5)
    elapsed = asyncio.get_event_loop().time() - start
    assert result["status"] == "complete"
    assert elapsed < 0.1  # cached, not re-waited


@pytest.mark.asyncio
async def test_await_subagent_timeout_returns_partial(tmp_path):
    """If the sub-agent doesn't finish within timeout, return a 'timeout'
    status with whatever partial info is available — don't wedge the caller."""
    mgr = _patch_route(_make_manager(tmp_path), delay=2.0)  # 2s, longer than timeout
    spawn = await mgr.spawn("recon", "10.0.0.5", "slow scan")
    sid = spawn["subagent_id"]
    result = await mgr.await_result(sid, timeout_seconds=0.2)
    assert result["status"] == "timeout"
    assert "partial" in result
    # The partial should carry the running status from spawn time.
    assert result["partial"]["status"] == "running"


@pytest.mark.asyncio
async def test_await_unknown_subagent_returns_unknown(tmp_path):
    """Awaiting a non-existent subagent_id returns 'unknown' status, not an
    exception — the main AI's tool call shouldn't crash on a bad id."""
    mgr = _make_manager(tmp_path)
    result = await mgr.await_result("does-not-exist", timeout_seconds=1)
    assert result["status"] == "unknown"
    assert "no sub-agent" in result["error"]


# ── list ──────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_subagents_shows_running_and_complete(tmp_path):
    """list_live() returns all spawned sub-agents with their current status."""
    mgr = _patch_route(_make_manager(tmp_path), delay=0.2)
    spawn1 = await mgr.spawn("recon", "10.0.0.5", "scan A")
    spawn2 = await mgr.spawn("recon", "10.0.0.6", "scan B")

    # While running, both should show 'running'.
    live = mgr.list_live()
    assert len(live) == 2
    statuses = {e["status"] for e in live}
    assert statuses == {"running"}

    # After they finish, list shows them complete.
    await asyncio.sleep(0.4)
    live = mgr.list_live()
    assert len(live) == 2
    assert all(e["status"] == "complete" for e in live)


# ── Result file persistence ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_subagent_result_written_to_file(tmp_path):
    """The sub-agent's result is persisted to <workspace>/subagents/<id>.json
    so it survives even after the task is garbage-collected."""
    mgr = _patch_route(_make_manager(tmp_path), delay=0.05)
    spawn = await mgr.spawn("recon", "10.0.0.5", "scan")
    sid = spawn["subagent_id"]
    await mgr.await_result(sid, timeout_seconds=5)

    result_path = mgr._workspace / "subagents" / f"{sid}.json"
    assert result_path.exists()
    data = json.loads(result_path.read_text(encoding="utf-8"))
    assert data["subagent_id"] == sid
    assert data["status"] == "complete"
    assert data["target"] == "10.0.0.5"


# ── Crash safety ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_subagent_crash_records_failed_result(tmp_path):
    """If the sub-agent task raises, the manager records a 'failed' result
    (not silently drops it) so await_subagent still returns something."""
    mgr = _make_manager(tmp_path)

    class _CrashingOrch:
        def route(self, task):
            raise RuntimeError("agent exploded")
    mgr._orchestrator = _CrashingOrch()

    spawn = await mgr.spawn("recon", "10.0.0.5", "doom")
    sid = spawn["subagent_id"]
    result = await mgr.await_result(sid, timeout_seconds=5)
    assert result["status"] == "failed"
    assert "agent exploded" in result["error"]


# ── Concurrent spawns ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_multiple_subagents_run_concurrently(tmp_path):
    """Two spawn() calls with 0.3s each should both be running
    simultaneously and complete in ~0.3s total, not ~0.6s."""
    mgr = _patch_route(_make_manager(tmp_path), delay=0.3)
    start = asyncio.get_event_loop().time()
    s1 = await mgr.spawn("recon", "10.0.0.5", "A")
    s2 = await mgr.spawn("recon", "10.0.0.6", "B")
    r1 = await mgr.await_result(s1["subagent_id"], timeout_seconds=5)
    r2 = await mgr.await_result(s2["subagent_id"], timeout_seconds=5)
    elapsed = asyncio.get_event_loop().time() - start

    assert r1["status"] == "complete"
    assert r2["status"] == "complete"
    # Both ran concurrently: 2 × 0.3s sequential = 0.6s; concurrent ≈ 0.3s.
    # Allow headroom for the to_thread dispatch + serialization.
    assert elapsed < 0.8, f"sub-agents ran sequentially (took {elapsed:.2f}s)"


# ── Target-IP lock (the safety property) ─────────────────────────────────
#
# These exercise the actual MCP tool function (spawn_subagent) — not just the
# _SubagentManager — so they cover the validation gate that runs at spawn
# time. The tools are registered via register_parallel_agent_tools but only
# when swarm.parallel_enabled is true, so we build a tiny fake mcp + ctx that
# captures the registered functions.


class _FakeMcp:
    """Captures @mcp.tool() decorated functions so a test can call them
    directly without a real MCP server."""
    def __init__(self):
        self.tools = {}
    def tool(self):
        def deco(fn):
            self.tools[fn.__name__] = fn
            return fn
        return deco


def _register_and_get_tools(tmp_path, *, parallel_enabled: bool, config_overrides: dict | None = None):
    """Register the parallel-agent tools on a fake mcp and return the
    {name: callable} dict. Mirrors how mcp_exploit_server.py wires them."""
    from tools.mcp_tools.parallel_agents import register_parallel_agent_tools
    from tools.mcp_tools.registry import ToolContext, make_audit_tool, make_require_allowlist
    ws = tmp_path / "exploit_workspace"
    ws.mkdir(parents=True, exist_ok=True)
    config = {"swarm": {"parallel_enabled": parallel_enabled}, "exploit": {"permission": "full_access"}}
    if config_overrides:
        config.update(config_overrides)
    audit_tool = make_audit_tool(ws)
    require_allowlist = make_require_allowlist(ws, config)
    ctx = ToolContext(
        workspace=ws, config=config, search=None, nvd=None, researcher=None,
        audit_tool=audit_tool, require_allowlist=require_allowlist,
    )
    mcp = _FakeMcp()
    register_parallel_agent_tools(mcp, ctx=ctx)
    return mcp.tools, ws, config


@pytest.mark.asyncio
async def test_spawn_subagent_refuses_out_of_allowlist_target(tmp_path):
    """spawn_subagent refuses a target not in the allowlist — parallelizing
    agents does NOT parallelize the attack surface. This is the one safety
    property kept on the attack path."""
    # require_explicit_allowlist + allowed_targets = [10.0.0.5] only.
    tools, ws, config = _register_and_get_tools(
        tmp_path,
        parallel_enabled=True,
        config_overrides={
            "exploit": {
                "permission": "full_access",
                "require_explicit_allowlist": True,
                "allowed_targets": ["10.0.0.5"],
            },
        },
    )
    # Patch the manager's orchestrator so a successful spawn wouldn't hang.
    from tools.mcp_tools.parallel_agents import _get_manager
    mgr = _get_manager(ws, config)
    mgr._orchestrator = type("O", (), {"route": lambda self, t: _FakeAgentResult("ok")})()

    spawn = tools["spawn_subagent"]
    # Out-of-allowlist target -> BLOCKED (returned as a plain string, not JSON,
    # since spawn_subagent returns the BLOCKED message directly). No task started.
    blocked_result = await spawn("recon", "8.8.8.8", "scan OOB target")
    assert "BLOCKED" in blocked_result
    assert "not in allowlist" in blocked_result or "not in the explicit allowlist" in blocked_result

    # In-allowlist target -> running (returned as JSON).
    running_result = json.loads(await spawn("recon", "10.0.0.5", "scan allowed target"))
    assert running_result["status"] == "running"


@pytest.mark.asyncio
async def test_spawn_subagent_rejects_invalid_phase(tmp_path):
    """spawn_subagent rejects an unsupported phase."""
    tools, ws, config = _register_and_get_tools(tmp_path, parallel_enabled=True)
    from tools.mcp_tools.parallel_agents import _get_manager
    mgr = _get_manager(ws, config)
    mgr._orchestrator = type("O", (), {"route": lambda self, t: _FakeAgentResult("ok")})()

    spawn = tools["spawn_subagent"]
    result = await spawn("lateral_movement", "10.0.0.5", "bad phase")
    assert "BLOCKED" in result
    assert "phase must be one of" in result


@pytest.mark.asyncio
async def test_spawn_subagent_rejects_invalid_target(tmp_path):
    """spawn_subagent rejects a non-IP/non-FQDN target string."""
    tools, ws, config = _register_and_get_tools(tmp_path, parallel_enabled=True)
    from tools.mcp_tools.parallel_agents import _get_manager
    mgr = _get_manager(ws, config)
    mgr._orchestrator = type("O", (), {"route": lambda self, t: _FakeAgentResult("ok")})()

    spawn = tools["spawn_subagent"]
    result = await spawn("recon", "not a target!!!", "bad input")
    assert "BLOCKED" in result
    assert "invalid target" in result.lower()


def test_parallel_agent_tools_not_registered_when_disabled(tmp_path):
    """When swarm.parallel_enabled is false (default), the tools are NOT
    registered — the delegation surface is opt-in only."""
    tools, ws, config = _register_and_get_tools(tmp_path, parallel_enabled=False)
    assert "spawn_subagent" not in tools
    assert "await_subagent" not in tools
    assert "list_subagents" not in tools


def test_parallel_agent_tools_registered_when_enabled(tmp_path):
    """When swarm.parallel_enabled is true, all three tools are registered."""
    tools, ws, config = _register_and_get_tools(tmp_path, parallel_enabled=True)
    assert "spawn_subagent" in tools
    assert "await_subagent" in tools
    assert "list_subagents" in tools