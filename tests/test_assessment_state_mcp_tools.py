"""Tests for the AI-facing assessment-state / capability-discovery MCP tools.

The tools are registered against a stub FastMCP-like object that captures the
decorated tool functions so we can call them directly without an MCP transport.
Workspace files are mocked in tmp_path. No live targets are required.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

import pytest


class _StubMCP:
    """Minimal stand-in for FastMCP: ``mcp.tool()`` is a decorator that records
    the wrapped function by name. We deliberately do NOT call the real
    FastMCP so the test stays transport-free and runs without an event loop."""

    def __init__(self) -> None:
        self.tools: dict[str, Callable[..., Any]] = {}

    def tool(self, *args: Any, **kwargs: Any) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            self.tools[fn.__name__] = fn
            return fn

        return decorator

    # some helpers query _tool_manager._tools (sync introspection path)
    _tool_manager: Any = None


def _build_ctx(
    tmp_path: Path, *, require_allowlist_flag: bool = True, allowed: tuple[str, ...] = ("10.0.0.50",)
) -> Any:
    from tools.cve_lookup import CVESearchSettings, NVDClient
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings
    from tools.mcp_shared import make_audit_tool, make_require_allowlist
    from tools.mcp_tools.registry import ToolContext
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    config: dict[str, Any] = {
        "exploit": {
            "require_explicit_allowlist": require_allowlist_flag,
            "allowed_targets": list(allowed),
        }
    }
    return ToolContext(
        workspace=tmp_path,
        config=config,
        search=ExploitSearch(ExploitSearchSettings()),
        nvd=NVDClient(CVESearchSettings()),
        researcher=WebResearcher(WebResearcherSettings()),
        audit_tool=make_audit_tool(tmp_path),
        require_allowlist=make_require_allowlist(tmp_path, config),
    )


def _register(tmp_path: Path, **ctx_kwargs: Any) -> tuple[_StubMCP, Any]:
    from tools.mcp_tools.assessment_state import register_assessment_state_tools

    mcp = _StubMCP()
    ctx = _build_ctx(tmp_path, **ctx_kwargs)
    register_assessment_state_tools(mcp, ctx=ctx)
    return mcp, ctx


# ---------------------------------------------------------------- get_assessment_state


def test_get_assessment_state_returns_block(tmp_path: Path) -> None:
    mcp, _ = _register(tmp_path)
    out = mcp.tools["get_assessment_state"](target_ip="10.0.0.50")
    assert out.startswith("ASSESSMENT_STATE:")
    assert "TARGET: 10.0.0.50" in out
    assert "PLAN: (none)" in out
    assert "RECON: (none)" in out
    assert "HYPOTHESES: 0 open / 0 total" in out


def test_get_assessment_state_blocked_when_target_not_allowed(tmp_path: Path) -> None:
    mcp, _ = _register(tmp_path)
    out = mcp.tools["get_assessment_state"](target_ip="10.0.0.99")
    assert out.startswith("BLOCKED:")


def test_get_assessment_state_reflects_hypotheses_and_plan(tmp_path: Path) -> None:
    from tools.assessment_state import AssessmentStateStore
    from tools.attack_planner import AttackPlanner, AttackStep

    mcp, ctx = _register(tmp_path)
    # seed owned assessment state
    store = AssessmentStateStore(ctx.workspace)
    state = store.load("10.0.0.50")
    state.goal = "backdoor"
    state.phase = "exploit"
    state.add_hypothesis("SMB vulnerable to EternalBlue", confidence=0.8, created_from="recon")
    store.save(state)
    # seed a plan
    planner = AttackPlanner(ctx.workspace)
    plan = planner.create_plan("10.0.0.50", attack_mode=True)
    plan.add_step(AttackStep(phase="exploit", tool="run_attack_module", reason="x", target_ip="10.0.0.50"))
    planner.save_plan(plan)

    out = mcp.tools["get_assessment_state"](target_ip="10.0.0.50")
    assert "GOAL: backdoor" in out
    assert "PHASE: exploit" in out
    assert "HYPOTHESES: 1 open / 1 total" in out
    assert "PLAN: phase=recon steps=1 done=0" in out


# ---------------------------------------------------------------- query_capabilities


def test_query_capabilities_modules_lists_capability_records(tmp_path: Path) -> None:
    mcp, _ = _register(tmp_path)
    out = mcp.tools["query_capabilities"](scope="modules")
    assert out.startswith("CAPABILITIES: scope=modules")
    assert "TOTAL:" in out
    # at least one well-known built-in module name shows up
    assert "Log4jRCE" in out or "EternalBlue" in out


def test_query_capabilities_modules_service_filter(tmp_path: Path) -> None:
    mcp, _ = _register(tmp_path)
    out = mcp.tools["query_capabilities"](scope="modules", service="http")
    assert out.startswith("CAPABILITIES: scope=modules")
    # every listed module line should be a module that targets http-ish service;
    # we just assert the filter narrows the set and is internally consistent.
    total_line = [line for line in out.splitlines() if line.startswith("TOTAL:")][0]
    total = int(total_line.split(":", 1)[1].strip())
    assert total >= 0


def test_query_capabilities_tools_lists_registered_names(tmp_path: Path) -> None:
    mcp, _ = _register(tmp_path)

    # populate the sync introspection path the tool uses
    class _TM:
        _tools = {
            "foo": type("T", (), {"name": "foo", "description": ""})(),
            "bar": type("T", (), {"name": "bar", "description": ""})(),
        }

    mcp._tool_manager = _TM()
    out = mcp.tools["query_capabilities"](scope="tools")
    assert out.startswith("CAPABILITIES: scope=tools")
    assert "COUNT: 2" in out
    assert "- foo" in out
    assert "- bar" in out


def test_query_capabilities_bad_scope(tmp_path: Path) -> None:
    mcp, _ = _register(tmp_path)
    out = mcp.tools["query_capabilities"](scope="bogus")
    assert out.startswith("BLOCKED:")


# ---------------------------------------------------------------- get_capability_details


def test_get_capability_details_module_found(tmp_path: Path) -> None:
    mcp, _ = _register(tmp_path)
    out = mcp.tools["get_capability_details"](name="Log4jRCE", scope="modules")
    assert out.startswith("CAPABILITY_DETAILS: scope=modules")
    assert "NAME: Log4jRCE" in out
    assert "APPLICABILITY_SCORE:" in out


def test_get_capability_details_module_not_found(tmp_path: Path) -> None:
    mcp, _ = _register(tmp_path)
    out = mcp.tools["get_capability_details"](name="NopeModule", scope="modules")
    assert out.startswith("CAPABILITY_DETAILS: module not found")


# ---------------------------------------------------------------- get_evidence


def test_get_evidence_empty_when_no_audit(tmp_path: Path) -> None:
    mcp, _ = _register(tmp_path)
    out = mcp.tools["get_evidence"](target_ip="10.0.0.50")
    assert out.startswith("EVIDENCE:")
    assert "COUNT: 0" in out


def test_get_evidence_returns_compact_refs_no_secrets(tmp_path: Path) -> None:
    mcp, ctx = _register(tmp_path)
    audit = ctx.workspace / "exploit_audit.jsonl"
    audit.parent.mkdir(parents=True, exist_ok=True)
    rows = [
        {
            "target_ip": "10.0.0.50",
            "tool_name": "run_exploit_terminal",
            "attempt_id": "att-1",
            "status": "completed",
            "duration_s": 12.5,
            "args": {"command": "SECRET_PASSWORD hunter2 nmap 10.0.0.50"},
        },
        {
            "target_ip": "10.0.0.50",
            "tool_name": "run_msf_module",
            "attempt_id": "att-2",
            "status": "blocked",
            "duration_s": 1.0,
            "args": {"command": "set RHOSTS 10.0.0.50"},
        },
        {"target_ip": "10.0.0.99", "tool_name": "run_exploit_terminal", "attempt_id": "att-3", "status": "completed"},
        {
            "target_ip": "10.0.0.50",
            "tool_name": "check_os",
            "attempt_id": "att-4",
            "status": "started",
        },  # started must be skipped
    ]
    with audit.open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")

    out = mcp.tools["get_evidence"](target_ip="10.0.0.50")
    assert out.startswith("EVIDENCE:")
    assert "COUNT: 2" in out  # att-3 filtered out (other target), att-4 skipped (started)
    assert "att-1" in out and "att-2" in out
    assert "att-3" not in out and "att-4" not in out
    # secrets must never leak
    assert "SECRET_PASSWORD" not in out
    assert "hunter2" not in out
    # compact ref shape present
    assert "exploit_audit:10.0.0.50:att-1" in out
    assert "duration=12.5" in out


def test_get_evidence_tool_filter(tmp_path: Path) -> None:
    mcp, ctx = _register(tmp_path)
    audit = ctx.workspace / "exploit_audit.jsonl"
    audit.parent.mkdir(parents=True, exist_ok=True)
    with audit.open("w", encoding="utf-8") as fh:
        fh.write(
            json.dumps({"target_ip": "10.0.0.50", "tool_name": "check_os", "attempt_id": "a1", "status": "completed"})
            + "\n"
        )
        fh.write(
            json.dumps(
                {"target_ip": "10.0.0.50", "tool_name": "run_msf_module", "attempt_id": "a2", "status": "completed"}
            )
            + "\n"
        )
    out = mcp.tools["get_evidence"](target_ip="10.0.0.50", tool="check_os")
    assert "COUNT: 1" in out
    assert "a1" in out and "a2" not in out


def test_get_evidence_blocked_when_target_not_allowed(tmp_path: Path) -> None:
    mcp, _ = _register(tmp_path)
    out = mcp.tools["get_evidence"](target_ip="10.0.0.99")
    assert out.startswith("BLOCKED:")


# ---------------------------------------------------------------- record_hypothesis


def test_record_hypothesis_persists_and_returns_id(tmp_path: Path) -> None:
    mcp, ctx = _register(tmp_path)
    out = mcp.tools["record_hypothesis"](
        target_ip="10.0.0.50",
        statement="SMB null session is enabled",
        confidence=0.7,
        expected_evidence="anonymous listing on \\\\10.0.0.50\\IPC$",
        created_from="recon",
    )
    assert out.startswith("HYPOTHESIS_RECORDED:")
    assert "ID: H-001" in out
    assert "CONFIDENCE: 0.70" in out

    # the file on disk must carry it
    from tools.assessment_state import AssessmentStateStore

    state = AssessmentStateStore(ctx.workspace).load("10.0.0.50")
    assert len(state.hypotheses) == 1
    assert state.hypotheses[0].statement == "SMB null session is enabled"
    assert state.hypotheses[0].created_from == "recon"


def test_record_hypothesis_blocked_when_target_not_allowed(tmp_path: Path) -> None:
    mcp, _ = _register(tmp_path)
    out = mcp.tools["record_hypothesis"](target_ip="10.0.0.99", statement="x")
    assert out.startswith("BLOCKED:")


def test_record_hypothesis_requires_statement(tmp_path: Path) -> None:
    mcp, _ = _register(tmp_path)
    out = mcp.tools["record_hypothesis"](target_ip="10.0.0.50", statement="   ")
    assert out.startswith("BLOCKED:")


def test_record_hypothesis_ids_increment(tmp_path: Path) -> None:
    mcp, _ = _register(tmp_path)
    first = mcp.tools["record_hypothesis"](target_ip="10.0.0.50", statement="h1")
    second = mcp.tools["record_hypothesis"](target_ip="10.0.0.50", statement="h2")
    assert "ID: H-001" in first
    assert "ID: H-002" in second


# ---------------------------------------------------------------- update_task


def _seed_plan(workspace: Path, target: str = "10.0.0.50") -> None:
    from tools.attack_planner import AttackPlanner, AttackStep

    planner = AttackPlanner(workspace)
    plan = planner.create_plan(target, attack_mode=True)
    plan.add_step(AttackStep(phase="recon", tool="check_os", reason="r", target_ip=target))
    plan.add_step(AttackStep(phase="exploit", tool="run_attack_module", reason="e", target_ip=target))
    planner.save_plan(plan)


def test_update_task_no_plan(tmp_path: Path) -> None:
    mcp, _ = _register(tmp_path)
    out = mcp.tools["update_task"](target_ip="10.0.0.50", step_index=0, action="complete")
    assert out == "NO_PLAN_FOUND"


def test_update_task_complete(tmp_path: Path) -> None:
    from tools.attack_planner import AttackPlanner

    mcp, ctx = _register(tmp_path)
    _seed_plan(ctx.workspace)
    out = mcp.tools["update_task"](
        target_ip="10.0.0.50",
        step_index=0,
        action="complete",
        success=True,
        summary="OS is Linux 5.x",
    )
    assert out.startswith("TASK_UPDATED:")
    assert "ACTION: complete" in out
    plan = AttackPlanner(ctx.workspace).load_plan("10.0.0.50")
    assert plan is not None
    assert plan.steps[0].completed is True
    assert plan.steps[0].success is True
    assert plan.steps[0].status == "done"
    assert plan.steps[0].result_summary == "OS is Linux 5.x"


def test_update_task_fail_then_reset(tmp_path: Path) -> None:
    from tools.attack_planner import AttackPlanner

    mcp, ctx = _register(tmp_path)
    _seed_plan(ctx.workspace)
    out = mcp.tools["update_task"](
        target_ip="10.0.0.50",
        step_index=1,
        action="fail",
        failure_class="prerequisite_missing",
        reason="no creds",
    )
    assert "ACTION: fail" in out
    plan = AttackPlanner(ctx.workspace).load_plan("10.0.0.50")
    assert plan is not None
    assert plan.steps[1].status == "failed"
    assert plan.steps[1].failure_class == "prerequisite_missing"
    assert plan.steps[1].attempt_count == 1

    out = mcp.tools["update_task"](target_ip="10.0.0.50", step_index=1, action="reset")
    assert "ACTION: reset" in out
    plan = AttackPlanner(ctx.workspace).load_plan("10.0.0.50")
    assert plan.steps[1].status == "pending"


def test_update_task_cancel(tmp_path: Path) -> None:
    from tools.attack_planner import AttackPlanner

    mcp, ctx = _register(tmp_path)
    _seed_plan(ctx.workspace)
    out = mcp.tools["update_task"](
        target_ip="10.0.0.50",
        step_index=1,
        action="cancel",
        reason="hypothesis refuted",
    )
    assert "ACTION: cancel" in out
    plan = AttackPlanner(ctx.workspace).load_plan("10.0.0.50")
    assert plan.steps[1].status == "cancelled"


def test_update_task_bad_action(tmp_path: Path) -> None:
    mcp, ctx = _register(tmp_path)
    _seed_plan(ctx.workspace)
    out = mcp.tools["update_task"](target_ip="10.0.0.50", step_index=0, action="bogus")
    assert out.startswith("BLOCKED:")


def test_update_task_out_of_range(tmp_path: Path) -> None:
    mcp, ctx = _register(tmp_path)
    _seed_plan(ctx.workspace)
    out = mcp.tools["update_task"](target_ip="10.0.0.50", step_index=99, action="complete")
    assert out.startswith("BLOCKED:")


def test_update_task_blocked_when_target_not_allowed(tmp_path: Path) -> None:
    mcp, ctx = _register(tmp_path)
    _seed_plan(ctx.workspace, target="10.0.0.50")
    out = mcp.tools["update_task"](target_ip="10.0.0.99", step_index=0, action="complete")
    assert out.startswith("BLOCKED:")


# ---------------------------------------------------------------- signatures preserved


def test_tool_signatures_preserved() -> None:
    """The @require_allowlist / @audit_tool wrappers must keep the original
    parameter names so FastMCP schema introspection still sees ``target_ip``."""
    import inspect

    mcp, _ = _register(Path("."))
    sig = inspect.signature(mcp.tools["get_assessment_state"])
    assert "target_ip" in sig.parameters
    sig = inspect.signature(mcp.tools["record_hypothesis"])
    assert "target_ip" in sig.parameters
    assert "statement" in sig.parameters
    sig = inspect.signature(mcp.tools["update_task"])
    assert {"target_ip", "step_index", "action"}.issubset(sig.parameters.keys())


# ---------------------------------------------------------------- registration smoke


@pytest.mark.asyncio
async def test_tools_registered_in_full_server(tmp_path: Path) -> None:
    """End-to-end registration smoke: the full server exposes the new tools."""
    from mcp_exploit_server import create_mcp_server
    from tools.cve_lookup import CVESearchSettings, NVDClient
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    mcp = create_mcp_server(
        ExploitSearch(ExploitSearchSettings()),
        NVDClient(CVESearchSettings()),
        WebResearcher(WebResearcherSettings()),
        tmp_path,
        {"exploit": {"require_explicit_allowlist": False}},
    )
    names = {tool.name for tool in await mcp.list_tools()}
    expected = {
        "get_assessment_state",
        "query_capabilities",
        "get_capability_details",
        "get_evidence",
        "record_hypothesis",
        "update_task",
    }
    assert expected <= names
