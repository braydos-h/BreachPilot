"""Tests for ``executor.py`` — the disciplined ExecutorAgent.

Covers ``ExecutionPlan``/``ExecutionResult`` dataclasses, ``_build_args`` for
every tool-family branch (scan/http/cve/smb/ssh/rdp/ldap/dir/terminal/python/msf),
explicit-args passthrough, no-allowed-tools early return, and the
``expected_observation_matched`` heuristic.
"""

from __future__ import annotations

from executor import ExecutionPlan, ExecutionResult, ExecutorAgent
from tool_router import RoutedToolResult

# ── Dataclasses ──────────────────────────────────────────────────────────────


def test_execution_plan_defaults():
    p = ExecutionPlan(task_id="T-1")
    assert p.tool_args == {}
    assert p.risk_level == "low"
    assert p.hypothesis == ""


def test_execution_result_defaults():
    r = ExecutionResult(task_id="T-1")
    assert r.success is False
    assert r.evidence_refs == []
    assert r.scope_gate_passed is False
    assert r.execution_time == 0.0


# ── Fake router ──────────────────────────────────────────────────────────────


class FakeRouter:
    """Mimics ToolRouter.route — returns a configurable RoutedToolResult."""

    def __init__(self, *, allowed=True, output="ok", output_summary="s",
                 evidence_refs=None, blocked_reason=""):
        self._allowed = allowed
        self._output = output
        self._summary = output_summary
        self._evidence = evidence_refs or []
        self._blocked = blocked_reason
        self.calls = []

    def route(self, *, task_id, tool_name, tool_args, target, risk_level,
              action_type, hypothesis):
        self.calls.append({
            "task_id": task_id, "tool_name": tool_name, "tool_args": tool_args,
            "target": target, "risk_level": risk_level, "action_type": action_type,
            "hypothesis": hypothesis,
        })
        return RoutedToolResult(
            allowed=self._allowed,
            output=self._output,
            output_summary=self._summary,
            evidence_refs=self._evidence,
            blocked_reason=self._blocked,
            tool_name=tool_name,
            target=target,
            task_id=task_id,
        )


def _task(**kw):
    base = {
        "task_id": "T-1", "target": "10.0.0.5", "phase": "recon",
        "objective": "Scan the target host", "hypothesis": "vulns exist",
        "allowed_tools": ["nmap_basic"], "risk_level": "low",
    }
    base.update(kw)
    return base


# ── execute: no allowed_tools ────────────────────────────────────────────────


def test_execute_no_allowed_tools_returns_error():
    agent = ExecutorAgent(FakeRouter())
    result = agent.execute({"task_id": "T-1", "target": "10.0.0.5", "phase": "recon"})
    assert result.success is False
    assert "No allowed_tools" in result.error


def test_execute_empty_allowed_tools_returns_error():
    agent = ExecutorAgent(FakeRouter())
    result = agent.execute(_task(allowed_tools=[]))
    assert result.success is False
    assert "No allowed_tools" in result.error


# ── execute: success path ───────────────────────────────────────────────────


def test_execute_success():
    router = FakeRouter(allowed=True, output="22/tcp open ssh", output_summary="scan ok")
    agent = ExecutorAgent(router)
    result = agent.execute(_task(objective="Scan target host ports"))
    assert result.success is True
    assert result.scope_gate_passed is True
    assert result.risk_gate_passed is True
    assert result.tool_name == "nmap_basic"
    assert result.target == "10.0.0.5"
    assert result.output_summary == "scan ok"
    assert result.execution_time >= 0.0


def test_execute_blocked_returns_error():
    router = FakeRouter(allowed=False, blocked_reason="out of scope")
    agent = ExecutorAgent(router)
    result = agent.execute(_task())
    assert result.success is False
    assert result.error == "out of scope"
    assert result.scope_gate_passed is False
    assert result.risk_gate_passed is False


def test_execute_output_contains_error_marks_failure():
    router = FakeRouter(allowed=True, output="ERROR: connection refused")
    agent = ExecutorAgent(router)
    result = agent.execute(_task())
    assert result.success is False  # "error" in first 200 chars of output


def test_execute_empty_output_marks_failure():
    router = FakeRouter(allowed=True, output="")
    agent = ExecutorAgent(router)
    result = agent.execute(_task())
    assert result.success is False


# ── execute: expected_observation_matched heuristic ─────────────────────────


def test_expected_observation_matched_when_keyword_in_output():
    router = FakeRouter(allowed=True, output="scan found open ports on target")
    agent = ExecutorAgent(router)
    result = agent.execute(_task(objective="Scan target host ports"))
    assert result.expected_observation_matched is True


def test_expected_observation_not_matched_when_no_keyword():
    router = FakeRouter(allowed=True, output="completely unrelated output")
    agent = ExecutorAgent(router)
    result = agent.execute(_task(objective="enumerate valid users"))
    assert result.expected_observation_matched is False


def test_expected_observation_matched_when_no_meaningful_keywords():
    # objective with only stopwords -> meaningful empty -> matched True
    router = FakeRouter(allowed=True, output="anything")
    agent = ExecutorAgent(router)
    result = agent.execute(_task(objective="the a an is are on at to for of"))
    assert result.expected_observation_matched is True


def test_expected_observation_not_checked_when_blocked():
    router = FakeRouter(allowed=False, blocked_reason="x")
    agent = ExecutorAgent(router)
    result = agent.execute(_task(objective="scan target"))
    assert result.expected_observation_matched is False


# ── execute: routes through router with correct args ────────────────────────


def test_execute_passes_correct_args_to_router():
    router = FakeRouter()
    agent = ExecutorAgent(router)
    agent.execute(_task(phase="recon", risk_level="medium", hypothesis="h1"))
    assert router.calls[0]["action_type"] == "recon"
    assert router.calls[0]["risk_level"] == "medium"
    assert router.calls[0]["hypothesis"] == "h1"
    assert router.calls[0]["target"] == "10.0.0.5"


# ── _build_args ──────────────────────────────────────────────────────────────


def test_build_args_explicit_args_passthrough():
    args = ExecutorAgent._build_args("any_tool", "10.0.0.5",
                                      {"tool_args": {"custom": "val"}})
    assert args == {"custom": "val"}


def test_build_args_nmap_sets_target_ip():
    args = ExecutorAgent._build_args("nmap_basic", "10.0.0.5", {})
    assert args["target_ip"] == "10.0.0.5"


def test_build_args_scan_sets_target_ip():
    args = ExecutorAgent._build_args("port_scan", "10.0.0.5", {})
    assert args["target_ip"] == "10.0.0.5"


def test_build_args_check_os_sets_target_ip():
    args = ExecutorAgent._build_args("check_os", "10.0.0.5", {})
    assert args["target_ip"] == "10.0.0.5"


def test_build_args_http_sets_target_ip_and_default_port():
    args = ExecutorAgent._build_args("http_request", "10.0.0.5", {})
    assert args["target_ip"] == "10.0.0.5"
    assert args["port"] == 80


def test_build_args_http_preserves_explicit_port():
    args = ExecutorAgent._build_args("http_request", "10.0.0.5", {"tool_args": {"port": 8080}})
    assert args["port"] == 8080


def test_build_args_cve_uses_objective_as_query():
    args = ExecutorAgent._build_args("search_cve", "10.0.0.5",
                                     {"objective": "Identify CVEs in nginx"})
    # "Identify " is stripped, query comes from the cleaned objective
    assert args["query"] == "CVEs in nginx"


def test_build_args_cve_falls_back_to_target_when_objective_short():
    args = ExecutorAgent._build_args("cve_lookup", "10.0.0.5", {"objective": ""})
    assert args["query"] == "10.0.0.5"


def test_build_args_smb_sets_target_ip():
    assert ExecutorAgent._build_args("smb_enum", "10.0.0.5", {})["target_ip"] == "10.0.0.5"


def test_build_args_ssh_sets_target_ip():
    assert ExecutorAgent._build_args("ssh_brute", "10.0.0.5", {})["target_ip"] == "10.0.0.5"


def test_build_args_rdp_sets_target_ip():
    assert ExecutorAgent._build_args("rdp_scan", "10.0.0.5", {})["target_ip"] == "10.0.0.5"


def test_build_args_ldap_sets_target_ip():
    assert ExecutorAgent._build_args("ldap_enum", "10.0.0.5", {})["target_ip"] == "10.0.0.5"


def test_build_args_dir_enum_sets_target_ip_and_port():
    args = ExecutorAgent._build_args("dir_buster", "10.0.0.5", {})
    assert args["target_ip"] == "10.0.0.5"
    assert args["port"] == 80


def test_build_args_terminal_sets_command():
    args = ExecutorAgent._build_args("run_terminal", "10.0.0.5", {})
    assert "command" in args
    assert "10.0.0.5" in args["command"]


def test_build_args_python_file_sets_target_and_optional_filename_code():
    args = ExecutorAgent._build_args("run_python_file", "10.0.0.5",
                                      {"filename": "x.py", "code": "print(1)"})
    assert args["target_ip"] == "10.0.0.5"
    assert args["filename"] == "x.py"
    assert args["code"] == "print(1)"


def test_build_args_python_file_without_optional_fields():
    args = ExecutorAgent._build_args("run_python_file", "10.0.0.5", {})
    assert args["target_ip"] == "10.0.0.5"
    assert "filename" not in args
    assert "code" not in args


def test_build_args_msf_sets_target_and_default_module():
    args = ExecutorAgent._build_args("run_msf_module", "10.0.0.5", {})
    assert args["target_ip"] == "10.0.0.5"
    assert args["module"] == "auxiliary/scanner/portscan/tcp"


def test_build_args_unknown_tool_falls_back_to_target():
    args = ExecutorAgent._build_args("totally_unknown_tool", "10.0.0.5", {})
    # The final fallback sets `target` when nothing else matched and no target_ip
    assert args.get("target") == "10.0.0.5" or args.get("target_ip") == "10.0.0.5"


def test_build_args_task_target_used_when_tool_does_not_expect_target_ip():
    # A tool name that matches no branch but task has 'target' -> target_ip set
    args = ExecutorAgent._build_args("weird_tool", "10.0.0.5", {"target": "10.0.0.99"})
    # The "if target_ip not in args and target in task" branch fires
    assert args.get("target_ip") == "10.0.0.99"


def test_build_args_empty_args_for_no_target_task():
    # tool matches terminal branch which always sets `command` -> args non-empty
    args = ExecutorAgent._build_args("terminal", "10.0.0.5", {})
    assert args  # non-empty due to command


# ── max_retries config ──────────────────────────────────────────────────────


def test_max_retries_default():
    agent = ExecutorAgent(FakeRouter())
    assert agent._max_retries_per_task == 2


def test_max_retries_custom():
    agent = ExecutorAgent(FakeRouter(), max_retries_per_task=5)
    assert agent._max_retries_per_task == 5
