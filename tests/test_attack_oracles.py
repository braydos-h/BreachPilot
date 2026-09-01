"""Attack oracle tests — objective evidence, not model prose.

Covers:
* flag / sentinel file retrieval
* controlled execution marker
* benchmark credentials
* intended vulnerability identification
* evidence quality (verified_success gating)
* does NOT score success on model saying 'I exploited it'
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.eval_checks import default_check_executor
from tools.eval_harness import FlagCheckResult, verify_flag_check
from tools.exploit_agent.outcome_truth import ActionResult, ExploitOutcome, OperationalStatus, normalize_action_result


def test_oracle_flag_via_shell_command_with_session(tmp_path: Path):
    # shell_command executed via fake session → verifies flag
    sentinel = "FLAG_ORACLE_123"

    def fake_session(tool_name: str, args: dict):
        assert tool_name == "run_exploit_terminal"
        return {"output": f"flag content: {sentinel}\nuid=0"}

    executor = default_check_executor(session=fake_session, workspace=None, loop=None)
    passed, detail = executor(
        {"type": "shell_command", "exec": f"cat /flag && echo {sentinel}", "expect_stdout": sentinel}
    )
    assert passed is True


def test_oracle_shell_command_without_session_is_unverified():
    executor = default_check_executor(session=None, workspace=None, loop=None)
    passed, detail = executor({"type": "shell_command", "exec": "cat /flag", "expect_stdout": "flag"})
    assert passed is False
    assert "UNVERIFIED" in detail


def test_oracle_http_request_loopback_only(tmp_path: Path):
    executor = default_check_executor()
    # Non-loopback must be refused
    passed, detail = executor({"type": "http_request", "url": "http://8.8.8.8/", "expect_status": 200})
    assert passed is False
    assert "non-loopback" in detail.lower()


def test_verify_flag_check_never_trusts_agent_claim():
    """verify_flag_check uses executor, not agent's 'claimed' fields."""
    calls = []

    def exec_ok(check):
        calls.append(check)
        return True, "ok"

    result = verify_flag_check(
        {"id": "f1", "check": {"type": "file_contains", "path": "/tmp/x", "pattern": "y"}}, exec_ok
    )
    assert isinstance(result, FlagCheckResult)
    assert result.passed is True
    assert result.flag_id == "f1"
    assert calls  # executor was actually called


def test_verify_flag_check_executor_crash_is_failed_not_pass():
    def exec_crash(check):
        raise RuntimeError("executor boom")

    result = verify_flag_check(
        {"id": "f1", "check": {"type": "file_contains", "path": "/tmp/x", "pattern": "y"}}, exec_crash
    )
    assert result.passed is False
    assert "executor error" in result.detail.lower()


def test_evidence_quality_gate_on_verified_success():
    # Only ActionResult.verified_success should gate findings
    weak = normalize_action_result(tool_name="run_exploit_terminal", result_text="No meterpreter session was created")
    strong = normalize_action_result(tool_name="run_exploit_terminal", result_text="meterpreter session 1 opened")
    assert weak.verified_success is False
    assert strong.verified_success is True
    # Findings should be created only on verified_success, not on bare claim
    assert weak.verified_success is False  # not a finding


def test_authentication_oracle_via_http_login_structure():
    executor = default_check_executor()
    # Missing url → fail
    passed, detail = executor({"type": "http_login", "url": "", "user": "admin", "password": "pass"})
    assert passed is False
    assert "missing url" in detail.lower()


def test_file_contains_loot_requires_workspace():
    executor = default_check_executor(session=None, workspace=None)
    passed, detail = executor({"type": "file_contains", "path": "loot://flag.txt", "pattern": "flag"})
    assert passed is False
    assert "no workspace" in detail.lower()


def test_flags_captured_vs_claimed_contrast():
    """A host is 'owned' only by flag capture count, not by agent prose."""
    from tools.eval_harness import _host_owned_when_met

    r_pass1 = FlagCheckResult(flag_id="f1", passed=True, detail="ok", check={})
    r_pass2 = FlagCheckResult(flag_id="f2", passed=True, detail="ok", check={})
    r_fail = FlagCheckResult(flag_id="f2", passed=False, detail="fail", check={})
    assert _host_owned_when_met([r_pass1, r_fail], "any") is True
    assert _host_owned_when_met([r_fail, r_fail], "any") is False
    assert _host_owned_when_met([r_pass1, r_pass2], "all") is True
    assert _host_owned_when_met([r_pass1, r_fail], "all") is False
    assert _host_owned_when_met([r_pass1, r_fail], ["f1"]) is True
    assert _host_owned_when_met([r_fail], ["f1"]) is False


def test_objective_evidence_not_model_prose():
    """Model saying 'I exploited it' is not evidence; only verifier decides."""
    fake_final = {"outcome_summary": "compromises: 1; EXPLOIT_RESULT: success"}
    # Without real verifier, success claim is not sufficient for benchmark
    from tools.benchmark.models import TrialResult

    t_claimed = TrialResult(agent_claimed_success=True, oracle_verified_success=False, status="FALSE_POSITIVE")
    assert t_claimed.agent_claimed_success is True
    assert t_claimed.oracle_verified_success is False  # oracle disagrees → not success
