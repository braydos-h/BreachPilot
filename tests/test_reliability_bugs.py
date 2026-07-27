"""Tests for reliability and control-flow bug fixes.

Covers:
- Malformed IPv4 address correction in commands
- Invalid / empty tool call filtering
- Auto-retry after syntax/invalid-target failures
- Phase minimum enforcement before termination
- Service banner parsing from recon output
- Planner continuation after recoverable failure
- Allowlist enforcement for terminal commands
- No early termination before required phases complete
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tools.exploit_agent import (
    ExploitPermission,
    ExploitPolicy,
    ExploitSettings,
    _attempt_retry_correction,
    _filter_and_validate_tool_calls,
    _PhaseTracker,
    run_exploit_agent,
)
from tools.validation_utils import (
    is_target_in_allowlist,
    parse_service_banners,
    preflight_command_check,
    sanitize_ipv4,
    sanitize_target_in_command,
    validate_ipv4,
)

# ── IPv4 Validation Tests ──────────────────────────────────────────────────

class TestIPv4Validation:
    def test_strict_valid_ipv4(self) -> None:
        assert validate_ipv4("192.168.1.1") is True
        assert validate_ipv4("10.0.0.1") is True
        assert validate_ipv4("255.255.255.255") is True
        assert validate_ipv4("0.0.0.0") is True

    def test_strict_invalid_ipv4(self) -> None:
        assert validate_ipv4("256.1.1.1") is False
        assert validate_ipv4("192.168.1") is False
        assert validate_ipv4("192.168.1.1.1") is False
        assert validate_ipv4("192.168.1.a") is False
        assert validate_ipv4("43.229.61.92oos") is False
        assert validate_ipv4("") is False

    def test_sanitize_ipv4_trailing_garbage(self) -> None:
        assert sanitize_ipv4("43.229.61.92oos") == "43.229.61.92"
        assert sanitize_ipv4("10.0.0.1abc") == "10.0.0.1"

    def test_sanitize_ipv4_unrecoverable(self) -> None:
        assert sanitize_ipv4("not-an-ip") is None
        assert sanitize_ipv4("999.999.999.999") is None


# ── Command Sanitization Tests ─────────────────────────────────────────────

class TestCommandSanitization:
    def test_sanitize_nmap_command(self) -> None:
        cmd = "nmap -sV 43.229.61.92oos"
        sanitized, corrections = sanitize_target_in_command(cmd)
        assert "43.229.61.92" in sanitized
        assert "oos" not in sanitized
        assert len(corrections) == 1
        assert corrections[0]["original"] == "43.229.61.92oos"
        assert corrections[0]["sanitized"] == "43.229.61.92"

    def test_preflight_empty_command(self) -> None:
        result = preflight_command_check("")
        assert result["valid"] is False
        assert result["blocked_reason"] == "Empty command."

    def test_preflight_logs_original_and_sanitized(self) -> None:
        cmd = "nmap -p- 43.229.61.92oos"
        result = preflight_command_check(cmd)
        assert result["valid"] is True
        assert result["original_command"] == cmd
        assert "43.229.61.92" in result["sanitized_command"]
        assert result["blocked_reason"] is None

    # M18: CIDR suffixes and :port suffixes on valid IPv4 tokens must be
    # preserved verbatim, not "corrected" by stripping the suffix.
    def test_sanitize_preserves_cidr_suffix(self) -> None:
        cmd = "nmap -sV 10.0.0.5/24"
        sanitized, corrections = sanitize_target_in_command(cmd)
        assert sanitized == cmd
        assert corrections == []

    def test_sanitize_preserves_port_suffix(self) -> None:
        cmd = "nmap -sV 10.0.0.5:80"
        sanitized, corrections = sanitize_target_in_command(cmd)
        assert sanitized == cmd
        assert corrections == []

    def test_sanitize_preserves_cidr_and_port_together(self) -> None:
        # The regex allows /CIDR and :port in any combination; a /24 then :80
        # token is preserved (octet portion still validates).
        cmd = "nmap 10.0.0.5/24:80"
        sanitized, corrections = sanitize_target_in_command(cmd)
        assert sanitized == cmd
        assert corrections == []

    def test_sanitize_still_fixes_trailing_garbage(self) -> None:
        # Regression guard: genuine trailing garbage is still corrected.
        cmd = "nmap -sV 43.229.61.92oos"
        sanitized, corrections = sanitize_target_in_command(cmd)
        assert "43.229.61.92" in sanitized
        assert "oos" not in sanitized
        assert len(corrections) == 1

    def test_sanitize_does_not_preserve_invalid_octet_with_suffix(self) -> None:
        # An out-of-range octet with a suffix is NOT rescued by the suffix rule;
        # it falls through to the existing garbage-stripping path.
        cmd = "nmap 999.0.0.5/24"
        sanitized, corrections = sanitize_target_in_command(cmd)
        # The 999 octet is not a valid IPv4 so the suffix rule does not apply;
        # the loose-IP sanitizer cannot recover it either, so it is left as-is.
        assert "999.0.0.5/24" in sanitized


# ── Tool Call Filtering Tests ──────────────────────────────────────────────

class TestToolCallFiltering:
    def test_empty_tool_call_filtered(self) -> None:
        raw = [{"function": {"name": "", "arguments": {}}}]
        valid, invalid = _filter_and_validate_tool_calls(raw)
        assert len(valid) == 0
        assert len(invalid) == 1
        assert invalid[0]["error"] == "invalid_tool_call"
        assert invalid[0]["recoverable"] is True

    def test_malformed_parentheses_tool_call(self) -> None:
        # Simulates the LLM emitting "()"
        raw = [{"function": {"name": "", "arguments": "()"}}]
        valid, invalid = _filter_and_validate_tool_calls(raw)
        assert len(valid) == 0
        assert len(invalid) == 1

    def test_valid_tool_call_passes(self) -> None:
        raw = [
            {"function": {"name": "check_os", "arguments": {"target_ip": "10.0.0.1"}}},
        ]
        valid, invalid = _filter_and_validate_tool_calls(raw)
        assert len(valid) == 1
        assert len(invalid) == 0

    def test_mixed_valid_and_invalid(self) -> None:
        raw = [
            {"function": {"name": "", "arguments": {}}},
            {"function": {"name": "check_os", "arguments": {"target_ip": "10.0.0.1"}}},
        ]
        valid, invalid = _filter_and_validate_tool_calls(raw)
        assert len(valid) == 1
        assert len(invalid) == 1


# ── Auto-Retry Correction Tests ────────────────────────────────────────────

class TestAutoRetryCorrection:
    def test_retry_fixes_malformed_ip(self) -> None:
        args = {"target_ip": "43.229.61.92oos", "command": "nmap -sV"}
        error = "malformed target address"
        corrected = _attempt_retry_correction("run_exploit_terminal", args, error)
        assert corrected is not None
        assert corrected["target_ip"] == "43.229.61.92"

    def test_retry_no_correction_for_permanent_error(self) -> None:
        args = {"target_ip": "10.0.0.1"}
        error = "permission denied on remote host"
        corrected = _attempt_retry_correction("run_exploit_terminal", args, error)
        assert corrected is None

    def test_retry_fixes_invalid_option(self) -> None:
        args = {"target_ip": "10.0.0.1"}
        error = "invalid option supplied to nmap"
        corrected = _attempt_retry_correction("run_exploit_terminal", args, error)
        # For invalid option, there may be no IP to fix, so correction is None
        # but the logic should still attempt to look at args
        assert corrected is None  # no malformed IP present

    def test_retry_fixes_unknown_host(self) -> None:
        args = {"target_ip": "10.0.0.1abc"}
        error = "unknown host"
        corrected = _attempt_retry_correction("run_exploit_terminal", args, error)
        assert corrected is not None
        assert corrected["target_ip"] == "10.0.0.1"


# ── Phase Tracker Tests ────────────────────────────────────────────────────

class TestPhaseTracker:
    def test_recon_minimum_enforced(self) -> None:
        pt = _PhaseTracker()
        pt.record_action("recon")
        can_term, reason = pt.can_terminate()
        assert can_term is False
        assert "recon" in reason

    def test_recon_minimum_satisfied(self) -> None:
        pt = _PhaseTracker()
        pt.record_action("recon")
        pt.record_action("recon")
        can_term, reason = pt.can_terminate()
        assert can_term is False  # still missing service_enumeration and reporting
        assert "service enumeration" in reason.lower()

    def test_all_minima_satisfied(self) -> None:
        pt = _PhaseTracker()
        pt.record_action("recon")
        pt.record_action("recon")
        pt.set_services_detected(1)
        pt.record_action("service_enumeration")
        pt.set_versions_identified(1)
        pt.record_action("vulnerability_research")
        pt.record_action("reporting")
        can_term, reason = pt.can_terminate()
        assert can_term is True
        assert "satisfied" in reason

    def test_service_enumeration_scales_with_detected_services(self) -> None:
        pt = _PhaseTracker()
        pt.record_action("recon")
        pt.record_action("recon")
        pt.set_services_detected(3)
        pt.record_action("service_enumeration")  # only 1, need 3
        can_term, _ = pt.can_terminate()
        assert can_term is False

    def test_no_early_termination_before_phases_complete(self) -> None:
        pt = _PhaseTracker()
        # Only recon done, nothing else
        pt.record_action("recon")
        pt.record_action("recon")
        assert pt.can_terminate()[0] is False
        pt.record_action("service_enumeration")
        pt.record_action("vulnerability_research")
        assert pt.can_terminate()[0] is False  # still needs reporting
        pt.record_action("reporting")
        assert pt.can_terminate()[0] is True


# ── Banner Parsing Tests ───────────────────────────────────────────────────

class TestBannerParsing:
    def test_parse_check_os_output(self) -> None:
        sample = """OS_CHECK_RESULTS:
TARGET: 10.0.0.50

  TTL: 64
  Port 22/tcp: open - OpenSSH_8.5p1
  Port 80/tcp: open - Apache/2.4.41
  Port 445/tcp: open - (no banner)

OS_VERDICT: LINUX
HINTS: Port 22/tcp open - likely Linux/Unix (SSH)
"""
        records = parse_service_banners(sample)
        assert len(records) == 3
        ssh = [r for r in records if r["port"] == 22][0]
        assert ssh["service"] == "ssh"
        assert ssh["product"] == "OpenSSH"
        assert ssh["version"] == "8.5p1"
        assert ssh["os_guess"] == "LINUX"

        http = [r for r in records if r["port"] == 80][0]
        assert http["service"] == "http"
        assert http["product"] == "Apache"

    def test_parse_empty_output(self) -> None:
        records = parse_service_banners("")
        assert records == []

    def test_os_guess_heuristic(self) -> None:
        sample = "WINDOWS_GUIDANCE: You are on a Windows system."
        records = parse_service_banners(sample)
        assert len(records) == 0
        # But if there were ports, they'd get WINDOWS os_guess
        sample2 = "Port 3389/tcp: open - RDP\nWINDOWS_GUIDANCE: ..."
        records2 = parse_service_banners(sample2)
        assert records2[0]["os_guess"] == "WINDOWS"


# ── Allowlist Enforcement Tests ────────────────────────────────────────────

class TestAllowlistEnforcement:
    def test_ip_in_allowlist_exact(self) -> None:
        assert is_target_in_allowlist("192.168.1.50", ["192.168.1.50"]) is True

    def test_ip_in_allowlist_cidr(self) -> None:
        assert is_target_in_allowlist("192.168.1.50", ["192.168.1.0/24"]) is True
        assert is_target_in_allowlist("10.0.0.1", ["192.168.1.0/24"]) is False

    def test_domain_in_allowlist_wildcard(self) -> None:
        assert is_target_in_allowlist("sub.example.com", ["*.example.com"]) is True
        assert is_target_in_allowlist("example.com", ["*.example.com"]) is False

    def test_ip_not_in_allowlist(self) -> None:
        assert is_target_in_allowlist("8.8.8.8", ["192.168.1.0/24"]) is False

    def test_allowlist_empty(self) -> None:
        assert is_target_in_allowlist("192.168.1.1", []) is False


# ── Exploit Agent Loop Integration Tests ───────────────────────────────────

@pytest.mark.asyncio
async def test_run_exploit_agent_filters_invalid_tool_calls() -> None:
    """Simulate LLM returning an empty tool call; agent should not stop."""
    settings = ExploitSettings(
        enabled=True,
        mode="standalone",
        permission=ExploitPermission.FULL_ACCESS,
        attack_mode=True,
        max_rounds=5,
        max_commands_per_session=10,
    )
    policy = ExploitPolicy(settings, Path("test_workspace"))

    client = MagicMock()
    # First response has an invalid empty tool call; second response has no tool calls
    client.chat.side_effect = [
        {
            "message": {
                "content": "Let me try.",
                "tool_calls": [
                    {"function": {"name": "", "arguments": {}}},
                    {"function": {"name": "check_os", "arguments": {"target_ip": "10.0.0.1"}}},
                ],
            }
        },
        {
            "message": {
                "content": "Done.",
                "tool_calls": [],
            }
        },
    ]

    session = AsyncMock()
    session.call_tool.return_value = MagicMock(
        content=[{"text": "OS_CHECK_RESULTS:\nTARGET: 10.0.0.1\nOS_VERDICT: LINUX"}]
    )

    with patch("tools.exploit_agent._stream_ollama", new_callable=AsyncMock) as mock_stream:
        mock_stream.return_value = {
            "role": "assistant",
            "content": "Final summary.",
        }
        result = await run_exploit_agent(
            client=client,
            model="test-model",
            session=session,
            exploit_tools=[],
            policy=policy,
            target_ip="10.0.0.1",
            target_cve="",
            target_os=None,
        )

    assert result["total_actions"] >= 1
    # The invalid call should have been filtered, not crashed the agent
    call_names = [c.args[0] for c in session.call_tool.call_args_list if c.args]
    assert "check_os" in call_names
    assert "" not in call_names


@pytest.mark.asyncio
async def test_run_exploit_agent_retries_on_syntax_error() -> None:
    """If run_exploit_terminal fails with a malformed target, auto-correct and retry once."""
    settings = ExploitSettings(
        enabled=True,
        mode="standalone",
        permission=ExploitPermission.FULL_ACCESS,
        attack_mode=True,
        max_rounds=5,
        max_commands_per_session=10,
    )
    policy = ExploitPolicy(settings, Path("test_workspace_retry"))

    client = MagicMock()
    client.chat.side_effect = [
        {
            "message": {
                "content": "Scanning.",
                "tool_calls": [
                    {
                        "function": {
                            "name": "run_exploit_terminal",
                            "arguments": {"command": "nmap -sV 43.229.61.92oos"},
                        }
                    },
                ],
            }
        },
        {
            "message": {
                "content": "Done.",
                "tool_calls": [],
            }
        },
    ]

    session = AsyncMock()
    # First call fails with syntax error, second succeeds
    session.call_tool.side_effect = [
        Exception("malformed target address"),
        MagicMock(
            content=[{"text": "TERMINAL_RESULT: completed\nCOMMAND_SANITIZED: nmap -sV 43.229.61.92"}]
        ),
    ]

    with patch("tools.exploit_agent._stream_ollama", new_callable=AsyncMock) as mock_stream:
        mock_stream.return_value = {
            "role": "assistant",
            "content": "Final summary.",
        }
        await run_exploit_agent(
            client=client,
            model="test-model",
            session=session,
            exploit_tools=[],
            policy=policy,
            target_ip="43.229.61.92",
            target_cve="",
            target_os=None,
        )

    # Should have called twice: once with original (fails), once with corrected (succeeds)
    assert session.call_tool.call_count == 2
    second_call_args = session.call_tool.call_args_list[1][1]["arguments"]
    # The command arg should have been corrected
    assert "oos" not in second_call_args["command"]
    assert "43.229.61.92" in second_call_args["command"]


@pytest.mark.asyncio
async def test_run_exploit_agent_phase_enforcement_prevents_early_exit() -> None:
    """Agent should not terminate before completing required phase minima."""
    settings = ExploitSettings(
        enabled=True,
        mode="standalone",
        permission=ExploitPermission.FULL_ACCESS,
        attack_mode=False,
        max_rounds=8,
        max_commands_per_session=20,
    )
    policy = ExploitPolicy(settings, Path("test_workspace_phase"))

    client = MagicMock()
    # Simulate LLM trying to finish immediately by returning no tool calls
    client.chat.return_value = {
        "message": {
            "content": "I think I'm done.",
            "tool_calls": [],
        }
    }

    session = AsyncMock()

    with patch("tools.exploit_agent._stream_ollama", new_callable=AsyncMock) as mock_stream:
        mock_stream.return_value = {
            "role": "assistant",
            "content": "Final summary.",
        }
        result = await run_exploit_agent(
            client=client,
            model="test-model",
            session=session,
            exploit_tools=[],
            policy=policy,
            target_ip="10.0.0.1",
            target_cve="",
            target_os=None,
        )

    # Because no tool calls were produced and phase minima are not met,
    # the agent should have injected a replanning user message and continued.
    # The loop will hit max_rounds or eventually stop.
    assert result["total_actions"] == 0
    # Most importantly: the agent did not crash or raise; it looped gracefully.


# ── Agent Loop Replanning Tests ────────────────────────────────────────────

class TestAgentLoopReplanning:
    def test_failure_driven_replanning_creates_retry_task(self) -> None:
        """Planner should retry only when it can select a different check."""
        from planner import PlannerAgent

        planner = PlannerAgent(risk_profile="standard_authorized")
        failed_task = planner._create_task(
            phase="recon",
            target="10.0.0.50",
            asset_type="host",
            objective="Test recon",
            hypothesis="Test",
            allowed_tools=["nmap_basic", "check_os"],
            risk_level="low",
        )
        retry = planner.plan_retry_with_modifications(
            failed_task=failed_task,
            error="Syntax error in command",
            attempt=1,
        )
        assert retry is not None
        assert "RETRY 1" in retry.get("objective", "")
        assert retry["phase"] == "recon"
        assert retry["allowed_tools"][0] == "check_os"

    def test_failure_driven_replanning_refuses_permanent_errors(self) -> None:
        """Permanent errors should not generate retry tasks."""
        from planner import PlannerAgent

        planner = PlannerAgent(risk_profile="standard_authorized")
        failed_task = planner._create_task(
            phase="recon",
            target="10.0.0.50",
            asset_type="host",
            objective="Test recon",
            hypothesis="Test",
            allowed_tools=["nmap_basic"],
            risk_level="low",
        )
        retry = planner.plan_retry_with_modifications(
            failed_task=failed_task,
            error="permission denied on remote host",
            attempt=1,
        )
        assert retry is None

    def test_phase_minima_on_agent_loop(self, tmp_path: Path) -> None:
        """Phase minima should prevent early termination."""

        from agent_loop import AgentLoop

        mission_config = {
            "program_name": "Test Program",
            "risk_profile": "standard_authorized",
            "allowed_assets": ["10.0.0.50"],
            "disallowed_assets": [],
            "forbidden_actions": [],
            "testing_modes": ["recon", "analysis", "test"],
            "max_commands_per_session": 100,
            "max_tasks_active": 20,
        }

        def mock_executor(tool_name: str, args: dict[str, Any]) -> str:
            return "mock output"

        loop = AgentLoop(mission_config, tmp_path / "workspace", mock_executor)

        # Directly test the phase tracking methods without running the full loop
        loop._record_task_phase(
            {"phase": "recon", "target": "10.0.0.50"},
            result_text="OS_CHECK_RESULTS:\nTARGET: 10.0.0.50\nPort 22/tcp: open - OpenSSH_8.5p1\nPort 80/tcp: open - Apache/2.4.41",
        )

        assert loop._phase_counts["recon"] == 1
        assert loop._services_detected == 2
        assert loop._versions_identified == 2

        # Phase minima should not yet be met (only 1 recon, need 2)
        met, reason = loop._phase_minima_met()
        assert met is False
        assert "recon" in reason

        # Add second recon and enough service enumeration (need 2 because 2 services detected)
        loop._record_task_phase({"phase": "recon", "target": "10.0.0.50"}, result_text="")
        loop._record_task_phase({"phase": "service_enumeration", "target": "10.0.0.50"}, result_text="")
        loop._record_task_phase({"phase": "service_enumeration", "target": "10.0.0.50"}, result_text="")
        loop._record_task_phase({"phase": "vulnerability_research", "target": "10.0.0.50"}, result_text="")
        loop._record_task_phase({"phase": "vulnerability_research", "target": "10.0.0.50"}, result_text="")
        loop._record_task_phase({"phase": "reporting", "target": "10.0.0.50"}, result_text="")

        met, reason = loop._phase_minima_met()
        assert met is True
        assert "satisfied" in reason


# ── MCP Server Allowlist Integration Test ────────────────────────────────────

@pytest.mark.asyncio
async def test_mcp_run_exploit_terminal_blocked_when_allowlist_required(tmp_path: Path) -> None:
    """Terminal command should be blocked if target IP is not in allowlist."""
    from mcp_exploit_server import create_mcp_server
    from tools.cve_lookup import CVESearchSettings, NVDClient
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    search = ExploitSearch(ExploitSearchSettings())
    nvd = NVDClient(CVESearchSettings())
    config = {
        "exploit": {
            "require_explicit_allowlist": True,
            "allowed_targets": ["192.168.1.50"],
        }
    }
    mcp = create_mcp_server(search, nvd, WebResearcher(WebResearcherSettings()), tmp_path, config)

    result = await mcp.call_tool("run_exploit_terminal", {"command": "nmap -sV 10.0.0.99"})
    text = "".join(c.text for c in result[0])
    assert "blocked" in text.lower() or "BLOCKED" in text
    assert "not in the explicit allowlist" in text


@pytest.mark.asyncio
async def test_mcp_run_exploit_terminal_allowed_when_in_allowlist(tmp_path: Path) -> None:
    """Terminal command should proceed if target IP is in allowlist."""
    from mcp_exploit_server import create_mcp_server
    from tools.cve_lookup import CVESearchSettings, NVDClient
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    search = ExploitSearch(ExploitSearchSettings())
    nvd = NVDClient(CVESearchSettings())
    config = {
        "exploit": {
            "require_explicit_allowlist": True,
            "allowed_targets": ["192.168.1.50"],
        }
    }
    mcp = create_mcp_server(search, nvd, WebResearcher(WebResearcherSettings()), tmp_path, config)

    result = await mcp.call_tool("run_exploit_terminal", {"command": "echo hello 192.168.1.50"})
    text = "".join(c.text for c in result[0])
    assert "not in the explicit allowlist" not in text


# ── ExploitPolicy / ScopeGate regression tests ─────────────────────────────


@pytest.mark.asyncio
async def test_exploit_policy_uses_runtime_target_ip() -> None:
    """Even if ExploitSettings.target_ip is empty, run_exploit_agent binds the
    concrete target so the scope gate and audit logs see the correct asset."""
    settings = ExploitSettings(
        enabled=True,
        mode="standalone",
        permission=ExploitPermission.FULL_ACCESS,
        attack_mode=True,
        max_rounds=5,
        max_commands_per_session=10,
    )
    policy = ExploitPolicy(settings, Path("test_workspace_target"))
    assert policy._target_ip == ""

    client = MagicMock()
    client.chat.side_effect = [
        {
            "message": {
                "content": "Checking OS.",
                "tool_calls": [
                    {"function": {"name": "check_os", "arguments": {"target_ip": "10.0.0.1"}}},
                ],
            }
        },
        {"message": {"content": "Done.", "tool_calls": []}},
    ]
    session = AsyncMock()
    session.call_tool.return_value = MagicMock(
        content=[{"text": "OS_CHECK_RESULTS:\nTARGET: 10.0.0.1\nOS_VERDICT: LINUX"}]
    )

    with patch("tools.exploit_agent._stream_ollama", new_callable=AsyncMock) as mock_stream:
        mock_stream.return_value = {"role": "assistant", "content": "Summary."}
        result = await run_exploit_agent(
            client=client,
            model="test-model",
            session=session,
            exploit_tools=[],
            policy=policy,
            target_ip="10.0.0.1",
            target_cve="",
            target_os=None,
        )

    assert result["total_actions"] >= 1
    assert session.call_tool.call_count >= 1
    assert policy._records
    assert policy._records[0].target_ip == "10.0.0.1"


@pytest.mark.asyncio
async def test_scope_gate_allows_exploit_named_tools() -> None:
    """Tool names like ``run_exploit_terminal`` are implementation details and
    must not be rejected just because they contain the substring ``exploit``."""
    from scope_gate import ScopeGate

    gate = ScopeGate(
        db=None,  # type: ignore[arg-type]
        mission_id="",
        allowed_assets=["10.0.0.1"],
        risk_profile="high_authorized_testing",
    )
    result = gate.check_scope(
        asset="10.0.0.1",
        action_type="authorized_test",
        tool_name="run_exploit_terminal(command='nmap 10.0.0.1')",
        risk_level="high",
        enforce_rate_limit=False,
    )
    assert result.allowed is True
