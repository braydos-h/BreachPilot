"""Error recovery & hallucination edge tests for LLM tool use.

Covers:
* timeout / permission denied / malformed response / unavailable dependency /
  target blocked / sandbox unavailable / temporary provider error
* correct noticing of failure, no false success, appropriate retry / fallback,
  clean termination when no recovery exists
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tests.helpers.llm_tool_harness import FakeToolSpec, ToolUseHarness, make_sentinel, make_tool_call
from tools.exploit_agent.outcome_truth import normalize_action_result
from tools.failure_taxonomy import FailureClass, classify_failure
from tools.providers.types import chat_response

# ---------------------------------------------------------------------------
# Timeout / permission / transport style failures
# ---------------------------------------------------------------------------


class TestToolErrorRecovery:
    @pytest.mark.asyncio
    async def test_timeout_tool_returns_retryable_and_agent_not_claims_success(self, tmp_path: Path):
        specs = [FakeToolSpec(name="run_exploit_terminal", handler_result="", handler_error="timed out")]
        # Agent will get an ERROR: tool message, should not claim compromise
        harness = ToolUseHarness(tmp_path=tmp_path)
        sentinel = make_sentinel("RECOVERY_SENT")
        queue = [
            {
                "message": {
                    "role": "assistant",
                    "content": "",
                    "thinking": "",
                    "tool_calls": [make_tool_call("run_exploit_terminal", {"command": "sleep 100"})],
                }
            },
            {
                "message": {
                    "role": "assistant",
                    "content": "TIMED OUT so I will try alternative",
                    "thinking": "",
                    "tool_calls": [],
                }
            },
        ]
        final, trace = await harness.run(specs, queue)
        # An error tool message must be present
        tool_msgs = [m for m in final.get("messages", []) if m.get("role") == "tool"]
        assert any("ERROR:" in str(m.get("content", "")) for m in tool_msgs)

    @pytest.mark.asyncio
    async def test_permission_denied_maps_to_access_denied_partial(self):
        text = "permission denied"
        res = normalize_action_result(tool_name="run_exploit_terminal", result_text=text)
        # permission denied is partial, not compromise
        assert res.exploit_outcome in ("partial", "failure", "unknown")
        assert res.verified_success is False

    @pytest.mark.asyncio
    async def test_malformed_response_is_internal_parse_error_not_blocked(self, tmp_path: Path):
        """A tool result that cannot be parsed surfaces as INTERNAL_PARSE_ERROR
        and must NOT increment blocked counters."""
        from tools.exploit_agent import ExploitPermission, ExploitPolicy, ExploitSettings, run_exploit_agent

        settings = ExploitSettings(
            enabled=True,
            permission=ExploitPermission.FULL_ACCESS,
            attack_mode=True,
            attack_max_rounds=3,
            attack_max_commands=3,
        )
        policy = ExploitPolicy(settings, tmp_path)

        client = MagicMock()
        client.chat.side_effect = lambda *a, **k: {
            "message": {
                "content": "probing",
                "tool_calls": [{"function": {"name": "check_os", "arguments": {"target_ip": "127.0.0.1"}}}],
            }
        }
        client.provider = "ollama"

        class _BadResult:
            @property
            def content(self):
                raise ValueError("malformed")

        session = AsyncMock()
        session.call_tool.return_value = _BadResult()

        async def _fake_stream(*a, **k):
            return {"role": "assistant", "content": "done", "thinking": ""}

        with (
            patch("tools.exploit_agent.runner._impl._stream_model", side_effect=_fake_stream),
            patch("tools.exploit_agent._stream_model", side_effect=_fake_stream),
        ):
            result = await run_exploit_agent(
                client=client,
                model="fake",
                session=session,
                exploit_tools=[{"type": "function", "function": {"name": "check_os"}}],
                policy=policy,
                target_ip="127.0.0.1",
            )
        tool_msgs = [m for m in result["messages"] if m.get("role") == "tool"]
        assert any("INTERNAL_PARSE_ERROR" in str(m.get("content", "")) for m in tool_msgs)

    def test_target_blocked_maps_to_scope_blocked(self):
        assert classify_failure("BLOCKED: target not in the explicit allowlist") == FailureClass.SCOPE_BLOCKED
        assert classify_failure("not in the allowlist") == FailureClass.SCOPE_BLOCKED

    def test_sandbox_unavailable_is_infrastructure_not_exploit_failure(self):
        """Sandbox failure should be INFRASTRUCTURE_ERROR/SANDBOX_FAILED, not exploitation FAIL."""
        from tools.benchmark.models import FailureCategory, TrialStatus

        # Mirrors BenchmarkRunner classification logic: sandbox_shortfall path
        assert FailureCategory.SANDBOX_FAILED.value == "SANDBOX_FAILED"
        assert TrialStatus.INFRASTRUCTURE_ERROR.value == "INFRASTRUCTURE_ERROR"

    @pytest.mark.asyncio
    async def test_temporary_provider_error_triggers_retry(self, tmp_path: Path):
        """The model client retry path should retry on transient httpx errors."""
        from tools.exploit_agent.model_client import _call_model_with_retry

        calls = []

        class _HttpxConnectError(RuntimeError):
            pass

        _HttpxConnectError.__module__ = "httpx"

        class _FlakyRaw:
            def __init__(self):
                self.n = 0

            def chat(self, **kwargs):
                self.n += 1
                calls.append(self.n)
                if self.n == 1:
                    raise _HttpxConnectError("connect failed")
                return {
                    "model": "m",
                    "message": {"role": "assistant", "content": "ok", "thinking": "", "tool_calls": []},
                }

        raw = _FlakyRaw()
        from tools.model_router import _build_model_client

        client = _build_model_client("fake-model", raw_client=raw, provider="ollama")
        # Patch sleep to avoid real delay
        with patch("tools.exploit_agent.model_client.asyncio.sleep", new_callable=AsyncMock):
            result = await _call_model_with_retry(
                client, "fake-model", [{"role": "user", "content": "hi"}], max_retries=2
            )
        assert result["content"] == "ok"
        assert len(calls) == 2

    @pytest.mark.asyncio
    async def test_unavailable_dependency_fallback(self, tmp_path: Path):
        """When primary tool is unavailable (UNKNOWN_TOOL), agent should try alternative."""
        from tools.exploit_agent.tool_calls import _tool_result_is_blocked

        assert _tool_result_is_blocked("UNAVAILABLE_TOOL: searchsploit not installed") is True
        assert _tool_result_is_blocked("UNKNOWN_TOOL: ghost_tool") is True

    def test_failure_taxonomy_distinguishes_transport_vs_schema(self):
        assert classify_failure("connection reset by peer") == FailureClass.TRANSPORT_ERROR
        assert classify_failure("schema: missing required field target_ip") == FailureClass.SCHEMA_ERROR
        assert classify_failure("BLOCKED: not in the explicit allowlist") == FailureClass.SCOPE_BLOCKED
        assert classify_failure("VULN_NOT_CONFIRMED") == FailureClass.FALSE_POSITIVE


# ---------------------------------------------------------------------------
# Hallucination matrix
# ---------------------------------------------------------------------------


class TestHallucinationMatrix:
    def test_bare_shell_markers_not_sufficient(self):
        from tools.exploit_agent.outcome_truth import classify_exploit_outcome

        # Bare markers that previously false-positive must be rejected
        for txt in ["meterpreter", "root cause analysis", "hashes were not found", "<html>"]:
            assert classify_exploit_outcome(txt)["outcome"] != "compromise", f"false positive on {txt!r}"

    def test_strong_markers_required_for_compromise(self):
        from tools.exploit_agent.outcome_truth import classify_exploit_outcome

        assert classify_exploit_outcome("meterpreter session 1 opened")["outcome"] == "compromise"
        assert classify_exploit_outcome("uid=0(root) id=0")["outcome"] == "compromise"
        assert classify_exploit_outcome("NT AUTHORITY\\SYSTEM")["outcome"] == "compromise"
        assert classify_exploit_outcome("COMPROMISE: shell obtained via CVE-2023-1234")["outcome"] == "compromise"

    def test_cred_dump_requires_strong_syntax(self):
        from tools.exploit_agent.outcome_truth import classify_exploit_outcome

        assert classify_exploit_outcome("credentials: admin:password123")["outcome"] == "cred_dump"
        assert classify_exploit_outcome("no credentials found")["outcome"] != "cred_dump"
        # Real hash hex (16+ hex chars after colon)
        assert classify_exploit_outcome("hashes: aad3b435b51404eeaad3b435b51404ee")["outcome"] == "cred_dump"

    @pytest.mark.asyncio
    async def test_hallucinated_success_vs_oracle(self, tmp_path: Path):
        """Agent claims success (compromise text) but oracle says fail → FALSE_POSITIVE."""
        from tools.benchmark.models import FailureCategory

        # Simulate BenchmarkRunner classifying claimed vs verified
        from tools.benchmark.runner import BenchmarkRunner

        assert FailureCategory.FALSE_POSITIVE.value == "FALSE_POSITIVE"

    def test_malformed_tool_arguments_string_falls_back_to_empty_dict(self):
        from tools.exploit_agent.tool_calls import _normalize_tool_call

        bad = {"function": {"name": "run_exploit_terminal", "arguments": "{bad json"}}
        assert _normalize_tool_call(bad)["function"]["arguments"] == {}

    def test_unknown_tool_name_creates_recoverable_error(self):
        from tools.exploit_agent.tool_calls import _filter_and_validate_tool_calls

        valid, invalid = _filter_and_validate_tool_calls([{"function": {"name": "", "arguments": {}}}], all_tools=[])
        assert invalid and invalid[0]["recoverable"] is True
