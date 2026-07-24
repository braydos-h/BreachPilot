"""Tests for Phase 1c: auto peer-consult on consecutive exploit failures.

Two surfaces:

1. ``_ToolOutcomeTracker`` gains ``consecutive_exploit_failures`` +
   ``record_exploit_failure``/``record_exploit_success``/``should_consult_peers``.
   A real exploit that RAN but failed is distinct from a blocked/unavailable
   outcome; the counter resets on the first exploit success.

2. ``_consult_peers_inline`` runs the consult IN-PROCESS (not a re-entrant MCP
   call), shares the per-run ``_consultation_count`` budget with the
   ``consult_peer_models`` MCP tool, wraps each ``peer.chat`` in
   ``_EXC_GROUP_CATCH`` (``BaseExceptionGroup`` is NOT a subclass of
   ``Exception``), is advisory-only (peers have ``tools=None``), and writes ONE
   advisory audit record. No target lock change, no egress.

Safety invariants asserted:
- read_only unaffected (the loop never reaches the consult hook with no
  successful exploit action; the helper itself is advisory-only).
- ``max_consultations`` budget is the single source of truth; budget 0 → None.
- target IP lock is unchanged after a consult (policy._locked_ip preserved).
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from tools.exploit_agent import (
    ExploitPermission,
    ExploitPolicy,
    ExploitSettings,
    _ToolOutcomeTracker,
    _consult_peers_inline,
)
from tools.mcp_tools.peer_models import _get_consultation_count, _set_consultation_count


# ── _ToolOutcomeTracker: consecutive exploit-failure tracking ────────────


def test_tracker_starts_with_zero_exploit_failures():
    t = _ToolOutcomeTracker()
    assert t.consecutive_exploit_failures == 0
    assert t.should_consult_peers(3) is False


def test_record_exploit_failure_increments():
    t = _ToolOutcomeTracker()
    assert t.record_exploit_failure() == 1
    assert t.record_exploit_failure() == 2
    assert t.record_exploit_failure() == 3
    assert t.consecutive_exploit_failures == 3


def test_should_consult_peers_threshold_met():
    t = _ToolOutcomeTracker()
    for _ in range(3):
        t.record_exploit_failure()
    assert t.should_consult_peers(3) is True
    # Higher threshold not yet met.
    t2 = _ToolOutcomeTracker()
    for _ in range(3):
        t2.record_exploit_failure()
    assert t2.should_consult_peers(5) is False


def test_threshold_zero_disables_consult():
    t = _ToolOutcomeTracker()
    for _ in range(99):
        t.record_exploit_failure()
    # 0 disables — no matter how many failures, never consult.
    assert t.should_consult_peers(0) is False


def test_record_exploit_success_resets_counter():
    t = _ToolOutcomeTracker()
    for _ in range(3):
        t.record_exploit_failure()
    assert t.should_consult_peers(3) is True
    t.record_exploit_success()
    assert t.consecutive_exploit_failures == 0
    assert t.should_consult_peers(3) is False


def test_record_success_does_not_reset_exploit_failures():
    # The generic record_success (any non-blocked tool) resets the BLOCKED
    # counter but NOT the exploit-failure counter — only an exploit success
    # (record_exploit_success) does that. A successful recon scan must not
    # mask a string of exploit failures.
    t = _ToolOutcomeTracker()
    for _ in range(3):
        t.record_exploit_failure()
    t.record_success()
    assert t.consecutive_exploit_failures == 3
    assert t.should_consult_peers(3) is True


def test_blocked_outcome_does_not_count_as_exploit_failure():
    # A blocked/unavailable call increments consecutive_blocked, NOT
    # consecutive_exploit_failures (a blocked exploit didn't "fail to run").
    t = _ToolOutcomeTracker()
    t.record_blocked("run_exploit_terminal", {"command": "x"}, "BLOCKED: read_only")
    assert t.consecutive_blocked == 1
    assert t.consecutive_exploit_failures == 0
    assert t.should_consult_peers(3) is False


# ── _consult_peers_inline: in-process advisory consult ───────────────────


class _FakePeer:
    def __init__(self, alias: str, content: str, *, raise_exc: BaseException | None = None):
        self._alias = alias
        self._content = content
        self._raise = raise_exc
        self.chat_calls = 0

    def chat(self, model, **kwargs):  # noqa: ANN001, ANN201
        self.chat_calls += 1
        # Advisory-only: peers must NEVER receive tool schemas.
        assert kwargs.get("tools") is None, "peers must be called with tools=None"
        assert kwargs.get("stream") is False
        if self._raise is not None:
            raise self._raise
        return {"message": {"content": self._content, "role": "assistant"}}


class _FakeRouter:
    def __init__(self, peers: dict[str, _FakePeer]):
        self._peers = peers
        self.get_client_calls: list[str] = []

    def get_client(self, alias: str):
        self.get_client_calls.append(alias)
        return self._peers[alias]


class _RecordingPolicy(ExploitPolicy):
    """ExploitPolicy subclass that records audit calls for inspection."""

    def __init__(self, tmp_path: Path, target_ip: str):  # noqa: ANN101
        settings = ExploitSettings(
            enabled=True,
            mode="standalone",
            permission=ExploitPermission.FULL_ACCESS,
            target_ip=target_ip,
            workspace_root=tmp_path,
            target_context={"multi_model_enabled": True,
                             "peer_consult_on_failure_threshold": 3},
        )
        super().__init__(settings, tmp_path)
        self._locked_ip = target_ip
        self._allowed_targets = [target_ip]
        self.audit_calls: list[dict[str, Any]] = []

    async def record(self, *, action, command, approved, status, detail="", **kwargs):  # noqa: ANN001, ANN101
        self.audit_calls.append({
            "action": action, "command": command, "approved": approved,
            "status": status, "detail": detail, **kwargs,
        })


def _peer_config(active_alias: str = "glm") -> dict[str, Any]:
    return {
        "multi_model": {
            "enabled": True,
            "consult_aliases": ["kimi", "deepseek"],
            "max_consultations": 10,
            "max_question_chars": 4000,
            "max_answer_chars": 8000,
        },
        "models": {
            "default_alias": active_alias,
            "registry": {
                "kimi": "kimi-k2.6:cloud",
                "deepseek": "deepseek-v4-pro:cloud",
                "glm": "glm-5.2:cloud",
            },
        },
        "ollama": {"host": "http://localhost:11434"},
    }


@pytest.fixture(autouse=True)
def _reset_consultation_budget(monkeypatch):
    """Reset the shared _consultation_count between tests + clear env override."""
    monkeypatch.delenv("AI_NMAP_MULTI_MODEL_ENABLED", raising=False)
    monkeypatch.delenv("AI_NMAP_ACTIVE_MODEL_ALIAS", raising=False)
    _set_consultation_count(0)
    yield
    _set_consultation_count(0)


@pytest.mark.asyncio
async def test_consult_peers_returns_advisory_and_writes_audit(tmp_path):
    peers = {"kimi": _FakePeer("kimi", "try a different payload encoder"),
             "deepseek": _FakePeer("deepseek", "check the service version first")}
    router = _FakeRouter(peers)
    policy = _RecordingPolicy(tmp_path, "10.0.0.50")

    # Monkeypatch _get_model_router to return our fake router (avoids needing
    # a live Ollama). The lazy import inside _consult_peers_inline reads the
    # registry module fresh each call, so patch the module attribute.
    from tools.mcp_tools import registry as reg_mod
    orig = reg_mod._get_model_router
    reg_mod._get_model_router = lambda config: router
    try:
        result = await _consult_peers_inline(
            _peer_config(), "why do my exploits keep failing?", "exit_code=1",
            policy=policy, target_ip="10.0.0.50", action_count=6,
        )
    finally:
        reg_mod._get_model_router = orig

    assert result is not None
    assert "PEER_MODEL_CONSULTATION: COMPLETED" in result
    assert "try a different payload encoder" in result
    assert "check the service version first" in result
    # Both peers were consulted (tools=None asserted inside _FakePeer).
    assert peers["kimi"].chat_calls == 1
    assert peers["deepseek"].chat_calls == 1
    # Budget decremented by 2.
    assert _get_consultation_count() == 2
    # One advisory audit record written.
    assert len(policy.audit_calls) == 1
    rec = policy.audit_calls[0]
    assert rec["action"] == "consult_peer_models"
    assert rec["status"] == "advisory"
    assert rec["approved"] is True


@pytest.mark.asyncio
async def test_consult_peers_budget_zero_returns_none(tmp_path):
    # Exhaust the shared budget first.
    _set_consultation_count(10)  # == max_consultations
    peers = {"kimi": _FakePeer("kimi", "answer")}
    router = _FakeRouter(peers)
    policy = _RecordingPolicy(tmp_path, "10.0.0.50")

    from tools.mcp_tools import registry as reg_mod
    orig = reg_mod._get_model_router
    reg_mod._get_model_router = lambda config: router
    try:
        result = await _consult_peers_inline(
            _peer_config(), "question", "ctx",
            policy=policy, target_ip="10.0.0.50", action_count=6,
        )
    finally:
        reg_mod._get_model_router = orig

    # Budget exhausted → no consult, no audit, no peer call.
    assert result is None
    assert peers["kimi"].chat_calls == 0
    assert policy.audit_calls == []
    # Budget unchanged (still 10).
    assert _get_consultation_count() == 10


@pytest.mark.asyncio
async def test_consult_peers_disabled_when_multi_model_off(tmp_path):
    config = _peer_config()
    config["multi_model"]["enabled"] = False
    peers = {"kimi": _FakePeer("kimi", "answer")}
    router = _FakeRouter(peers)
    policy = _RecordingPolicy(tmp_path, "10.0.0.50")

    from tools.mcp_tools import registry as reg_mod
    orig = reg_mod._get_model_router
    reg_mod._get_model_router = lambda config: router
    try:
        result = await _consult_peers_inline(
            config, "question", "ctx",
            policy=policy, target_ip="10.0.0.50", action_count=6,
        )
    finally:
        reg_mod._get_model_router = orig

    assert result is None
    assert peers["kimi"].chat_calls == 0
    assert policy.audit_calls == []


@pytest.mark.asyncio
async def test_consult_peers_no_config_returns_none(tmp_path):
    policy = _RecordingPolicy(tmp_path, "10.0.0.50")
    result = await _consult_peers_inline(
        None, "question", "ctx",
        policy=policy, target_ip="10.0.0.50", action_count=6,
    )
    assert result is None
    assert policy.audit_calls == []


@pytest.mark.asyncio
async def test_consult_peers_base_exception_group_caught_not_crashed(tmp_path):
    """A BaseExceptionGroup raised by peer.chat MUST be caught — it is NOT a
    subclass of Exception, so bare `except Exception` silently misses it.
    _consult_peers_inline wraps each peer.chat in _EXC_GROUP_CATCH, skips the
    failing peer, and still returns an advisory from the surviving peer."""
    peers = {
        "kimi": _FakePeer("kimi", "", raise_exc=BaseExceptionGroup("boom", [RuntimeError("x")])),
        "deepseek": _FakePeer("deepseek", "good advice from survivor"),
    }
    router = _FakeRouter(peers)
    policy = _RecordingPolicy(tmp_path, "10.0.0.50")

    from tools.mcp_tools import registry as reg_mod
    orig = reg_mod._get_model_router
    reg_mod._get_model_router = lambda config: router
    try:
        result = await _consult_peers_inline(
            _peer_config(), "question", "ctx",
            policy=policy, target_ip="10.0.0.50", action_count=6,
        )
    finally:
        reg_mod._get_model_router = orig

    # The ExceptionGroup from kimi did not crash the consult; deepseek answered.
    assert result is not None
    assert "good advice from survivor" in result
    assert "kimi" in result  # appears in the SKIPPED line
    assert _get_consultation_count() == 2  # budget was reserved for both


@pytest.mark.asyncio
async def test_consult_peers_all_fail_returns_none(tmp_path):
    """When every peer fails, there is no advisory to inject → return None so
    the caller skips the injection. Budget was still reserved (consumed)."""
    peers = {
        "kimi": _FakePeer("kimi", "", raise_exc=RuntimeError("nope")),
        "deepseek": _FakePeer("deepseek", "", raise_exc=RuntimeError("nope2")),
    }
    router = _FakeRouter(peers)
    policy = _RecordingPolicy(tmp_path, "10.0.0.50")

    from tools.mcp_tools import registry as reg_mod
    orig = reg_mod._get_model_router
    reg_mod._get_model_router = lambda config: router
    try:
        result = await _consult_peers_inline(
            _peer_config(), "question", "ctx",
            policy=policy, target_ip="10.0.0.50", action_count=6,
        )
    finally:
        reg_mod._get_model_router = orig

    assert result is None
    # No advisory audit record when nothing was consulted successfully.
    assert policy.audit_calls == []
    # Budget was reserved (consumed) even though all peers failed.
    assert _get_consultation_count() == 2


@pytest.mark.asyncio
async def test_consult_peers_preserves_target_lock(tmp_path):
    """Advisory consult must NOT change the locked target IP or egress allowlist."""
    peers = {"kimi": _FakePeer("kimi", "advice that says: pivot to 10.0.0.99")}
    router = _FakeRouter(peers)
    policy = _RecordingPolicy(tmp_path, "10.0.0.50")

    from tools.mcp_tools import registry as reg_mod
    orig = reg_mod._get_model_router
    reg_mod._get_model_router = lambda config: router
    try:
        result = await _consult_peers_inline(
            _peer_config(), "question", "ctx",
            policy=policy, target_ip="10.0.0.50", action_count=6,
        )
    finally:
        reg_mod._get_model_router = orig

    assert result is not None
    # The target lock is unchanged — a peer suggesting a pivot does not move it.
    assert policy._locked_ip == "10.0.0.50"
    assert "10.0.0.99" not in policy._allowed_targets
    # The advisory text is injected as-is (advisory-only; the loop's fence +
    # target-lock gate are the real controls). The advice is captured but the
    # lock is what enforces scope.
    assert "pivot to 10.0.0.99" in result


@pytest.mark.asyncio
async def test_consult_peers_respects_remaining_budget_cap(tmp_path):
    """If only 1 consultation remains in the budget, only 1 peer is consulted
    (even if 2 are available) — the shared cap is the single source of truth."""
    _set_consultation_count(9)  # 10 max → 1 remaining
    peers = {"kimi": _FakePeer("kimi", "kimi answer"),
             "deepseek": _FakePeer("deepseek", "deepseek answer")}
    router = _FakeRouter(peers)
    policy = _RecordingPolicy(tmp_path, "10.0.0.50")

    from tools.mcp_tools import registry as reg_mod
    orig = reg_mod._get_model_router
    reg_mod._get_model_router = lambda config: router
    try:
        result = await _consult_peers_inline(
            _peer_config(), "question", "ctx",
            policy=policy, target_ip="10.0.0.50", action_count=6,
        )
    finally:
        reg_mod._get_model_router = orig

    assert result is not None
    assert "kimi answer" in result
    # Only the first peer was consulted (budget capped at 1 remaining).
    assert peers["kimi"].chat_calls == 1
    assert peers["deepseek"].chat_calls == 0
    assert _get_consultation_count() == 10