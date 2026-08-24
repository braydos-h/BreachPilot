"""Tests for ToolRouter human-approval gating (C2 regression).

C2: when a high-risk action requires human approval but no approval handler
is configured (``human_approval_fn is None``), the router must block the
action rather than silently fall through to execution.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from tool_router import ToolRouter

# ── Lightweight stubs ──────────────────────────────────────────────────────
# We avoid importing the real ScopeGate/RiskController/EvidenceStore/Database
# (which pull in Ollama and other heavy deps) by supplying minimal doubles that
# implement only the surface the router touches.


@dataclass
class _ScopeResult:
    allowed: bool = True
    reason: str = ""
    matched_scope_rule: str = "allow-default"
    risk_level: str = "low"
    requires_human_approval: bool = False
    is_third_party: bool = False
    rate_limit_remaining: int | None = None


@dataclass
class _RiskResult:
    allowed: bool = True
    reason: str = ""
    risk_level: str = "low"
    warnings: list[str] = field(default_factory=list)
    requires_human_approval: bool = False


class _StubScopeGate:
    """Minimal ScopeGate double."""

    def __init__(self, *, requires_human_approval: bool = False) -> None:
        self._requires_human = requires_human_approval

    def check_scope(self, **kwargs: Any) -> _ScopeResult:
        return _ScopeResult(
            allowed=True,
            requires_human_approval=self._requires_human,
        )


class _StubRiskController:
    """Minimal RiskController double."""

    def __init__(self, *, requires_human_approval: bool = False) -> None:
        self._requires_human = requires_human_approval

    def assess_action(self, **kwargs: Any) -> _RiskResult:
        return _RiskResult(
            allowed=True,
            risk_level="high",
            warnings=["high-risk action"],
            requires_human_approval=self._requires_human,
        )

    def record_execution(self) -> None:
        pass


class _StubEvidenceStore:
    """EvidenceStore double — save() returns a synthetic evidence id."""

    def save(self, **kwargs: Any) -> str:
        return "E-0001"


class _StubDB:
    """DatabaseManager double — records audit calls in-memory."""

    def __init__(self) -> None:
        self.audit_entries: list[tuple[str, str, str, str]] = []

    class _Conn:
        def __enter__(self) -> "_Conn":  # noqa: F821
            return self

        def __exit__(self, *exc: Any) -> None:
            pass

    def connection(self, *, write: bool = False) -> "_Conn":  # noqa: F821
        return _StubDB._Conn()

    def log_audit(
        self,
        conn: Any,
        mission_id: str,
        *,
        event_type: str,
        message: str,
        task_id: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.audit_entries.append((mission_id, event_type, message, task_id))


# ── Fixtures ───────────────────────────────────────────────────────────────


def _build_router(
    *,
    human_approval_fn: Any = ...,
    scope_requires_human: bool = False,
    risk_requires_human: bool = False,
    tool_executor: Any = None,
) -> tuple[ToolRouter, _StubDB, list[str]]:
    """Return (router, db_stub, executor_call_log)."""
    if tool_executor is None:
        tool_executor = lambda name, args: "RAW OUTPUT"  # noqa: E731
    if human_approval_fn is ...:
        human_approval_fn = None  # default: no handler
    db = _StubDB()
    router = ToolRouter(
        scope_gate=_StubScopeGate(requires_human_approval=scope_requires_human),
        risk_controller=_StubRiskController(requires_human_approval=risk_requires_human),
        evidence_store=_StubEvidenceStore(),
        tool_executor=tool_executor,
        db=db,
        mission_id="M-0001",
        human_approval_fn=human_approval_fn,
    )
    executor_calls: list[str] = []
    return router, db, executor_calls


# ── C2: missing-handler block ─────────────────────────────────────────────


class TestHumanApprovalMissingHandler:
    """C2 — high-risk action with no approval handler must block, not execute."""

    def test_scope_requires_human_blocks_when_no_handler(self) -> None:
        executor_calls: list[str] = []
        router, db, _ = _build_router(
            scope_requires_human=True,
            tool_executor=lambda name, args: executor_calls.append(name) or "RAW",
        )

        rt = router.route(
            task_id="T-0001",
            tool_name="msfconsole",
            tool_args={"module": "exploit/multi/http/log4shell"},
            target="10.0.0.1",
            risk_level="high",
            action_type="exploit",
        )

        assert rt.allowed is False
        assert rt.requires_human is True
        assert "no approval handler" in rt.blocked_reason.lower()
        # Must NOT have reached the tool executor
        assert executor_calls == []
        # Must be logged as a human_missing block
        assert any("human_missing" in entry[2] and entry[1] == "tool_blocked" for entry in db.audit_entries)

    def test_risk_requires_human_blocks_when_no_handler(self) -> None:
        executor_calls: list[str] = []
        router, _, _ = _build_router(
            risk_requires_human=True,
            tool_executor=lambda name, args: executor_calls.append(name) or "RAW",
        )

        rt = router.route(
            task_id="T-0002",
            tool_name="hydra",
            tool_args={"service": "ssh"},
            target="10.0.0.1",
            risk_level="high",
            action_type="exploit",
        )

        assert rt.allowed is False
        assert rt.requires_human is True
        assert executor_calls == []

    def test_low_risk_still_executes_when_no_handler(self) -> None:
        """Sanity: actions that don't require human approval still run."""
        executor_calls: list[str] = []
        router, _, _ = _build_router(
            tool_executor=lambda name, args: executor_calls.append(name) or "RAW",
        )

        rt = router.route(
            task_id="T-0003",
            tool_name="nmap",
            tool_args={"flags": "-sV"},
            target="10.0.0.1",
            risk_level="low",
            action_type="recon",
        )

        assert rt.allowed is True
        assert rt.requires_human is False
        assert executor_calls == ["nmap"]


# ── Regression: handler present is still called ───────────────────────────


class TestHumanApprovalHandlerPresent:
    """Regression — when a handler IS present, it is consulted."""

    def test_handler_called_and_can_approve(self) -> None:
        calls: list[tuple[str, dict[str, Any]]] = []
        executor_calls: list[str] = []

        def handler(action_name: str, context: dict[str, Any]) -> bool:
            calls.append((action_name, context))
            return True

        router, _, _ = _build_router(
            human_approval_fn=handler,
            risk_requires_human=True,
            tool_executor=lambda name, args: executor_calls.append(name) or "RAW",
        )

        rt = router.route(
            task_id="T-0004",
            tool_name="msfconsole",
            tool_args={"module": "exploit/multi/http/log4shell"},
            target="10.0.0.1",
            risk_level="high",
            action_type="exploit",
        )

        assert rt.allowed is True
        assert len(calls) == 1
        assert calls[0][0] == "msfconsole"
        # Execution proceeds on approval
        assert executor_calls == ["msfconsole"]

    def test_handler_called_and_can_deny(self) -> None:
        executor_calls: list[str] = []

        def handler(action_name: str, context: dict[str, Any]) -> bool:
            return False

        router, db, _ = _build_router(
            human_approval_fn=handler,
            risk_requires_human=True,
            tool_executor=lambda name, args: executor_calls.append(name) or "RAW",
        )

        rt = router.route(
            task_id="T-0005",
            tool_name="msfconsole",
            tool_args={},
            target="10.0.0.1",
            risk_level="high",
            action_type="exploit",
        )

        assert rt.allowed is False
        assert rt.requires_human is True
        # Denied path must NOT reach executor
        assert executor_calls == []
        # Denied path logged as human_denied
        assert any("human_denied" in entry[2] and entry[1] == "tool_blocked" for entry in db.audit_entries)
