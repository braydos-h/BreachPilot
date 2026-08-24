"""Tool Router — scope-gated execution layer between agent and MCP tools.

Every tool call passes through:
1. Scope Check (must be in authorized scope)
2. Risk Assessment (must pass risk profile constraints)
3. Human Approval (if required by mission profile)
4. Execution (actual MCP tool call)
5. Evidence Capture (save raw output + metadata)

The Tool Router is the ONLY way an executor should invoke tools.
It internally calls check_scope before any actual execution.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from db import DatabaseManager
from evidence import EvidenceStore
from risk_controller import RiskController
from scope_gate import ScopeGate
from summarizer import summarize_tool_output


@dataclass
class RoutedToolResult:
    """Result of a tool call through the ToolRouter."""

    allowed: bool
    reason: str = ""
    output: str = ""
    output_summary: str = ""
    tool_name: str = ""
    target: str = ""
    task_id: str = ""
    evidence_refs: list[str] = field(default_factory=list)
    scope_check: dict[str, Any] | None = None
    risk_assessment: dict[str, Any] | None = None
    execution_time_seconds: float = 0.0
    blocked_reason: str = ""
    requires_human: bool = False


class ToolRouter:
    """Routes tool calls through scope gate + risk controller, captures evidence.

    Usage::

        router = ToolRouter(scope_gate, risk_controller, evidence_store, tool_executor_fn)
        result = router.route(
            task_id="T-0001",
            tool_name="search_cve_intel",
            tool_args={"query": "CVE-2021-44228"},
            target="example.com",
            risk_level="low",
        )
        if result.allowed:
            print(result.output_summary)
        else:
            print(f"BLOCKED: {result.blocked_reason}")
    """

    def __init__(
        self,
        scope_gate: ScopeGate,
        risk_controller: RiskController,
        evidence_store: EvidenceStore,
        tool_executor: Callable[[str, dict[str, Any]], str],
        db: DatabaseManager,
        mission_id: str,
        *,
        human_approval_fn: Callable[[str, dict[str, Any]], bool] | None = None,
    ) -> None:
        self._scope_gate = scope_gate
        self._risk_controller = risk_controller
        self._evidence_store = evidence_store
        self._tool_executor = tool_executor  # fn(tool_name, args) -> output
        self._db = db
        self._mission_id = mission_id
        self._human_approval_fn = human_approval_fn  # fn(action_name, context) -> bool

    # ── Main API ────────────────────────────────────────────────────────

    def route(
        self,
        task_id: str,
        tool_name: str,
        tool_args: dict[str, Any],
        target: str,
        risk_level: str = "low",
        action_type: str = "recon",
        hypothesis: str = "",
    ) -> RoutedToolResult:
        """Route a tool call through scope gate → risk controller → execution → evidence capture.

        Returns RoutedToolResult with `allowed` flag. If blocked, `output` is empty.
        """
        start = time.monotonic()

        # ── Step 1: Scope Check ──
        scope_result = self._scope_gate.check_scope(
            asset=target,
            action_type=action_type,
            tool_name=tool_name,
            risk_level=risk_level,
        )

        if not scope_result.allowed:
            rt = RoutedToolResult(
                allowed=False,
                blocked_reason=scope_result.reason,
                reason=scope_result.reason,
                scope_check={
                    "allowed": scope_result.allowed,
                    "reason": scope_result.reason,
                    "matched_rule": scope_result.matched_scope_rule,
                },
            )
            self._log_block(task_id, tool_name, "scope", rt.blocked_reason)
            return rt

        # ── Step 2: Risk Assessment ──
        cmd_repr = f"{tool_name}({json.dumps(tool_args, default=str)[:300]})"
        risk_result = self._risk_controller.assess_action(
            action_type=action_type,
            tool_name=tool_name,
            command_or_args=cmd_repr,
            target=target,
            risk_level=risk_level,
        )

        if not risk_result.allowed:
            rt = RoutedToolResult(
                allowed=False,
                blocked_reason=risk_result.reason,
                reason=risk_result.reason,
                risk_assessment={
                    "allowed": risk_result.allowed,
                    "risk_level": risk_result.risk_level,
                    "warnings": risk_result.warnings,
                },
            )
            self._log_block(task_id, tool_name, "risk", rt.blocked_reason)
            return rt

        # ── Step 3: Human Approval (if required) ──
        needs_human = risk_result.requires_human_approval or scope_result.requires_human_approval
        if needs_human and self._human_approval_fn is None:
            rt = RoutedToolResult(
                allowed=False,
                blocked_reason="Human approval required but no approval handler is configured.",
                requires_human=True,
            )
            self._log_block(task_id, tool_name, "human_missing", rt.blocked_reason)
            return rt
        if needs_human and self._human_approval_fn:
            approved = self._human_approval_fn(
                tool_name,
                {
                    "target": target,
                    "task_id": task_id,
                    "risk_level": risk_level,
                    "tool_args": tool_args,
                    "hypothesis": hypothesis,
                    "risk_warnings": risk_result.warnings,
                },
            )
            if not approved:
                rt = RoutedToolResult(
                    allowed=False,
                    blocked_reason="Human approval denied.",
                    requires_human=True,
                )
                self._log_block(task_id, tool_name, "human_denied", "Human operator denied this action.")
                return rt

        # ── Step 4: Execution ──
        try:
            raw_output = self._tool_executor(tool_name, tool_args)
        except Exception as exc:
            error_output = f"TOOL_EXECUTION_ERROR: {exc}"
            rt = RoutedToolResult(
                allowed=False,
                blocked_reason=error_output,
                reason=error_output,
                tool_name=tool_name,
                target=target,
                task_id=task_id,
                execution_time_seconds=time.monotonic() - start,
            )
            return rt

        elapsed = time.monotonic() - start

        # ── Step 5: Evidence Capture ──
        self._risk_controller.record_execution()
        evidence_id = self._evidence_store.save(
            evidence_type="raw_output",
            content=raw_output,
            metadata={
                "tool_name": tool_name,
                "tool_args": json.dumps(tool_args, default=str)[:1000],
                "target": target,
                "action_type": action_type,
                "risk_level": risk_level,
            },
            task_id=task_id,
            target=target,
        )

        # ── Step 6: Summarize ──
        output_summary = summarize_tool_output(raw_output, tool_name)
        self._log_audit(task_id, tool_name, f"Executed: {output_summary[:200]}")

        return RoutedToolResult(
            allowed=True,
            reason=f"Successfully executed {tool_name} on {target}.",
            output=raw_output if len(raw_output) < 10000 else raw_output[:10000],
            output_summary=output_summary,
            tool_name=tool_name,
            target=target,
            task_id=task_id,
            evidence_refs=[evidence_id],
            scope_check={
                "allowed": scope_result.allowed,
                "matched_rule": scope_result.matched_scope_rule,
            },
            risk_assessment={
                "allowed": risk_result.allowed,
                "risk_level": risk_result.risk_level,
                "warnings": risk_result.warnings,
            },
            execution_time_seconds=elapsed,
            requires_human=needs_human,
        )

    # ── Internal logging ────────────────────────────────────────────────

    def _log_audit(self, task_id: str, event_type: str, message: str) -> None:
        with self._db.connection(write=True) as conn:
            self._db.log_audit(
                conn,
                self._mission_id,
                event_type=f"tool_{event_type}",
                message=message,
                task_id=task_id,
            )

    def _log_block(self, task_id: str, tool_name: str, gate: str, reason: str) -> None:
        with self._db.connection(write=True) as conn:
            self._db.log_audit(
                conn,
                self._mission_id,
                event_type="tool_blocked",
                message=f"Tool '{tool_name}' blocked by {gate} gate: {reason}",
                task_id=task_id,
                metadata={"tool_name": tool_name, "gate": gate},
            )
