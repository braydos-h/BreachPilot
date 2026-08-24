"""Executor Agent — only runs approved tasks from the task queue.

Rules:
- Never act without a task.
- Never act without a scope check (done via ToolRouter).
- Never act without an expected observation.
- Prefer safe, low-noise actions.
- Save raw output to evidence.
- Return structured output to the Observer.
- Do not flood LLM context with huge raw logs.

Before execution, the executor produces an ExecutionPlan.
After execution, it returns a compact ExecutionResult.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from tool_router import ToolRouter


@dataclass
class ExecutionPlan:
    """What the Executor intends to do before touching any tool."""

    task_id: str
    hypothesis: str = ""
    planned_action: str = ""
    tool: str = ""
    tool_args: dict[str, Any] = field(default_factory=dict)
    why_allowed: str = ""
    expected_observation: str = ""
    risk_level: str = "low"
    target: str = ""


@dataclass
class ExecutionResult:
    """Compact result returned after execution (for the Observer)."""

    task_id: str
    success: bool = False
    output_summary: str = ""
    evidence_refs: list[str] = field(default_factory=list)
    tool_name: str = ""
    target: str = ""
    expected_observation_matched: bool = False
    error: str = ""
    execution_time: float = 0.0
    scope_gate_passed: bool = False
    risk_gate_passed: bool = False
    raw_output: str = ""


class ExecutorAgent:
    """Disciplined tool executor — only acts with a plan + scope clearance."""

    def __init__(
        self,
        tool_router: ToolRouter,
        *,
        max_retries_per_task: int = 2,
    ) -> None:
        self._router = tool_router
        self._max_retries_per_task = max_retries_per_task

    # ── Main API ────────────────────────────────────────────────────────

    def execute(
        self,
        task: dict[str, Any],
    ) -> ExecutionResult:
        """Execute a single task from the task queue.

        The task dict must contain: task_id, target, phase, objective, hypothesis,
        allowed_tools, risk_level, success_criteria, stop_conditions.

        Returns ExecutionResult for the Observer to process.
        """
        task_id = task.get("task_id", task.get("id", ""))
        target = task.get("target", "")
        phase = task.get("phase", "recon")
        hypothesis = task.get("hypothesis", "")

        # Pick the first allowed tool
        allowed_tools = task.get("allowed_tools", [])
        if not allowed_tools:
            return ExecutionResult(
                task_id=task_id,
                success=False,
                error="No allowed_tools specified for this task.",
            )

        tool = allowed_tools[0]
        risk_level = task.get("risk_level", "low")

        # Build tool arguments from context
        tool_args = self._build_args(tool, target, task)

        # Create execution plan
        plan = ExecutionPlan(
            task_id=task_id,
            hypothesis=hypothesis,
            planned_action=f"Execute {tool} against {target}",
            tool=tool,
            tool_args=tool_args,
            why_allowed=f"Task phase '{phase}' is within mission's testing_modes. "
            f"Asset '{target}' must pass scope check.",
            expected_observation=task.get("objective", "")[:200],
            risk_level=risk_level,
            target=target,
        )

        # Route through the Tool Router (scope + risk + execution + evidence)
        start = time.monotonic()
        result = self._router.route(
            task_id=task_id,
            tool_name=plan.tool,
            tool_args=plan.tool_args,
            target=plan.target,
            risk_level=plan.risk_level,
            action_type=phase,
            hypothesis=plan.hypothesis,
        )
        elapsed = time.monotonic() - start

        # Check output against expected observation (simple heuristic)
        expected_matched = False
        if result.allowed and result.output:
            # Check if output contains key terms from the objective
            obj_keywords = set(task.get("objective", "").lower().split()) - {
                "the",
                "a",
                "an",
                "is",
                "are",
                "was",
                "were",
                "on",
                "at",
                "to",
                "for",
                "of",
                "in",
                "and",
                "or",
                "not",
                "be",
                "has",
                "have",
                "that",
                "this",
            }
            output_lower = result.output.lower()
            # If any meaningful keyword is found, observation is partially matched
            meaningful = [w for w in obj_keywords if len(w) > 3]
            matches = sum(1 for w in meaningful if w in output_lower)
            expected_matched = matches >= 1 if meaningful else True

        return ExecutionResult(
            task_id=task_id,
            success=result.allowed and bool(result.output) and "error" not in result.output.lower()[:200],
            output_summary=result.output_summary,
            evidence_refs=result.evidence_refs,
            tool_name=result.tool_name,
            target=result.target,
            expected_observation_matched=expected_matched,
            error="" if result.allowed else result.blocked_reason,
            execution_time=elapsed,
            scope_gate_passed=result.allowed,
            risk_gate_passed=result.allowed,
            raw_output=result.output,
        )

    # ── Helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _build_args(tool: str, target: str, task: dict[str, Any]) -> dict[str, Any]:
        """Construct reasonable default arguments for common tools."""
        explicit_args = task.get("tool_args")
        if isinstance(explicit_args, dict):
            return dict(explicit_args)

        args: dict[str, Any] = {}

        # Common patterns
        if "check_os" in tool or "nmap" in tool or "scan" in tool:
            args["target_ip"] = target
        elif "http" in tool or "web" in tool:
            args["target_ip"] = target
            args["port"] = args.get("port", 80)
        elif "cve" in tool or "exploit_db" in tool:
            # Use service context from task for search queries
            cve_query = task.get("objective", "").replace("Identify ", "").replace("Scan ", "").strip()[:200]
            args["query"] = cve_query if cve_query else target
        elif "smb" in tool:
            args["target_ip"] = target
        elif "ssh" in tool:
            args["target_ip"] = target
        elif "rdp" in tool:
            args["target_ip"] = target
        elif "ldap" in tool:
            args["target_ip"] = target
        elif "dir" in tool or "enum" in tool:
            args["target_ip"] = target
            args["port"] = 80
        elif "terminal" in tool:
            args["command"] = f"echo 'Running against {target}'"
        elif "python_file" in tool:
            args["target_ip"] = target
            if task.get("filename"):
                args["filename"] = task["filename"]
            if task.get("code"):
                args["code"] = task["code"]
        elif "msf" in tool:
            args["target_ip"] = target
            args["module"] = "auxiliary/scanner/portscan/tcp"

        # Always set target if the tool expects it
        if "target_ip" not in args and "target" in task:
            args["target_ip"] = task["target"]
        if not args:
            args["target"] = target

        return args
