"""Attack planner for autonomous AI-driven penetration testing.

Provides:
- AttackPhase enum: RECON, ENUMERATE, EXPLOIT, ESCALATE, LOOT, PIVOT, DONE
- AttackPlan: JSON-serializable plan with ordered phases and tool selections
- AttackPlanner: drives the AI to create/adapt plans based on results
- Plan execution helpers that feed context back to the LLM
"""

from __future__ import annotations

import enum
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class AttackPhase(str, enum.Enum):
    RECON = "recon"
    ENUMERATE = "enumerate"
    EXPLOIT = "exploit"
    ESCALATE = "escalate"
    LOOT = "loot"
    PIVOT = "pivot"
    DONE = "done"


@dataclass
class AttackStep:
    phase: str
    tool: str
    reason: str
    target_ip: str
    arguments: dict[str, Any] = field(default_factory=dict)
    depends_on: list[int] = field(default_factory=list)
    completed: bool = False
    success: bool | None = None
    result_summary: str = ""


@dataclass
class AttackPlan:
    target_ip: str
    target_os: str | None = None
    target_cves: list[str] = field(default_factory=list)
    service_context: str = ""
    phases: list[AttackPhase] = field(default_factory=lambda: [
        AttackPhase.RECON, AttackPhase.ENUMERATE, AttackPhase.EXPLOIT,
        AttackPhase.ESCALATE, AttackPhase.LOOT, AttackPhase.PIVOT, AttackPhase.DONE,
    ])
    steps: list[AttackStep] = field(default_factory=list)
    current_phase_index: int = 0
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    attack_mode: bool = False

    @property
    def current_phase(self) -> AttackPhase:
        if self.current_phase_index < len(self.phases):
            return self.phases[self.current_phase_index]
        return AttackPhase.DONE

    def next_phase(self) -> None:
        if self.current_phase_index < len(self.phases) - 1:
            self.current_phase_index += 1
        self.updated_at = time.time()

    def add_step(self, step: AttackStep) -> int:
        self.steps.append(step)
        self.updated_at = time.time()
        return len(self.steps) - 1

    def mark_step_done(self, index: int, success: bool, summary: str) -> None:
        if 0 <= index < len(self.steps):
            self.steps[index].completed = True
            self.steps[index].success = success
            self.steps[index].result_summary = summary[:2000]
        self.updated_at = time.time()

    def is_complete(self) -> bool:
        return self.current_phase_index >= len(self.phases) - 1

    def to_json(self) -> dict[str, Any]:
        return {
            "target_ip": self.target_ip,
            "target_os": self.target_os,
            "target_cves": self.target_cves,
            "service_context": self.service_context,
            "phases": [p.value for p in self.phases],
            "current_phase": self.current_phase.value,
            "current_phase_index": self.current_phase_index,
            "steps": [
                {
                    "phase": s.phase,
                    "tool": s.tool,
                    "reason": s.reason,
                    "target_ip": s.target_ip,
                    "arguments": s.arguments,
                    "depends_on": s.depends_on,
                    "completed": s.completed,
                    "success": s.success,
                    "result_summary": s.result_summary,
                }
                for s in self.steps
            ],
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "attack_mode": self.attack_mode,
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> AttackPlan:
        plan = cls(
            target_ip=data.get("target_ip", ""),
            target_os=data.get("target_os"),
            target_cves=data.get("target_cves", []),
            service_context=data.get("service_context", ""),
            current_phase_index=data.get("current_phase_index", 0),
            phases=[AttackPhase(p) for p in data.get("phases", [])],
            created_at=data.get("created_at", time.time()),
            updated_at=data.get("updated_at", time.time()),
            attack_mode=data.get("attack_mode", False),
        )
        for s in data.get("steps", []):
            step = AttackStep(
                phase=s.get("phase", ""),
                tool=s.get("tool", ""),
                reason=s.get("reason", ""),
                target_ip=s.get("target_ip", ""),
                arguments=s.get("arguments", {}),
                depends_on=s.get("depends_on", []),
                completed=s.get("completed", False),
                success=s.get("success"),
                result_summary=s.get("result_summary", ""),
            )
            plan.steps.append(step)
        return plan

    def generate_battle_log(self) -> str:
        """Compact summary of everything tried so far for context compression."""
        lines = [
            f"Target: {self.target_ip}",
            f"Current Phase: {self.current_phase.value}",
            f"Total Steps: {len(self.steps)}",
            f"Completed Steps: {sum(1 for s in self.steps if s.completed)}",
            f"Successful Steps: {sum(1 for s in self.steps if s.completed and s.success)}",
        ]
        for i, s in enumerate(self.steps):
            status = "✓" if s.completed and s.success else "✗" if s.completed else "○"
            lines.append(f"  [{i}] {status} {s.phase}/{s.tool}: {s.reason[:80]}")
            if s.completed:
                lines.append(f"       Result: {s.result_summary[:120]}")
        return "\n".join(lines)


def build_planning_prompt(
    phase: AttackPhase,
    target_ip: str,
    target_os: str | None,
    known_cves: list[str],
    service_context: str,
    attacker_os: str,
    previous_result: str = "",
    battle_log: str = "",
) -> str:
    """Build a prompt that asks the AI to generate an attack plan for the current phase."""
    base = f"""You are an autonomous penetration testing AI. You are in **{phase.value.upper()}** phase.

TARGET: {target_ip}
TARGET OS: {target_os or "Unknown"}
KNOWN CVEs: {', '.join(known_cves) if known_cves else "None"}
SERVICE CONTEXT: {service_context}
ATTACKER OS: {attacker_os}

{previous_result}

BATTLE LOG (history of attempts):
{battle_log}

Your task: Generate the NEXT attack steps for this phase.
Return ONLY a JSON list of steps, like:
[
  {{
    "phase": "{phase.value}",
    "tool": "check_os",
    "reason": "Need to confirm target OS before choosing exploit",
    "target_ip": "{target_ip}",
    "arguments": {{"target_ip": "{target_ip}"}},
    "depends_on": []
  }},
  ...
]

Rules:
- Each step must use a valid tool name from your available MCP tools.
- "depends_on" lists indices of previous steps that must succeed before this step.
- Keep each reason concise (under 200 chars).
- If the phase should be skipped, return an empty list and explain why in your reasoning.
- After generating the plan, execute it step-by-step.
"""
    return base


def build_replanning_prompt(
    plan: AttackPlan,
    last_result: str,
    attacker_os: str,
) -> str:
    """Prompt the AI to update its plan after a tool result."""
    phase = plan.current_phase
    base = f"""You are in **{phase.value.upper()}** phase against {plan.target_ip}.

SERVICE CONTEXT: {plan.service_context}
ATTACKER OS: {attacker_os}

BATTLE LOG:
{plan.generate_battle_log()}

LAST RESULT:
{last_result[:2000]}

Adaptive instructions:
- If the last step succeeded, consider escalating or moving to the next phase.
- If it failed, try an alternative approach within the same phase.
- If you gained access (shell, RCE, command execution), automatically transition to POST-EXPLOITATION (escalate, loot, pivot).
- Do NOT repeat failed steps verbatim.
- If target OS is now known and differs from assumptions, update your tool choices.

What is your next move? Return a JSON step OR a phase transition command:
{{
  "action": "step" | "next_phase" | "done",
  "step": {{"phase": "...", "tool": "...", "reason": "...", "target_ip": "...", "arguments": {{}}, "depends_on": []}},
  "explanation": "..."
}}
"""
    return base


def parse_plan_json(text: str) -> list[AttackStep]:
    """Extract JSON list of attack steps from AI response text (with markdown fence stripping)."""
    text = text.strip()
    if text.startswith("```json"):
        text = text[7:]
    if text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    text = text.strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        data = data.get("steps", [])
    if not isinstance(data, list):
        return []
    steps: list[AttackStep] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        steps.append(AttackStep(
            phase=item.get("phase", ""),
            tool=item.get("tool", ""),
            reason=item.get("reason", ""),
            target_ip=item.get("target_ip", ""),
            arguments=item.get("arguments", {}),
            depends_on=item.get("depends_on", []),
        ))
    return steps


def parse_replan_json(text: str) -> tuple[str, AttackStep | None, str]:
    """Parse replanning response: returns (action, step_or_none, explanation)."""
    text = text.strip()
    if text.startswith("```json"):
        text = text[7:]
    if text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    text = text.strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return "step", None, "Parse error; continuing with heuristic step"
    action = data.get("action", "step")
    explanation = data.get("explanation", "")
    step_data = data.get("step")
    step = None
    if isinstance(step_data, dict):
        step = AttackStep(
            phase=step_data.get("phase", ""),
            tool=step_data.get("tool", ""),
            reason=step_data.get("reason", ""),
            target_ip=step_data.get("target_ip", ""),
            arguments=step_data.get("arguments", {}),
            depends_on=step_data.get("depends_on", []),
        )
    return action, step, explanation


class AttackPlanner:
    """Manages plan lifecycle: creation, execution, adaptive replanning, persistence."""

    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace
        self.workspace.mkdir(parents=True, exist_ok=True)
        self._plans: dict[str, AttackPlan] = {}
        self._plan_path = workspace / "plans"
        self._plan_path.mkdir(parents=True, exist_ok=True)

    def create_plan(
        self,
        target_ip: str,
        *,
        target_os: str | None = None,
        known_cves: list[str] | None = None,
        service_context: str = "",
        attack_mode: bool = False,
    ) -> AttackPlan:
        plan = AttackPlan(
            target_ip=target_ip,
            target_os=target_os,
            target_cves=known_cves or [],
            service_context=service_context,
            attack_mode=attack_mode,
        )
        self._plans[target_ip] = plan
        return plan

    def get_plan(self, target_ip: str) -> AttackPlan | None:
        return self._plans.get(target_ip)

    def save_plan(self, plan: AttackPlan) -> None:
        path = self._plan_path / f"{plan.target_ip.replace('.', '_')}_plan.json"
        path.write_text(json.dumps(plan.to_json(), indent=2, default=str), encoding="utf-8")

    def load_plan(self, target_ip: str) -> AttackPlan | None:
        path = self._plan_path / f"{target_ip.replace('.', '_')}_plan.json"
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            plan = AttackPlan.from_json(data)
            self._plans[target_ip] = plan
            return plan
        except (json.JSONDecodeError, KeyError):
            return None

    def has_active_plan(self, target_ip: str) -> bool:
        plan = self.get_plan(target_ip) or self.load_plan(target_ip)
        if plan is None:
            return False
        return not plan.is_complete()

    def all_plans_summary(self) -> str:
        lines = ["ACTIVE PLANS:"]
        for ip, plan in self._plans.items():
            status = "DONE" if plan.is_complete() else plan.current_phase.value.upper()
            lines.append(f"  {ip}: {status} ({len(plan.steps)} steps, {sum(1 for s in plan.steps if s.completed and s.success)} success)")
        return "\n".join(lines)
