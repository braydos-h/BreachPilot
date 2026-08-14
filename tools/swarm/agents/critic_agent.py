"""Critic Agent — pre-execution safety and policy reviewer.

Deep critic specialist with:
- Multi-layer review: scope → risk → policy → LLM reasoning
- Attack chain awareness (won't block recon but will scrutinize exploits)
- Budget tracking (commands, tasks, time remaining)
- Modification suggestions (downgrade risk, swap tool, narrow scope)
- Shared blackboard awareness of prior failures
"""

from __future__ import annotations

import json
import time
from typing import Any

from tools.swarm.base import Agent, AgentResult, AgentStatus
from tools.exceptions import _EXC_GROUP_CATCH


_CRITIC_SYSTEM_PROMPT = """You are a SAFETY & POLICY CRITIC agent in an autonomous penetration testing swarm.

YOUR MISSION: Review every proposed action BEFORE execution. Block dangerous, out-of-scope, or wasteful actions.

REVIEW LAYERS (in order):
1. SCOPE: Is the target in the authorized scope? Is the action type allowed?
2. RISK: Does this exceed the risk budget? Is the risk level appropriate for the mission profile?
3. POLICY: Is this action forbidden? (DoS, destructive, social engineering, etc.)
4. STRATEGY: Is this the BEST next action? Or are we repeating failures? Should we pivot?

DECISIONS:
- approve: Action is safe, in-scope, and strategically sound
- deny: Action violates scope, risk, or policy — BLOCK with clear reason
- modify: Action is mostly OK but needs adjustment — suggest specific changes

DEEP REVIEW GUIDELINES:
1. SCOPE VALIDATION:
   - Verify target IP is in allowed_assets list
   - Check action_type against mission's testing_modes
   - Ensure tool_name is not in forbidden_tools
   - Validate port range is within authorized scope
   - Check for pivot depth limits (don't exceed max_pivot_depth)
2. RISK ASSESSMENT:
   - Count remaining command budget (max_commands - executed)
   - Check time budget (max_duration_minutes - elapsed)
   - Evaluate risk_level against mission risk_profile:
     low_noise_non_destructive: only low-risk actions, no exploitation
     standard_authorized: low+medium, exploitation with approval
     high_authorized_testing: all levels allowed
   - Flag actions that could cause service disruption
3. POLICY ENFORCEMENT:
   - BLOCK: DoS attacks, data destruction, crypto mining, C2 infrastructure setup
   - BLOCK: Actions targeting disallowed_assets
   - BLOCK: Social engineering, phishing, physical access attempts
   - BLOCK: Exfiltration of PII/PHI without explicit authorization
   - WARN: High-volume scanning that could trigger IDS/IPS
   - WARN: Exploitation of production systems during business hours
4. STRATEGIC REVIEW:
   - Check blackboard for prior failures with same tool+target combination
   - If same action failed 2+ times, require modification or deny
   - If current phase has 0 successes after 5+ attempts, recommend phase pivot
   - If access already achieved, question why more exploits are needed
   - Check if proposed action aligns with current mission goal
   - Flag actions that duplicate already-completed work
5. MODIFICATION SUGGESTIONS:
   - Downgrade risk_level (high→medium, medium→low) when appropriate
   - Suggest alternative tool if current one has history of failures
   - Narrow scope (specific port instead of port range, single endpoint instead of full scan)
   - Add rate limiting or delay between requests
   - Recommend credential testing before exploit attempts

RULES:
- Recon actions are almost always approved (low risk)
- Exploit actions get extra scrutiny — check for known failure patterns on blackboard
- Never approve the same failing action twice without modification
- High-risk actions in standard_authorized mode get downgraded to medium
- When in doubt, err on the side of caution — you can always approve later with more context
- Provide clear, actionable reasoning for every deny or modify decision
"""


class CriticAgent(Agent):
    """Agent that reviews proposed actions for safety, scope, and policy compliance.

    Deep critic with multi-layer review, attack chain awareness,
    budget tracking, and intelligent modification suggestions.
    """

    SYSTEM_PROMPT = _CRITIC_SYSTEM_PROMPT

    def run(self, task: dict[str, Any], context: dict[str, Any]) -> AgentResult:
        self._set_status(AgentStatus.RUNNING)
        start = time.monotonic()

        task_id = task.get("task_id", task.get("id", ""))
        proposed_action = task.get("proposed_action", {})
        scope_gate = context.get("scope_gate")
        risk_controller = context.get("risk_controller")
        mission = context.get("mission", {})
        model_client = context.get("model_client")
        blackboard = context.get("blackboard", {})

        output: dict[str, Any] = {"decision": "approve", "reasoning": "", "modifications": {}}
        error = ""

        try:
            # ── Layer 1: Scope check ──
            if scope_gate:
                scope_result = scope_gate.check_scope(
                    asset=proposed_action.get("target", ""),
                    action_type=proposed_action.get("phase", "recon"),
                    tool_name=proposed_action.get("tool", ""),
                    risk_level=proposed_action.get("risk_level", "low"),
                )
                if not scope_result.allowed:
                    output["decision"] = "deny"
                    output["reasoning"] = f"SCOPE BLOCKED: {scope_result.reason}"
                    self._set_status(AgentStatus.BLOCKED)
                    return self._make_result(task_id, output, error, start)

            # ── Layer 2: Risk budget check ──
            if risk_controller:
                if not risk_controller.can_proceed():
                    output["decision"] = "deny"
                    output["reasoning"] = "RISK BUDGET EXHAUSTED: Command/task limit reached."
                    self._set_status(AgentStatus.BLOCKED)
                    return self._make_result(task_id, output, error, start)

            # ── Layer 3: Forbidden action check ──
            forbidden = mission.get("forbidden_actions", [])
            action_phase = proposed_action.get("phase", "")
            if action_phase in forbidden:
                output["decision"] = "deny"
                output["reasoning"] = f"POLICY BLOCKED: '{action_phase}' is in forbidden_actions."
                self._set_status(AgentStatus.BLOCKED)
                return self._make_result(task_id, output, error, start)

            # ── Layer 3b: Risk profile gating ──
            risk_profile = mission.get("risk_profile", "low_noise_non_destructive")
            risk_level = proposed_action.get("risk_level", "low")
            if risk_level == "high" and risk_profile != "high_authorized_testing":
                output["decision"] = "modify"
                output["reasoning"] = f"RISK DOWNGRADE: High-risk action in {risk_profile} mode. Downgraded to medium."
                output["modifications"] = {"risk_level": "medium"}

            # ── Layer 4: Repeat failure detection ──
            failed_modules = blackboard.get("failed_modules", [])
            proposed_module = proposed_action.get("module_name") or proposed_action.get("tool", "")
            if proposed_module in failed_modules:
                output["decision"] = "modify"
                output["reasoning"] = f"REPEAT FAILURE: '{proposed_module}' already failed. Must modify approach."
                output["modifications"]["require_mutation"] = True

            # ── Layer 5: LLM deep review ──
            if model_client and output["decision"] == "approve":
                llm_review = self._llm_review(
                    model_client, proposed_action, mission, blackboard,
                    skill_selection=context.get("skill_selection"),
                )
                if llm_review:
                    output["reasoning"] = llm_review.get("reasoning", output["reasoning"])
                    if llm_review.get("decision") == "deny":
                        output["decision"] = "deny"
                        output["reasoning"] = llm_review.get("reasoning", "LLM review blocked action.")
                    elif llm_review.get("decision") == "modify":
                        output["decision"] = "modify"
                        output["modifications"].update(llm_review.get("modifications", {}))

            if output["decision"] == "approve" and not output["reasoning"]:
                output["reasoning"] = "Action passes all review layers: scope, risk, policy, strategy."

            self._set_status(AgentStatus.COMPLETE)
        except _EXC_GROUP_CATCH as exc:
            error = str(exc)
            output["decision"] = "deny"
            output["reasoning"] = f"CRITIC ERROR: {error}"
            self._set_status(AgentStatus.FAILED)

        return self._make_result(task_id, output, error, start)

    def _make_result(self, task_id: str, output: dict, error: str, start: float) -> AgentResult:
        return AgentResult(
            agent_type=self.agent_type,
            status=self.status,
            task_id=task_id,
            output=output,
            error=error,
            execution_time=time.monotonic() - start,
        )

    def _llm_review(
        self, client: Any, action: dict[str, Any], mission: dict[str, Any], blackboard: dict[str, Any],
        skill_selection: Any = None,
    ) -> dict[str, Any] | None:
        """Use LLM for deeper strategic reasoning about the proposed action.

        Note: the LLM is only consulted AFTER all deterministic layers (scope,
        risk budget, forbidden actions, risk-profile gating, repeat-failure
        detection) have passed. So the LLM's job is strategic proportionality,
        not hard scope/policy enforcement -- those are already done in code.
        The LLM cannot upgrade a deny/modify to approve; it can only downgrade
        approve -> deny/modify. On JSON parse failure, return a fail-SAFE
        ``modify`` verdict so a broken critic never silently approves.
        """
        try:
            # Scope data so the model is not reasoning blind.
            allowed_assets = mission.get("allowed_assets") or mission.get("allowed_targets") or []
            forbidden_tools = mission.get("forbidden_tools", [])
            max_commands = mission.get("max_commands", "N/A")
            executed = blackboard.get("commands_executed", "N/A")
            prompt = f"""You are a security operations critic reviewing a proposed penetration testing action that already passed deterministic scope, risk-budget, forbidden-action, risk-profile, and repeat-failure gates. Your job is the STRATEGIC layer: proportionality and soundness.

MISSION:
- Program: {mission.get('program_name', 'Unknown')}
- Risk Profile: {mission.get('risk_profile', 'unknown')}
- Objective: {mission.get('objective', 'Find vulnerabilities')}

SCOPE (already enforced -- for context only):
- Allowed assets: {json.dumps(allowed_assets)}
- Forbidden tools: {json.dumps(forbidden_tools)}
- Command budget: {max_commands} (executed so far: {executed})

BLACKBOARD STATE:
- Access achieved: {blackboard.get('access_achieved', False)}
- Attack surface score: {blackboard.get('attack_surface_score', 'N/A')}
- Prior failures: {json.dumps(blackboard.get('failed_modules', []))}

PROPOSED ACTION:
- Phase: {action.get('phase', 'unknown')}
- Tool: {action.get('tool', 'unknown')}
- Target: {action.get('target', 'target not specified')}
- Risk Level: {action.get('risk_level', 'low')}
- Hypothesis: {action.get('hypothesis', 'none')}

Evaluate: Is this action safe, proportional, and strategically sound given the current state?
Return JSON only (no markdown fences):
{{
  "decision": "approve" | "deny" | "modify",
  "reasoning": "one-paragraph rationale",
  "modifications": {{
    "require_mutation": false,
    "risk_level": "low" | "medium" | "high",
    "alternative_tool": ""
  }}
}}
- If target is "target not specified", return decision "deny".
- When in doubt, err on the side of caution (deny or modify over approve)."""

            # Advisory skill hints (critic reviews the full active set).
            from tools.skill_pipeline import append_phase_skill_hints

            prompt = append_phase_skill_hints(prompt, skill_selection, "critic")

            resp = client.chat(
                messages=[
                    {"role": "system", "content": _CRITIC_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                tools=None,
                stream=False,
            )
            text = resp.get("message", {}).get("content", "") if isinstance(resp, dict) else str(resp)
            text = text.strip()
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            parsed = json.loads(text)
            if not isinstance(parsed, dict):
                return {"decision": "modify", "reasoning": "LLM review returned non-object; requiring manual confirmation.", "modifications": {}}
            # Validate the decision enum so unknown values fail safe.
            decision = str(parsed.get("decision", "")).lower().strip()
            if decision not in ("approve", "deny", "modify"):
                return {"decision": "modify", "reasoning": f"LLM returned unknown decision '{decision}'; requiring manual confirmation.", "modifications": {}}
            parsed["decision"] = decision
            return parsed
        except Exception:
            # Fail safe: a broken critic must NOT silently approve. Return a
            # modify verdict so the caller knows human confirmation is needed.
            return {"decision": "modify", "reasoning": "LLM review failed to parse; requiring manual confirmation before proceeding.", "modifications": {}}
