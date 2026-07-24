"""Safety reviewer for recon mode.

When in recon mode, after the initial reconnaissance phase completes,
the safety reviewer sends the results to the AI with a safety-focused prompt.
The AI evaluates whether proceeding to attack is safe/appropriate.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SafetyReview:
    safe_to_proceed: bool
    reasoning: str
    concerns: list[str] = field(default_factory=list)
    recommended_next_steps: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "safe_to_proceed": self.safe_to_proceed,
            "reasoning": self.reasoning,
            "concerns": self.concerns,
            "recommended_next_steps": self.recommended_next_steps,
        }


def build_safety_review_prompt(recon_results: str, target_ip: str, goal: str) -> str:
    return f"""You are a safety reviewer analyzing reconnaissance results before an attack operation.

TARGET: {target_ip}
PROPOSED GOAL: {goal}

RECONNAISSANCE RESULTS:
{recon_results[:4000]}

Your task: Review these results and determine whether proceeding with the proposed attack is SAFE and APPROPRIATE.
Consider:
- Is this target likely a production/critical system? (e.g., medical devices, SCADA, hospital networks)
- Are there signs this is a honeypot or security research system?
- Does the target appear to be a personal/lab device vs a corporate critical asset?
- Are the proposed attack methods proportional to the target type?

Return a JSON object exactly in this format (no markdown fences):
{{
  "safe_to_proceed": true or false,
  "reasoning": "Detailed explanation of your risk assessment",
  "concerns": ["List any safety or ethical concerns"],
  "recommended_next_steps": ["Suggested actions if proceeding"]
}}
"""


def parse_safety_review(text: str) -> SafetyReview:
    """Parse safety review JSON from AI response."""
    text = text.strip()
    # Strip markdown fences if present
    if text.startswith("```json"):
        text = text[7:]
    if text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    text = text.strip()
    try:
        data = json.loads(text)
        return SafetyReview(
            safe_to_proceed=bool(data.get("safe_to_proceed", False)),
            reasoning=str(data.get("reasoning", "No reasoning provided.")),
            concerns=data.get("concerns", []),
            recommended_next_steps=data.get("recommended_next_steps", []),
        )
    except json.JSONDecodeError:
        return SafetyReview(
            safe_to_proceed=False,
            reasoning="Could not parse safety review JSON. Defaulting to caution.",
        )


class SafetyReviewer:
    """Runs the safety review phase after recon."""

    def __init__(self, client: Any, model: str) -> None:
        self.client = client
        self.model = model

    def review(self, recon_results: str, target_ip: str, goal: str) -> SafetyReview:
        prompt = build_safety_review_prompt(recon_results, target_ip, goal)
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": "You are a cautious security reviewer."},
            {"role": "user", "content": prompt},
        ]
        try:
            response = self.client.chat(self.model, messages=messages, stream=False)
        except Exception as exc:
            return SafetyReview(
                safe_to_proceed=False,
                reasoning=f"Safety reviewer: LLM call failed ({exc}). Defaulting to caution.",
            )
        content = ""
        if hasattr(response, "message"):
            content = getattr(response.message, "content", "") or ""
        elif isinstance(response, dict):
            msg = response.get("message", {})
            content = msg.get("content", "") if isinstance(msg, dict) else getattr(msg, "content", "")
        return parse_safety_review(content)
