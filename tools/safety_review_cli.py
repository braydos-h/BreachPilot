"""Safety review helper for recon-mode CLI runs."""

from __future__ import annotations

from typing import Any

from tools.attack_ui import AttackUi
from tools.goal_engine import AttackGoal
from tools.safety_reviewer import SafetyReviewer, SafetyReview

ui = AttackUi(plain=False)

async def run_safety_review(
    client: Any,
    model: str,
    result: dict[str, Any],
    target_ip: str,
    goal: AttackGoal,
) -> SafetyReview:
    """After recon, send results to AI for safety review."""
    ui.status("Reconnaissance complete. Running safety review...")

    # Extract results text for review
    parts: list[str] = []
    for msg in result.get("messages", []):
        if isinstance(msg, dict) and msg.get("role") == "tool":
            content = msg.get("content", "")
            if content:
                parts.append(f"[{msg.get('tool_name', 'tool')}] {content[:500]}")

    recon_summary = "\n\n".join(parts[:20])
    reviewer = SafetyReviewer(client, model)
    review = reviewer.review(recon_summary, target_ip, goal.description)
    ui.display_safety_review(review)
    return review


# ---------------------------------------------------------------------------
# Recon-first assessment — scan target, suggest goals with exploit ratings
# ---------------------------------------------------------------------------

