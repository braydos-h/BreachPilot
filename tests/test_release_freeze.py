"""TODO 022: freeze holds; REQUIRES_APPROVAL covered on every Flow A path."""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def test_freeze_doc_exists():
    text = (REPO / "docs" / "release.md").read_text(encoding="utf-8")
    assert "trust freeze" in text.lower() or "0.69" in text
    assert "post-0.69" in text


def test_requires_approval_on_flow_a_paths():
    # Every Flow A execution path must handle ScopeVerdict.REQUIRES_APPROVAL.
    paths = [
        "tools/exploit_agent/policy.py",
        "tools/campaign/executor.py",
        "tools/swarm/agents/critic_agent.py",
    ]
    missing: list[str] = []
    for rel in paths:
        text = (REPO / rel).read_text(encoding="utf-8")
        if "REQUIRES_APPROVAL" not in text:
            missing.append(rel)
    assert not missing, f"Flow A paths missing REQUIRES_APPROVAL handling: {missing}"
