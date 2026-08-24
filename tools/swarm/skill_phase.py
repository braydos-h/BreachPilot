"""Swarm phase → skill-tag mapping.

Each specialist agent in the swarm operates in one phase (recon, vuln,
exploit, post_exploit, critic, reflection). ``phase_tags`` returns the set of
skill tags relevant to that phase, or ``None`` for the critic/reflection
phases which review the whole active set.

Used by ``tools.skill_pipeline.phase_skill_hints`` /
``phase_skill_payloads`` to give each agent only the advisory skills that
match its phase -- never full bodies for non-exploit agents (the single
MCP-session invariant).
"""

from __future__ import annotations

_PHASE_TAGS: dict[str, frozenset[str]] = {
    "recon": frozenset({"reconnaissance", "nmap", "network-security", "osint"}),
    "vuln": frozenset({"vulnerability-scanning", "cve", "vulnerability-triage", "cvss"}),
    "exploit": frozenset({"exploit-research", "exploit", "web", "api", "database", "sql-injection"}),
    "post_exploit": frozenset(
        {
            "post-exploit",
            "credential",
            "active-directory",
            "privilege-escalation",
            "lateral",
        }
    ),
    # PostExploitAgent.agent_type lowercases to "postexploit" (no underscore);
    # alias it to the same tag set so phase filtering works by agent_type.
    "postexploit": frozenset(
        {
            "post-exploit",
            "credential",
            "active-directory",
            "privilege-escalation",
            "lateral",
        }
    ),
}

# critic and reflection review the full active set (read-only advisory review).
_REVIEW_PHASES = frozenset({"critic", "reflection"})


def phase_tags(phase: str) -> frozenset[str] | None:
    """Return the skill-tag set for a swarm phase, or ``None`` for review phases.

    ``None`` signals "all active skills" to the pipeline helpers.
    """

    key = str(phase or "").strip().lower()
    if key in _REVIEW_PHASES:
        return None
    return _PHASE_TAGS.get(key, frozenset())
