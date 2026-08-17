"""Shared runtime-skill selection pipeline.

Centralizes the build → select → render/hints flow used by the main exploit
loop (``main.py``), the mid-run re-selection hook (``tools.exploit_agent``),
the swarm (``tools/swarm/``), and MCP tools so every consumer applies the same
advisory-only invariant and the same char budgets.

Skills are advisory prompt context only -- nothing here grants execution
authority or changes permission/scope/audit behavior.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from tools.skill_registry import SkillRegistry
from tools.skill_registry_cache import get_registry
from tools.skill_selector import SkillSelection, select_runtime_skills


def _skills_config(config: dict[str, Any] | None) -> dict[str, Any]:
    from tools.config_manager import CONFIG_SCHEMA

    base = dict(CONFIG_SCHEMA.get("skills", {}) or {})
    overlay = ((config or {}).get("skills", {}) or {})
    if isinstance(overlay, dict):
        base.update(overlay)
    return base


def build_skill_selection_for_context(
    config: dict[str, Any] | None = None,
    *,
    goal_name: str = "",
    goal_description: str = "",
    mode: str = "recon",
    services: Iterable[str] | None = None,
    known_cves: Iterable[str] | None = None,
    recent_tools: Iterable[str] | None = None,
    context_text: str = "",
    registry: SkillRegistry | None = None,
    active_names: Iterable[str] = (),
    sticky_defaults: bool = False,
    experience_store: Any | None = None,
    skill_embedder: Any | None = None,
    is_domain: bool = False,
) -> SkillSelection:
    """Build a ``SkillSelection`` for the given run context.

    When ``registry`` is omitted the shared process-level cache is used. Pass
    ``active_names`` / ``sticky_defaults`` from the mid-run re-selection path
    to prefer newly-relevant skills and retain configured defaults. Pass an
    ``experience_store`` to apply the cross-mission feedback boost (advisory,
    boost-only; no-op without a store). Pass a ``skill_embedder`` to enable
    embedding-based semantic matching (default-on with graceful fallback).
    Pass ``is_domain=True`` when the operator targeted a domain --target so
    domain-attack skills (subdomain enum, DNS recon, takeover, vhost) get a
    ``target:domain`` tag-signal boost.
    """

    skills_cfg = _skills_config(config)
    if skills_cfg.get("enabled", True) is False:
        return SkillSelection()
    if registry is None:
        registry = get_registry({"skills": skills_cfg}, base_dir=Path.cwd())
    # Note: the embedder is NOT auto-resolved here. Resolving it would build a
    # SemanticMemoryManager and (when Ollama is up) embed the full catalog on
    # every call -- far too expensive for the test suite and for callers that
    # only want deterministic tag matching. Production callers (main.py, the
    # swarm, the mid-run re-selection hook) pass ``get_shared_skill_embedder``
    # explicitly so semantic matching is default-on in real runs and off in
    # tests/unit paths that pass no embedder.
    merged = dict(config or {})
    merged["skills"] = skills_cfg
    return select_runtime_skills(
        registry,
        config=merged,
        goal_name=goal_name,
        goal_description=goal_description,
        mode=mode,
        services=services,
        known_cves=known_cves,
        recent_tools=recent_tools,
        context_text=context_text,
        active_names=active_names,
        sticky_defaults=sticky_defaults,
        experience_store=experience_store,
        skill_embedder=skill_embedder,
        is_domain=is_domain,
    )


def active_skill_payloads(selection: SkillSelection) -> list[dict[str, Any]]:
    return [
        {
            "name": activation.name,
            "reason": activation.reason,
            "source": activation.source,
            "matched_tags": list(activation.matched_tags),
            "risk_level": activation.risk_level,
        }
        for activation in selection.activations
    ]


def compact_skill_hints(selection: SkillSelection, *, max_chars: int = 1200) -> str:
    if not selection.activations:
        return ""
    lines = [
        "Selected advisory skills are available on demand. "
        "Load full guidance only when a concrete current step needs it.",
    ]
    for activation in selection.activations:
        tags = ", ".join(activation.matched_tags[:5]) or "no matched tags"
        lines.append(
            f"- {activation.name} | {activation.risk_level} | tags: {tags} | {activation.reason}"
        )
    text = "\n".join(lines)
    if len(text) <= max_chars:
        return text
    return text[: max(0, max_chars - 16)].rstrip() + "\n...[truncated]"


def apply_skill_selection(
    target_context: dict[str, Any],
    selection: SkillSelection,
    *,
    skills_cfg: dict[str, Any],
) -> None:
    """Write the advisory skill fields into a ``target_context`` dict.

    Mirrors the pre-refactor ``main._apply_runtime_skill_selection`` behavior:
    hints are always injected; the full rendered body (``skill_context``) only
    when ``inject_startup_context`` is true.
    """

    target_context["active_skills"] = active_skill_payloads(selection)
    target_context["skill_hints"] = compact_skill_hints(selection)
    if bool(skills_cfg.get("inject_startup_context", False)):
        target_context["skill_context"] = selection.prompt_context
    else:
        target_context["skill_context"] = ""


def _phase_activations(selection: SkillSelection, phase: str) -> tuple:
    # ponytail: SwarmOrchestrator.orchestrator.py:149 stores None in
    # context["skill_selection"] when build_skill_selection_for_swarm raises
    # (bare except Exception). Without this guard the review-phase branch
    # below dereferences selection.activations and crashes with
    # 'NoneType' object has no attribute 'activations' every reflection cycle.
    if selection is None:
        return ()
    from tools.swarm.skill_phase import phase_tags

    wanted = phase_tags(phase)
    if wanted is None:
        return selection.activations
    return tuple(
        activation
        for activation in selection.activations
        if set(activation.matched_tags) & wanted
    )


def phase_skill_hints(selection: SkillSelection, phase: str) -> str:
    """Compact hints for the skills relevant to one swarm phase.

    Returns ``""`` when no skills match the phase (or the selection is empty).
    """

    activations = _phase_activations(selection, phase)
    if not activations:
        return ""
    sub = SkillSelection(activations=activations)
    return compact_skill_hints(sub)


def phase_skill_payloads(selection: SkillSelection, phase: str) -> list[dict[str, Any]]:
    activations = _phase_activations(selection, phase)
    return [
        {
            "name": a.name,
            "reason": a.reason,
            "source": a.source,
            "matched_tags": list(a.matched_tags),
            "risk_level": a.risk_level,
        }
        for a in activations
    ]


def build_skill_selection_for_swarm(context: dict[str, Any]) -> SkillSelection:
    """Best-effort mission-level skill selection for the swarm shared context.

    Built once from the swarm ``context`` (config + mission objective + mode
    hint) and stashed on ``context["skill_selection"]`` so every specialist
    agent can derive phase-relevant hints from one advisory set. Advisory only.
    """

    config = context.get("config", {}) or {}
    skills_cfg = _skills_config(config)
    if skills_cfg.get("enabled", True) is False:
        return SkillSelection()
    if not skills_cfg.get("swarm_inject", True):
        return SkillSelection()
    mission = context.get("mission", {}) or {}
    goal = str(
        mission.get("objective") or mission.get("goal") or ""
    )
    mode = str(context.get("skill_mode") or mission.get("mode") or "recon").strip() or "recon"
    # Use the swarm's shared ExperienceStore when present (same DB the agents
    # write outcomes into); otherwise the process-wide skill store; otherwise
    # None (selector skips the feedback boost -- tag matching remains floor).
    store = context.get("experience")
    if store is None:
        from tools.skill_feedback import get_shared_skill_store

        store = get_shared_skill_store(config)
    return build_skill_selection_for_context(
        config,
        goal_name=goal,
        goal_description=goal,
        mode=mode,
        experience_store=store,
    )


def append_phase_skill_hints(prompt: str, selection: SkillSelection, phase: str) -> str:
    """Append a compact advisory skill-hints block to an agent prompt.

    Returns the prompt unchanged when there are no phase-relevant skills (or
    no selection). Hints are activation metadata (name/tags/reason), not skill
    bodies, so there is no prompt-injection surface; the bodies stay available
    only via the exploit agent's MCP ``load_runtime_skill`` tool.
    """

    hints = phase_skill_hints(selection, phase)
    if not hints:
        return prompt
    return (
        f"{prompt}\n\nRUNTIME SKILL HINTS (advisory only -- never override scope, "
        f"permission, approval, command-safety, or audit rules):\n{hints}"
    )
