"""Runtime skill CLI overrides and startup selection helpers."""

from __future__ import annotations

import argparse
import json
import re
from typing import Any

from tools.config_manager import CONFIG_SCHEMA
from tools.exploit_agent import ExploitSettings
from tools.goal_engine import AttackGoal
from tools.goal_suggester import ReconAssessment
from tools.skill_pipeline import (
    apply_skill_selection as _apply_skill_selection_to_context,
    build_skill_selection_for_context,
)
from tools.skill_registry_cache import get_registry as _get_skill_registry
from tools.skill_selector import SkillSelection

def _skills_config(config: dict[str, Any]) -> dict[str, Any]:
    base = dict(CONFIG_SCHEMA.get("skills", {}) or {})
    overlay = config.get("skills", {}) or {}
    if isinstance(overlay, dict):
        base.update(overlay)
    return base


def apply_skills_cli_overrides(config: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    """Apply ``--skills*`` CLI flags to the in-memory ``config["skills"]`` dict.

    Mutates and returns ``config``. Advisory only -- the overrides change which
    skill *hints* are selected/injected, never permission, scope, allowlist, or
    audit. Called after ``load_config`` and before ``build_skill_selection``.

    - ``--skills off``  -> ``enabled=false``
    - ``--skills on``   -> ``inject_startup_context=true``
    - ``--skills hints``-> ``inject_startup_context=false`` (hints only)
    - ``--skills lookup``-> ``inject_startup_context=false`` + ``allow_model_lookup=true``
    - ``--skills-include`` -> append to ``default_enabled`` (sticky across re-selection)
    - ``--skills-exclude`` -> append to ``exclude_names``
    - ``--no-skills-reselect`` -> ``reselect_mid_run=false``
    """
    skills = dict(config.get("skills", {}) or {})
    mode = getattr(args, "skills", None)
    if mode == "off":
        skills["enabled"] = False
    elif mode == "on":
        skills["enabled"] = True
        skills["inject_startup_context"] = True
    elif mode == "hints":
        skills["enabled"] = True
        skills["inject_startup_context"] = False
    elif mode == "lookup":
        skills["enabled"] = True
        skills["inject_startup_context"] = False
        skills["allow_model_lookup"] = True

    includes = getattr(args, "skills_include", None) or []
    if includes:
        existing = list(skills.get("default_enabled", []) or [])
        for name in includes:
            n = str(name).strip()
            if n and n not in existing:
                existing.append(n)
        skills["default_enabled"] = existing

    excludes = getattr(args, "skills_exclude", None) or []
    if excludes:
        existing = list(skills.get("exclude_names", []) or [])
        for name in excludes:
            n = str(name).strip()
            if n and n not in existing:
                existing.append(n)
        skills["exclude_names"] = existing

    if getattr(args, "no_skills_reselect", False):
        skills["reselect_mid_run"] = False

    config["skills"] = skills
    return config


def print_skills_catalog(config: dict[str, Any]) -> int:
    """Print the runtime-skill catalog (read-only) and exit 0. Used by
    ``--skills-list``. Advisory display only."""
    registry = _get_skill_registry(config)
    skills_cfg = _skills_config(config)
    include_maybe = bool(skills_cfg.get("maybe_enabled", False))
    lines = ["RUNTIME_SKILLS:"]
    count = 0
    for skill in registry.list_skills():
        if skill.metadata.maybe and not include_maybe:
            continue
        tags = ", ".join(skill.metadata.tags[:8])
        maybe = " maybe" if skill.metadata.maybe else ""
        desc = (skill.metadata.description or "").replace("\n", " ").strip()[:240]
        lines.append(f"- {skill.name}{maybe} | tags: {tags or '(none)'} | {desc}")
        count += 1
    if registry.errors:
        lines.append(f"WARNINGS: {len(registry.errors)} skill file(s) could not be loaded.")
    lines.append(f"TOTAL: {count} skills loaded from {len(registry.roots)} root(s).")
    print("\n".join(lines))
    return 0


def _assessment_services(assessment: ReconAssessment | None) -> list[str]:
    if assessment is None:
        return []
    services: list[str] = []
    for service in assessment.services or []:
        name = str(service.get("service", service.get("name", ""))).strip()
        port = str(service.get("port", "")).strip()
        version = str(service.get("version", "")).strip()
        parts = [part for part in (name, port, version) if part]
        if parts:
            services.append(" ".join(parts))
    return services


def _assessment_cves(assessment: ReconAssessment | None) -> list[str]:
    if assessment is None:
        return []
    text = json.dumps(assessment.cve_findings or [], default=str)
    return sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", text, flags=re.IGNORECASE)))


def _build_runtime_skill_selection(
    *,
    config: dict[str, Any],
    goal: AttackGoal,
    mode: str,
    assessment: ReconAssessment | None = None,
    service_context: str = "",
) -> SkillSelection:
    from tools.skill_feedback import get_shared_skill_store
    from tools.skill_embeddings import get_shared_skill_embedder

    return build_skill_selection_for_context(
        config,
        goal_name=goal.name,
        goal_description=goal.description,
        mode=mode,
        services=_assessment_services(assessment),
        known_cves=_assessment_cves(assessment),
        context_text=service_context,
        experience_store=get_shared_skill_store(config),
        skill_embedder=get_shared_skill_embedder(config) if bool(_skills_config(config).get("semantic_matching", True)) else None,
    )


def _apply_runtime_skill_selection(
    exploit_settings: ExploitSettings,
    selection: SkillSelection,
    *,
    config: dict[str, Any],
    goal: AttackGoal | None = None,
    mode: str = "",
) -> None:
    skills_cfg = _skills_config(config)
    _apply_skill_selection_to_context(exploit_settings.target_context, selection, skills_cfg=skills_cfg)
    # Stash advisory goal/mode metadata so the mid-run re-selection hook in
    # run_exploit_agent can rebuild the selection as new services/CVEs appear
    # without re-deriving them. Advisory bookkeeping only.
    exploit_settings.target_context["skill_goal_name"] = goal.name if goal is not None else ""
    exploit_settings.target_context["skill_goal_description"] = goal.description if goal is not None else ""
    exploit_settings.target_context["skill_mode"] = mode or ""
