"""Deterministic runtime skill selection."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from tools.skill_registry import LoadedSkill, SkillRegistry, normalized_skill_tags, render_skill_context


_SERVICE_TAGS: dict[str, set[str]] = {
    "http": {"web", "web-application", "api", "http", "security-headers"},
    "https": {"web", "web-application", "api", "tls", "ssl", "http"},
    "api": {"api", "web", "owasp"},
    "graphql": {"graphql", "api"},
    "smb": {"smb", "active-directory", "windows", "network-security"},
    "microsoft-ds": {"smb", "active-directory", "windows"},
    "ldap": {"ldap", "active-directory", "windows"},
    "kerberos": {"kerberos", "active-directory", "windows"},
    "rdp": {"rdp", "windows", "active-directory"},
    "ssh": {"ssh", "network-security", "privilege-escalation"},
    "ftp": {"ftp", "network-security"},
    "dns": {"dns", "osint", "reconnaissance"},
    "mysql": {"database", "sql-injection", "web"},
    "postgres": {"database", "sql-injection", "web"},
    "mongodb": {"database", "nosql", "api"},
    "redis": {"database", "network-security"},
    "tls": {"tls", "ssl", "certificate"},
}

_GOAL_TAGS: dict[str, set[str]] = {
    "recon": {"reconnaissance", "nmap", "osint", "network-security"},
    "scan": {"vulnerability-scanning", "nmap", "network-security"},
    "verify": {"vulnerability-triage", "cvss", "cve"},
    "cve": {"cve", "vulnerability-scanning", "exploit-research"},
    "web": {"web", "web-application", "api"},
    "api": {"api", "owasp", "web"},
    "credential": {"credential", "active-directory"},
    "report": {"reporting", "vulnerability-triage"},
    "scope": {"scope", "safety", "mcp"},
}

_ATTACK_ONLY_TERMS = {
    "exploit",
    "exploiting",
    "exploitation",
    "exploit-research",
    "bypass",
    "authentication-bypass",
    "privilege-escalation",
    "lateral",
    "credential",
    "credential-dumping",
    "dump",
    "metasploit",
    "adcs",
    "post-exploit",
    "post-exploitation",
    "red-team",
}

_CONTEXTUAL_SOURCES = {"goal", "service", "cve", "tool", "context", "search"}


@dataclass(frozen=True)
class SkillActivation:
    name: str
    reason: str
    source: str
    matched_tags: tuple[str, ...] = ()
    risk_level: str = "advisory"
    score: int = 0
    signals: tuple[str, ...] = ()


@dataclass(frozen=True)
class SkillSelection:
    skills: tuple[LoadedSkill, ...] = ()
    activations: tuple[SkillActivation, ...] = ()
    prompt_context: str = ""
    errors: tuple[str, ...] = ()

    @property
    def reasons(self) -> dict[str, str]:
        return {activation.name: activation.reason for activation in self.activations}


def select_runtime_skills(
    registry: SkillRegistry,
    *,
    config: dict[str, Any] | None = None,
    goal_name: str = "",
    goal_description: str = "",
    mode: str = "recon",
    services: Iterable[str] | None = None,
    known_cves: Iterable[str] | None = None,
    recent_tools: Iterable[str] | None = None,
    context_text: str = "",
    active_names: Iterable[str] = (),
    sticky_defaults: bool = False,
    experience_store: Any | None = None,
    skill_embedder: Any | None = None,
) -> SkillSelection:
    cfg = (config or {}).get("skills", {}) if isinstance(config, dict) else {}
    if cfg.get("enabled", True) is False:
        return SkillSelection()

    max_active = _positive_int(cfg.get("max_active_skills"), 6)
    max_chars_per_skill = _positive_int(cfg.get("max_chars_per_skill"), 2500)
    max_total_chars = _positive_int(cfg.get("max_total_chars"), 9000)
    min_contextual = min(max_active, _positive_int(cfg.get("min_contextual_skills"), 3))
    default_weight = _positive_int(cfg.get("default_skill_weight"), 12)
    context_weight = _positive_int(cfg.get("context_skill_weight"), 24)
    include_maybe = bool(cfg.get("maybe_enabled", False))
    excluded = {str(name).strip() for name in cfg.get("exclude_names", []) or [] if str(name).strip()}

    candidates: dict[str, _Candidate] = {}

    def add(
        skill: LoadedSkill | None,
        score: int,
        reason: str,
        source: str,
        tags: Iterable[str] = (),
        signals: Iterable[str] = (),
    ) -> None:
        if skill is None or skill.name in excluded:
            return
        if skill.metadata.maybe and not include_maybe:
            return
        candidate = candidates.get(skill.name)
        if candidate is None:
            candidates[skill.name] = _Candidate(
                skill=skill,
                score=score,
                reasons=[reason],
                sources={source},
                tags=set(tags),
                signals=set(signals),
            )
        else:
            candidate.score += score
            candidate.reasons.append(reason)
            candidate.sources.add(source)
            candidate.tags.update(tags)
            candidate.signals.update(signals)

    for name in cfg.get("default_enabled", []) or []:
        add(
            registry.get(str(name)),
            default_weight,
            "Configured fallback runtime skill.",
            "default",
            signals=[f"default:{name}"],
        )

    for tag in cfg.get("include_tags", []) or []:
        for skill in registry.search(tags=[str(tag)], include_maybe=include_maybe, limit=max_active * 2):
            add(
                skill,
                context_weight,
                f"Matched configured tag '{tag}'.",
                "config",
                [str(tag)],
                [f"config-tag:{tag}"],
            )

    service_values = [str(s) for s in (services or [])]
    cve_values = [str(cve) for cve in (known_cves or [])]
    tool_values = [str(tool) for tool in (recent_tools or [])]
    goal_text = " ".join([goal_name, goal_description, mode]).lower()
    service_text = " ".join(service_values).lower()
    cve_text = " ".join(cve_values).lower()
    tool_text = " ".join(tool_values).lower()
    extra_text = str(context_text or "").lower()
    text = " ".join([goal_text, service_text, cve_text, tool_text, extra_text]).strip()

    dynamic_tags = _tag_signals(
        goal_text=goal_text,
        service_values=service_values,
        cve_text=cve_text,
        tool_text=tool_text,
        context_text=extra_text,
        mode=mode,
    )
    for tag, signals in dynamic_tags.items():
        source = _source_from_signals(signals)
        for skill in registry.search(tags=[tag], include_maybe=include_maybe, limit=4):
            if mode != "attack" and _looks_attack_only(skill):
                continue
            add(
                skill,
                context_weight + min(len(signals), 4) * 2,
                f"Matched runtime context tag '{tag}'.",
                source,
                [tag],
                signals,
            )

    # Name/query search catches skills whose tags are sparse but title matches.
    for skill in registry.search(text, include_maybe=include_maybe, limit=max_active * 2):
        if mode != "attack" and _looks_attack_only(skill):
            continue
        add(
            skill,
            max(8, context_weight // 2),
            "Matched current goal, services, CVEs, or tool activity.",
            "search",
            signals=["query:text"],
        )

    # ── Tier 2.2: embedding-based semantic matching (default-on, fallback) ──
    # When ``semantic_matching`` is true (default) and an embedder is
    # available, rank the catalog by cosine similarity to the combined context
    # text and add each hit with a similarity-weighted score. Graceful
    # fallback: semantic_rank returns [] when embeddings are unavailable
    # (Ollama down / model missing / offline) after emitting one [WARN], so
    # deterministic tag matching above remains the floor. Attack-only gating
    # applies to semantic hits too (no exploit methodology in recon mode).
    if bool(cfg.get("semantic_matching", True)) and skill_embedder is not None:
        from tools.skill_embeddings import semantic_rank

        sem_weight = _positive_int(cfg.get("semantic_skill_weight", 16), 16)
        for skill, sim in semantic_rank(text, registry, skill_embedder, top_k=max_active * 3):
            if mode != "attack" and _looks_attack_only(skill):
                continue
            add(
                skill,
                int(sim * sem_weight),
                f"Semantic match (similarity={sim:.2f}).",
                "semantic",
                signals=[f"semantic:{sim:.2f}"],
            )

    # Mid-run re-selection support: a small novelty bonus for skills not
    # already active so re-selection surfaces newly-relevant methodology
    # instead of re-emitting the same set. Advisory only -- it only nudges
    # ranking, never excludes.
    active_set = {str(name).strip() for name in (active_names or []) if str(name).strip()}
    if active_set:
        for item in candidates.values():
            if item.skill.name not in active_set:
                item.score += 2

    # ── Tier 2.1: cross-mission feedback boost (advisory, boost-only) ──
    # A skill with a positive Beta posterior (prior > 0.5) over enough
    # observations gets a non-negative score bump so it is more likely to be
    # selected again. A negative track record simply fails to boost -- it
    # NEVER subtracts (advisory invariant: safety-relevant methodology must
    # not be hidden because it once underperformed). No-op without a store or
    # when feedback is disabled; tag matching remains the floor.
    if experience_store is not None and bool(cfg.get("feedback_enabled", True)):
        from tools.skill_feedback import skill_observation_count, skill_prior

        fb_weight = _positive_int(cfg.get("feedback_skill_weight", 8), 8)
        fb_min_obs = max(1, _positive_int(cfg.get("feedback_min_observations", 3), 3))
        for item in candidates.values():
            if skill_observation_count(experience_store, item.skill.name) < fb_min_obs:
                continue
            prior = skill_prior(experience_store, item.skill.name)
            if prior > 0.5:
                bump = int((prior - 0.5) * 2 * fb_weight)
                if bump > 0:
                    item.score += bump
                    item.reasons.append(f"Cross-mission feedback boost (prior={prior:.2f}).")
                    item.signals.add("feedback:prior")

    ranked_all = sorted(candidates.values(), key=lambda item: (-item.score, item.skill.name))
    contextual = [item for item in ranked_all if _is_contextual(item)]
    default_names = {
        str(name).strip()
        for name in (cfg.get("default_enabled", []) or [])
        if str(name).strip()
    }
    selected: list[_Candidate] = []
    if sticky_defaults and default_names:
        # Keep configured defaults across re-selections (safety-relevant
        # methodology must not be rotated out as the assessment evolves).
        for item in ranked_all:
            if item.skill.name in default_names:
                selected.append(item)
    for item in contextual[:min_contextual]:
        if item in selected:
            continue
        selected.append(item)
    for item in ranked_all:
        if item in selected:
            continue
        if len(selected) >= max_active:
            break
        selected.append(item)
    ranked = selected[:max_active]
    skills = tuple(item.skill for item in ranked)
    activations = tuple(
        SkillActivation(
            name=item.skill.name,
            reason=_merge_reasons(item.reasons),
            source="+".join(sorted(item.sources)),
            matched_tags=tuple(sorted(item.tags)),
            risk_level="attack-advisory" if _looks_attack_only(item.skill) else "advisory",
            score=item.score,
            signals=tuple(sorted(item.signals)),
        )
        for item in ranked
    )
    include_metadata = bool(cfg.get("include_metadata", False))
    prompt_context = render_skill_context(
        skills,
        reasons={activation.name: activation.reason for activation in activations},
        max_chars_per_skill=max_chars_per_skill,
        max_total_chars=max_total_chars,
        include_metadata=include_metadata,
    )
    return SkillSelection(skills=skills, activations=activations, prompt_context=prompt_context, errors=registry.errors)


@dataclass
class _Candidate:
    skill: LoadedSkill
    score: int
    reasons: list[str] = field(default_factory=list)
    sources: set[str] = field(default_factory=set)
    tags: set[str] = field(default_factory=set)
    signals: set[str] = field(default_factory=set)


def _tag_signals(
    *,
    goal_text: str,
    service_values: Iterable[str],
    cve_text: str,
    tool_text: str,
    context_text: str,
    mode: str,
) -> dict[str, set[str]]:
    tags: dict[str, set[str]] = {}

    def mark(tag: str, signal: str) -> None:
        tags.setdefault(tag, set()).add(signal)

    mark("safety", "context:safety")
    mark("mcp", "context:mcp")
    if mode == "recon":
        for tag in ("reconnaissance", "nmap", "network-security"):
            mark(tag, "mode:recon")
    elif mode == "attack":
        for tag in ("exploit-research", "vulnerability-scanning"):
            mark(tag, "mode:attack")
    for key, mapped in _GOAL_TAGS.items():
        if key in goal_text:
            for tag in mapped:
                mark(tag, f"goal:{key}")
    for service in service_values:
        service_text = str(service).lower()
        for key, mapped in _SERVICE_TAGS.items():
            if key in service_text:
                for tag in mapped:
                    mark(tag, f"service:{key}")
    for cve in re.findall(r"\bcve-\d{4}-\d+\b", cve_text + " " + context_text):
        for tag in ("cve", "vulnerability-scanning", "exploit-research"):
            mark(tag, f"cve:{cve.upper()}")
    combined_tool_text = tool_text + " " + context_text
    if "nmap" in combined_tool_text:
        for tag in ("nmap", "network-security", "reconnaissance"):
            mark(tag, "tool:nmap")
    if "searchsploit" in combined_tool_text or "exploit-db" in combined_tool_text:
        for tag in ("exploit-research", "cve"):
            mark(tag, "tool:exploit-search")
    return tags


def _looks_attack_only(skill: LoadedSkill) -> bool:
    haystack = " ".join([skill.name, *normalized_skill_tags(skill.metadata.tags)]).lower()
    return any(term in haystack for term in _ATTACK_ONLY_TERMS)


def _is_contextual(candidate: _Candidate) -> bool:
    return bool(candidate.sources & _CONTEXTUAL_SOURCES)


def _source_from_signals(signals: Iterable[str]) -> str:
    prefixes = {signal.split(":", 1)[0] for signal in signals}
    for source in ("service", "cve", "goal", "tool"):
        if source in prefixes:
            return source
    return "context"


def _merge_reasons(reasons: list[str]) -> str:
    seen: list[str] = []
    for reason in reasons:
        if reason not in seen:
            seen.append(reason)
    return " ".join(seen[:3])


def _positive_int(value: Any, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default
