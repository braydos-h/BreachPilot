"""Runtime Skills MCP tool registration."""

from __future__ import annotations

from tools.mcp_tools.registry import *


def register_runtime_skill_tools(mcp: Any, *, ctx: ToolContext) -> None:
    workspace = ctx.workspace
    config = ctx.config
    search = ctx.search
    nvd = ctx.nvd
    researcher = ctx.researcher
    audit_tool = ctx.audit_tool
    require_allowlist = ctx.require_allowlist

    skills_cfg = _skills_config(config)

    def _skill_registry():
        # Shared process-level cache so the MCP tools, main loop, and swarm all
        # read the same registry instead of re-rglobbing the catalog per consumer.
        from tools.skill_registry_cache import get_registry

        return get_registry({"skills": skills_cfg}, base_dir=Path.cwd())

    if _runtime_skills_enabled(config):

        @mcp.tool()
        @audit_tool
        def list_runtime_skills(include_maybe: bool = False, limit: int = 50) -> str:
            """List read-only runtime skills available to guide the assessment. Skills are advisory prompt context only; they do not execute code or change permissions."""
            registry = _skill_registry()
            max_items = max(1, min(_positive_int(limit, 50), 200))
            lines = ["RUNTIME_SKILLS:"]
            count = 0
            for skill in registry.list_skills():
                if skill.metadata.maybe and not (include_maybe or bool(skills_cfg.get("maybe_enabled", False))):
                    continue
                tags = ", ".join(skill.metadata.tags[:8])
                maybe = " maybe" if skill.metadata.maybe else ""
                desc = _truncate_text(skill.metadata.description, 240).replace("\n", " ")
                lines.append(f"- {skill.name}{maybe} | tags: {tags or '(none)'} | {desc}")
                count += 1
                if count >= max_items:
                    break
            if registry.errors:
                lines.append(f"WARNINGS: {len(registry.errors)} skill file(s) could not be loaded.")
            return "\n".join(lines)

        @mcp.tool()
        @audit_tool
        def search_runtime_skills(query: str, tags: str = "", include_maybe: bool = False, limit: int = 10) -> str:
            """Search read-only runtime skills by query text and optional comma-separated tags. Use before load_runtime_skill when the current attack path needs more specific methodology guidance."""
            registry = _skill_registry()
            parsed_tags = [tag.strip() for tag in re.split(r"[,\s]+", tags or "") if tag.strip()]
            found = registry.search(
                query=query or "",
                tags=parsed_tags,
                include_maybe=include_maybe or bool(skills_cfg.get("maybe_enabled", False)),
                limit=max(1, min(_positive_int(limit, 10), 25)),
            )
            if not found:
                return "RUNTIME_SKILL_SEARCH: no matches."
            lines = ["RUNTIME_SKILL_SEARCH:"]
            for skill in found:
                tag_text = ", ".join(skill.metadata.tags[:8])
                desc = _truncate_text(skill.metadata.description, 300).replace("\n", " ")
                lines.append(f"- {skill.name} | tags: {tag_text or '(none)'} | {desc}")
            return "\n".join(lines)

        @mcp.tool()
        @audit_tool
        def load_runtime_skill(name: str, reason: str = "") -> str:
            """Load one read-only runtime skill by exact name. Returns compact markdown methodology guidance. This never executes scripts, enables tools, changes target scope, or changes permission mode."""
            registry = _skill_registry()
            skill = registry.get(name)
            if skill is None:
                return f"RUNTIME_SKILL_LOAD: not found: {name!r}. Use search_runtime_skills first."
            if skill.metadata.maybe and not bool(skills_cfg.get("maybe_enabled", False)):
                return f"RUNTIME_SKILL_LOAD: blocked: {skill.name!r} is under maybe/ and skills.maybe_enabled is false."
            max_chars = _positive_int(skills_cfg.get("max_chars_per_skill"), 2500)
            rendered = render_skill_context(
                [skill],
                reasons={skill.name: reason or "Loaded explicitly by the model for the current assessment step."},
                max_chars_per_skill=max_chars,
                max_total_chars=max_chars,
            )
            return (
                "RUNTIME_SKILL_LOAD: loaded\n"
                f"NAME: {skill.name}\n"
                f"PATH: {skill.metadata.path}\n"
                "SAFETY: Advisory only; scope, permission, approval, command safety, workspace containment, and audit logging still apply.\n\n"
                f"{rendered}"
            )

        @mcp.tool()
        @audit_tool
        def list_skill_references(name: str) -> str:
            """List the reference document paths bundled with a runtime skill (read-only). Returns paths only, never contents -- read a path via the workspace read tools if needed (still subject to approval/allowlist)."""
            if not bool(skills_cfg.get("allow_reference_listing", True)):
                return "RUNTIME_SKILL_REFERENCES: listing disabled by skills.allow_reference_listing."
            registry = _skill_registry()
            skill = registry.get(name)
            if skill is None:
                return f"RUNTIME_SKILL_REFERENCES: not found: {name!r}."
            refs = skill.metadata.references
            if not refs:
                return f"RUNTIME_SKILL_REFERENCES: {skill.name} has no references/*.md files."
            lines = [f"RUNTIME_SKILL_REFERENCES: {skill.name}"]
            for ref in refs:
                lines.append(f"- {ref}")
            if skill.metadata.nist_csf:
                lines.append("NIST CSF: " + ", ".join(skill.metadata.nist_csf))
            if skill.metadata.mitre_attack:
                lines.append("MITRE ATT&CK: " + ", ".join(skill.metadata.mitre_attack))
            return "\n".join(lines)
