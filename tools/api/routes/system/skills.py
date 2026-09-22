"""System routes: skill catalog, detail, search, install, and remove.

Split of ``tools/api/routes/system.py`` (p2-02) — endpoint paths, auth,
and bodies unchanged; former ``create_router`` closures now read ``ctx``.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from ._shared import (
    SystemContext,
    _plugin_skill_dirs,
    _resolve_skill_dir,
    _validate_skill_name,
)

__all__ = ["register"]


def _skill_writable_root(ctx: SystemContext) -> Path:
    """Return the first configured skills.roots entry, resolved against the repo base.

    The repo base is the config file's parent dir (matches how load_config and
    skill_registry_cache resolve relative roots). Raises 400 if no root is
    configured or it is not a writable directory.
    """
    from tools.api.errors import APIError

    skills_cfg = ctx.config.get("skills", {}) or {}
    roots = skills_cfg.get("roots") or ["skills"]
    if not isinstance(roots, list) or not roots:
        raise APIError("invalid_config", "skills.roots is empty.", status_code=400)
    first = Path(str(roots[0]))
    if not first.is_absolute():
        first = ctx.config_path.parent / first
    try:
        first = first.resolve()
    except OSError as exc:
        raise APIError("invalid_config", f"Cannot resolve skills root: {exc}", status_code=400)
    if not first.is_dir():
        raise APIError("invalid_config", f"Skills root is not a directory: {first}", status_code=400)
    return first


def register(router: APIRouter, ctx: SystemContext) -> None:
    """Mount the skills endpoints (paths/auth unchanged)."""

    @router.get("/skills")
    async def list_skills(auth: str = Depends(ctx.require_auth)) -> dict[str, Any]:
        """List runtime skills catalog."""
        try:
            from tools.skill_registry_cache import get_registry

            reg = get_registry(ctx.config)
            skills = [
                {"name": s.name, "description": s.metadata.description, "tags": list(s.metadata.tags or [])}
                for s in reg.list_skills()
            ]
            return {"skills": skills}
        except Exception as exc:
            return {"skills": [], "error": f"{type(exc).__name__}: {exc}"}

    @router.get("/skills/search")
    async def search_skills(q: str = "", auth: str = Depends(ctx.require_auth)) -> dict[str, Any]:
        """Search runtime skills by query."""
        try:
            from tools.skill_registry_cache import get_registry

            reg = get_registry(ctx.config)
            results = reg.search(q) if q else reg.list_skills()
            return {"results": [{"name": s.name, "description": s.metadata.description} for s in results[:20]]}
        except Exception as exc:
            return {"results": [], "error": f"{type(exc).__name__}: {exc}"}

    @router.get("/skills/{name}")
    async def get_skill(name: str, auth: str = Depends(ctx.require_auth)) -> dict[str, Any]:
        """Return a single runtime skill's sanitized body + sections + references."""
        try:
            from tools.skill_registry_cache import get_registry

            reg = get_registry(ctx.config)
            skill = reg.get(name)
            if skill is None:
                raise HTTPException(status_code=404, detail="Skill not found")
            return {
                "name": skill.name,
                "description": skill.metadata.description,
                "body": skill.body,
                "sections": skill.sections,
                "tags": list(skill.metadata.tags or []),
                "references": [str(r) for r in skill.metadata.references],
                "nist_csf": list(skill.metadata.nist_csf or []),
                "mitre_attack": list(skill.metadata.mitre_attack or []),
                "domain": skill.metadata.domain,
                "subdomain": skill.metadata.subdomain,
                "version": skill.metadata.version,
            }
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Could not load skill: {exc}")

    # ── Skill install / remove (write path) ──────────────────────────────────────
    # Skills are advisory-only markdown guidance imported into the LLM system prompt.
    # Install writes a new SKILL.md under the first configured skills.roots dir;
    # remove deletes the skill's directory. Both paths guard against path traversal
    # (regex on the name + resolve()-based containment under the chosen root) and
    # refuse to touch plugin-contributed skill dirs (only configured roots are
    # writable). parse_skill_file validates on write so malformed skills never land
    # on disk; the registry cache is cleared so the next read reloads from disk.

    @router.post("/skills")
    async def install_skill(request: Request, auth: str = Depends(ctx.require_auth)) -> dict[str, Any]:
        """Install a new skill by writing SKILL.md under the writable skills root.

        Body: {name: str, markdown: str}. The name is validated and the markdown is
        parsed on write -- a malformed skill (bad front matter, empty name, etc.)
        is rejected and the created directory is cleaned up so nothing broken
        lands on disk. The registry cache is cleared so the next /skills read
        reflects the new file.
        """
        from tools.api.errors import APIError
        from tools.skill_registry import parse_skill_file
        from tools.skill_registry_cache import clear_cache

        body = await request.json()
        if not isinstance(body, dict):
            raise APIError("invalid_body", "Expected a JSON object.", status_code=400)
        name = _validate_skill_name(str(body.get("name") or ""))
        markdown = body.get("markdown")
        if not isinstance(markdown, str) or not markdown.strip():
            raise APIError("invalid_body", "markdown must be a non-empty string.", status_code=400)

        root = _skill_writable_root(ctx)
        target_dir = _resolve_skill_dir(name, root)
        if target_dir.exists():
            raise APIError("skill_exists", f"Skill '{name}' already exists.", status_code=409)

        skill_file = target_dir / "SKILL.md"
        tmp_file = target_dir.with_name(f".{target_dir.name}.tmp")
        created_dir = False
        try:
            target_dir.mkdir(parents=True)
            created_dir = True
            # Write via temp file then atomic replace, mirroring config write style.
            tmp_file.write_text(markdown, encoding="utf-8")
            os.replace(tmp_file, skill_file)
            # Validate on write: parse the file we just wrote. On failure, clean up.
            try:
                parsed = parse_skill_file(skill_file, root=root)
            except Exception as exc:
                raise APIError("invalid_skill", f"Skill markdown is invalid: {exc}", status_code=400)
            # Enforce dir name == front-matter name so the registry (which keys on
            # the front-matter name) indexes the skill under the same name the
            # client used -- otherwise DELETE /skills/{name} and config toggles
            # would target the wrong identifier.
            if parsed.name != name:
                raise APIError(
                    "invalid_skill",
                    f"Front-matter name '{parsed.name}' does not match the requested name '{name}'.",
                    status_code=400,
                )
            clear_cache()
            return {
                "name": parsed.name,
                "description": parsed.metadata.description,
                "tags": list(parsed.metadata.tags or []),
            }
        except APIError:
            # Clean up any partial state on validation/config errors.
            if created_dir and target_dir.exists():
                shutil.rmtree(target_dir, ignore_errors=True)
            if tmp_file.exists():
                try:
                    tmp_file.unlink()
                except OSError:
                    pass
            raise
        except Exception as exc:
            if created_dir and target_dir.exists():
                shutil.rmtree(target_dir, ignore_errors=True)
            if tmp_file.exists():
                try:
                    tmp_file.unlink()
                except OSError:
                    pass
            raise APIError("install_failed", f"Could not install skill: {exc}", status_code=500)

    @router.delete("/skills/{name}")
    async def remove_skill(name: str, auth: str = Depends(ctx.require_auth)) -> dict[str, Any]:
        """Delete a skill's directory from the writable skills root.

        Refuses to delete skills that resolve to plugin-contributed roots (those
        are read-only). Path traversal is blocked by _resolve_skill_dir's
        containment check. Clears the registry cache so the next /skills read
        reflects the deletion.
        """
        from tools.api.errors import APIError
        from tools.skill_registry_cache import clear_cache

        cleaned = _validate_skill_name(name)
        root = _skill_writable_root(ctx)
        target_dir = _resolve_skill_dir(cleaned, root)
        if not target_dir.exists():
            raise HTTPException(status_code=404, detail=f"Skill '{cleaned}' not found")
        # Reject deletion of plugin-contributed skill dirs (defence in depth).
        plugin_dirs = _plugin_skill_dirs()
        if any(str(target_dir).startswith(pd) for pd in plugin_dirs):
            raise APIError(
                "skill_not_writable",
                "Cannot delete skills from plugin-contributed directories.",
                status_code=400,
            )
        try:
            shutil.rmtree(target_dir)
        except OSError as exc:
            raise APIError("remove_failed", f"Could not delete skill: {exc}", status_code=500)
        clear_cache()
        return {"name": cleaned, "deleted": True}
