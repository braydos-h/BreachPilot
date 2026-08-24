---
title: "Tool Family: runtime-skills"
sources:
  - tools/mcp_tools/runtime_skills.py
  - tools/skill_registry.py
  - tools/skill_registry_cache.py
  - tools/mcp_tools/registry.py
tests:
  - tests/test_mcp_runtime_skills.py
  - tests/test_mcp_tool_registration.py
subsystem: mcp
---

# Tool Family: runtime-skills

- **Registration source:** `tools/mcp_tools/runtime_skills.py:8 register_runtime_skill_tools(mcp, *, ctx)` — auto-discovered but **conditionally registers** only when `_runtime_skills_enabled(config)` (`tools/mcp_tools/registry.py:271-273`): `skills.enabled: true` **and** `skills.allow_model_lookup: true`. Otherwise no tools are added.
- **Gate:** all `@audit_tool` (local read-only methodology catalog; never changes scope/permission/approval).

## Tools Exported (4) — conditional

| Tool | Params | Result Shape | Notes |
|------|--------|--------------|-------|
| `list_runtime_skills` | `include_maybe: bool=False`, `limit: int=50` (capped 1..200) | `RUNTIME_SKILLS:\n- name maybe? | tags: ... | desc[:240]` + `WARNINGS: N skill file(s) could not be loaded.` | `_skill_registry()` via `get_registry({"skills": skills_cfg}, base_dir=Path.cwd())` (process-level cache shared with main loop/swarm). Filters `maybe` skills unless `include_maybe` or `skills.maybe_enabled: true`. Truncates desc 240 chars. |
| `search_runtime_skills` | `query: str`, `tags: str=""` (comma/space CSV), `include_maybe=False`, `limit=10` (capped 1..25) | `RUNTIME_SKILL_SEARCH:` + matches `name | tags | desc[:300]` or `no matches.` | Parses `tags` via `re.split(r"[,\\s]+")`; calls `registry.search(query, tags, include_maybe, limit)` lexical+field-weighted over `SKILL.md` frontmatter. |
| `load_runtime_skill` | `name: str`, `reason: str=""` | `RUNTIME_SKILL_LOAD: loaded\nNAME: ...\nPATH: ...\nSAFETY: Advisory only; scope, ... still apply.\n\n<rendered markdown>` or `not found: ...` / `blocked: ... is under maybe/ and maybe_enabled is false.` | `registry.get(name)` exact; `skills.maybe_enabled` gates `maybe`; `max_chars_per_skill = skills.max_chars_per_skill` (default 2500 via `_positive_int`) and `render_skill_context([skill], reasons, max_chars_per_skill, max_total_chars)`. |
| `list_skill_references` | `name: str` | `RUNTIME_SKILL_REFERENCES: name\n- references/*.md\nNIST CSF: ...\nMITRE ATT&CK: ...` or `... has no references/*.md files.` / `not found: ...` / `listing disabled by skills.allow_reference_listing.` | Requires `skills.allow_reference_listing: true` (default true) else blocked. Surfaces `metadata.references` paths only — not contents — plus `nist_csf`/`mitre_attack`. |

## Dependencies

- `tools/skill_registry_cache.get_registry`, `tools/skill_registry.load_skill_registry`, `render_skill_context`
- `tools/mcp_tools/registry._skills_config` (overlay `CONFIG_SCHEMA.skills`), `_runtime_skills_enabled`, `_positive_int`, `_truncate_text`
- `tools/config_manager.CONFIG_SCHEMA`

## Config

- `skills.enabled: bool` (default true), `skills.allow_model_lookup: bool` (default true) — both required for enable
- `skills.maybe_enabled: bool` (default false) — gate `maybe/` skills
- `skills.allow_reference_listing: bool` (default true) — gates `list_skill_references`
- `skills.max_chars_per_skill: int` (default 2500) — render cap
- `skills.roots: list[str]` (default `["skills"]`) — catalog discovery

## Auditing

- All `@audit_tool` with `_redact_args` (no secrets in these params); `reason` not wholesale-redacted but still content-masked if it contained an inline cred shape.
- Advisory only disclaimer included in `load_runtime_skill` output.

## Validation

- `limit` clamped via `_positive_int` + `max(1, min(...))`.
- `maybe` gate checked both in list and load.
- `name` exact match required; `search` returns empty string when no matches (`no matches.` sentinel).

## Tests

- `tests/test_mcp_runtime_skills.py:67,90,121,140,150,171,183,198` — list/search/load + audit, disabling via `skills.enabled: false` / `allow_model_lookup: false`, `list_skill_references` paths / unknown / disabled, `references` not read into context, metadata parsing (nist_csf/mitre)
- `tests/test_mcp_tool_registration.py` — expects `list_runtime_skills`, `search_runtime_skills`, `load_runtime_skill` when enabled

## Related Docs

- `docs/skills.md` / `docs/skill-authoring.md` — skill catalog authoring
- `docs/mcp/registration.md`
