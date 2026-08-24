---
title: "Tool Family: mitre"
sources:
  - tools/mcp_tools/mitre.py
  - tools/mitre_export.py
  - tools/mitre_technique_map.json
  - tools/kernel/audit.py
tests:
  - tests/test_mitre_export.py
subsystem: mcp
---

# Tool Family: mitre

- **Registration source:** `tools/mcp_tools/mitre.py:15 register_mitre_tools(mcp, *, ctx)` — auto-discovered, always registered.
- **Gate:** `@audit_tool` — local-only (reads `exploit_workspace/exploit_audit.jsonl` filtered by `target_ip`, writes a JSON layer file); no target touch, no network.
- **Purpose:** Map audit trail to MITRE ATT&CK Navigator layer for blue-team handoff.

## Tools Exported (1)

| Tool | Params | Result Shape | Notes |
|------|--------|--------------|-------|
| `export_attack_navigator` | `target_ip: str`, `output_path: str=""` | `MITRE_NAVIGATOR_EXPORT:\nlayer_path: ...\ntechniques: [...] \ntechnique_ids: Txxxx, ...\nOpen the layer JSON in ATT&CK Navigator (https://mitre-attack.github.io/attack-navigator/).` or `BLOCKED: ...` when `result["error"]` | Reads config `mitre.technique_map` (default `tools/mitre_technique_map.json`), `mitre.navigator_output_dir` (default `reports/mitre`), `mitre.include_skill_tags` bool → calls `_export_attack_navigator(target_ip, output_path, technique_map_path, navigator_output_dir, include_skills)`. Tool-name → technique ID mapping via technique map; also merges skill `mitre_attack` tags when `include_skill_tags: true`. Output path coerced under `navigator_output_dir` to prevent traversal. Empty audit trail returns `techniques: []`. Local-only, no target gate but `target_ip` filters the audit log slice. |

## Dependencies

- `tools/mitre_export.export_attack_navigator`
- `tools/mitre_technique_map.json` — curated mapping
- `tools/skill_registry` (when `include_skill_tags: true`)

## Config

- `mitre.technique_map: str` (default `tools/mitre_technique_map.json`)
- `mitre.navigator_output_dir: str` (default `reports/mitre`)
- `mitre.include_skill_tags: bool` (default true) — merges skill ATT&CK tags into layer

## Auditing

- `@audit_tool` — `target_ip`/`output_path` not secret; `started`/`completed|blocked` recorded so layer exports are in the trail.

## Validation

- `target_ip` not allowlist-gated (local read), but downstream export filters by that IP; `output_path` traversal coerced under `navigator_output_dir`.

## Tests

- `tests/test_mitre_export.py` — technique mapping, empty audit, skill-tag merge, output dir coercion

## Related Docs

- `docs/mcp/security.md` — audit trail source
- `tools/mitre_export.py` — mapping logic and Navigator 4.5 layer schema
