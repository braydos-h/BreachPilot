---
title: "Tool Family: assessment-state"
sources:
  - tools/mcp_tools/assessment_state.py
  - tools/assessment_state.py
  - tools/attack_modules/
  - tools/attack_planner.py
  - tools/skill_registry_cache.py
  - tools/kernel/allowlist.py
  - tools/kernel/audit.py
tests:
  - tests/test_assessment_state.py
  - tests/test_mcp_tool_registration.py
subsystem: mcp
---

# Tool Family: assessment-state

- **Registration source:** `tools/mcp_tools/assessment_state.py:109 register_assessment_state_tools(mcp, *, ctx)` — auto-discovered, always registered (no config gate). Six tools give the model ONE compact run-state view plus capability discovery; two writers mutate LLM-owned state files.
- **Design:** read-mostly (§8/§16 capability upgrade) — `query_capabilities`/`get_capability_details` are target-free `@audit_tool`; the 4 target-scoped tools are `@require_allowlist()` + writers add explicit `_check_allowlist` re-validation inside the body (defense-in-depth because store path is LLM-influenced — the `run_campaign_step` precedent).

## Tools Exported (6)

| Tool | Gate | Params | Result Shape | Notes |
|------|------|--------|--------------|-------|
| `get_assessment_state` | `@require_allowlist()` | `target_ip: str` | `ASSESSMENT_STATE:\nTARGET: ...\nGOAL: ...\nPHASE: ...\nPLAN: phase=... steps=N done=N ok=N ready=[...] blocked=[...] failed=[...]\nRECON: os=... services=N cves=N (+ SERVICES/CVES lines)\nHYPOTHESES: N open / total (+ [id] status (conf) statement[:80])\nCREDENTIALS_AVAILABLE: N\nACTIVITY: tool_calls=N blocked=N (+ BY_TOOL top10, RECENT 15 refs)` | `aggregate_state(target_ip, workspace, config)` (`tools/assessment_state.py`) merges goal/phase, plan DAG, newest `recon_result.json`, assessment store hypotheses, credential vault count, and audit rollup. `_format_state_block` (`assessment_state.py:47-106`). Never emits raw command/args. |
| `query_capabilities` | `@audit_tool` | `scope: str="modules"` (`modules|tools|skills`), `service: str=""` (module filter) | `CAPABILITIES: scope=modules\n- name | phase=... cost=... ro=bool requires=... produces=...\nTOTAL: N` or `scope=tools\nCOUNT: N\n- tool_name...` or `scope=skills\nCOUNT: N\n- name | tags=... | desc` | `modules`: `list_modules()` filtered by `service` substring against `mod.target_services` (lowercased) via `_service` set check; each `mod.capability_record()` reports `requires/produces`. `tools`: introspects `mcp._tool_manager._tools` name→Tool via `_registered_tool_names` (`assessment_state.py:30-37`, sync read of `__dict`). `skills`: `get_registry(...).list_skills()` capped 50; best-effort try/except. Unknown scope → `BLOCKED: unknown scope ...`. |
| `get_capability_details` | `@audit_tool` | `name: str`, `scope: str="modules"` (`modules|skills`) | `CAPABILITY_DETAILS: scope=modules\nNAME: ...\nREQUIRES: ...\nAPPLICABILITY_SCORE: N\nREASONS:\n  - ...\nPENALTIES:\n  - ...` or `scope=skills` with `NAME/DESCRIPTION/DOMAIN/TAGS/VERSION/MAYBE/NIST_CSF/MITRE_ATTACK/PATH` | `modules`: `get_module(name)` must exist else `module not found`; builds empty `ModuleContext(target_ip="")` for `applicability_explain` to show score/reasons. `skills`: `get_registry(...).get(name)` else `skill not found` / `registry unavailable`. |
| `get_evidence` | `@require_allowlist()` | `target_ip`, `limit: int=25` (1..200), `tool: str=""` (filter by name) | `EVIDENCE:\nCOUNT: N\n- exploit_audit:ip:attempt_id tool=name status=blocked|completed duration=...` (+ `(no audit entries for this target)` when empty) | Reads `workspace/exploit_audit.jsonl` line-by-line, `json.loads`, filters `rec["target_ip"] == target_ip`, skips `status=="started"`, optional `tool` lower equality, emits `attempt_id/target_ip/status/duration` refs only — never `command/args` (may contain secrets). Last `max_items` rows kept. `OSError` → `ERROR: could not read audit trail`. |
| `record_hypothesis` | `@require_allowlist()` + `_check_allowlist_explicit` re-validate | `target_ip`, `statement: str`, `confidence: float=0.5`, `expected_evidence: str=""` (newline CSV), `created_from: str=""` | `HYPOTHESIS_RECORDED:\nID: ...\nTARGET: ...\nCONFIDENCE: 0.00\nSTATUS: ...` or `BLOCKED: ...` | Loads `AssessmentStateStore(workspace).load(target_ip)`, splits `expected_evidence` by lines non-empty trimmed, `state.add_hypothesis(statement, confidence, expected_evidence, created_from)`, `store.save(state)`. Path `plans/<ip>_assessment.json` is LLM-influenced → re-validated via `_check_allowlist_explicit` before write. Empty statement → `BLOCKED`. |
| `update_task` | `@require_allowlist()` + `_check_allowlist_explicit` re-validate | `target_ip`, `step_index: int`, `action: str="complete"` (`complete|fail|cancel|reset`), `success: bool=True`, `summary: str=""`, `failure_class: str=""`, `reason: str=""` | `TASK_UPDATED:\nTARGET: ...\nSTEP: ...\nACTION: ...\nstep N -> done success=...` / `-> failed class=...` / `-> cancelled` / `-> reset` or `NO_PLAN_FOUND` / `BLOCKED: step_index out of range` / `BLOCKED: unknown action` | Loads `AttackPlanner(workspace).load_plan(target_ip)`, validates `step_index` bounds, dispatches `plan.mark_step_done/fail_step/cancel_step/reset_step` then `planner.save_plan(plan)`. Target re-validated before write. |

## Dependencies

- `tools/assessment_state.aggregate_state`, `AssessmentStateStore`
- `tools/attack_planner.AttackPlanner`, `AttackPlan`
- `tools/attack_modules.list_modules`, `get_module`, `ModuleContext`
- `tools/skill_registry_cache.get_registry`, `tools/mcp_tools/registry._skills_config`, `_truncate_text`, `_positive_int`
- `tools/kernel/allowlist._check_allowlist`, `is_target_in_allowlist`

## Config

- `exploit.require_explicit_allowlist`, `exploit.allowed_targets`
- `skills.*` — reused for `query_capabilities scope=skills` registry roots

## Auditing

- `query_capabilities` / `get_capability_details` — `@audit_tool` free-text gate.
- Target-scoped tools — `@require_allowlist()` records `started` then `completed|blocked` with redacted args; writer tools add a second explicit allowlist check inside; `get_evidence` never emits secrets, only refs with `target_ip:attempt_id`.

## Validation

- Empty `statement` → `BLOCKED`; out-of-range `step_index` → `BLOCKED`; unknown `action/scope` → `BLOCKED: unknown ...`.
- Plan file path derived from `target_ip` — allowlist re-validated before any write to prevent LLM widening the store to another IP.

## Tests

- `tests/test_assessment_state.py` — `aggregate_state` snapshot, `AssessmentStateStore` round-trip
- `tests/test_mcp_tool_registration.py` — discovery sanity; capability module tests cover `capability_record`/`applicability_explain`

## Related Docs

- `docs/architecture.md` — Capability Model / Task Graph / AssessmentState
- `docs/mcp/tool-families/attack-modules.md` — attack planner that these tools mutate
