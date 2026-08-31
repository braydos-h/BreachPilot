# Capability Upgrade — Architecture Design (Phase 2 output)

Status: approved-by-author / implemented incrementally. Companion to the audit
reports in `docs/phase1-audit/`.

The capability model described here (declared vs available, capability
records, requires/produces composition) is also the substrate the future
browser-native web agent builds on: prepared seam
`tools/browser/capabilities.py` (stable `browser.*` names, fail-closed
availability) + design doc [docs/browser-agent-design.md](browser-agent-design.md).

Governing principle, forced by the audit: **extend existing seams, build zero
parallel systems.** Every wishlist item below names the existing substrate it
extends.

## The loop the AI should run

```
Operator Goal
      ↓
Assessment State        ← tools/assessment_state.py aggregates plan + recon +
      ↓                    creds + audit + hypotheses (owned) into one snapshot
Planner / Task Graph    ← AttackPlan/AttackStep extended into a real DAG
      ↓                    (depends_on already serialized; add ready_steps(),
Capability Selection       per-step status/hypothesis/priority/failure fields)
      ↓                 ← capability_record() metadata + applicability_explain()
MCP / Attack Module        (score + reasons + penalties), find_producers() for
      ↓                    dynamic composition off requires/produces attrs
Structured Result       ← ModuleResult extended: failure_class, retryable,
      ↓                    confidence, produced_artifacts, follow_ups
Evidence Store          ← existing: exploit_audit.jsonl + workspace artifacts
      ↓                    + plans/<ip>_assessment.json (hypotheses, notes)
State Update            ← update_task / record_hypothesis MCP tools mutate the
      ↓                    plan + assessment JSON (allowlist-gated)
Reflection / Next       ← failure_taxonomy.classify_failure() → recovery action
                           decides retry-with-params / prereq / switch / stop
```

## Component map (wishlist § → substrate → change)

1. **Capability model (§1)** — new class attrs on `AttackModule`
   (`requires`, `produces`, `read_only`, `cost`, `phase_hint`), all defaulted
   `[]`/safe. New method `capability_record()` returns the full machine-
   readable record. `to_json()` stays byte-identical (tests key-pin it).
   `find_producers(kind)` added to `registry.py` for composition discovery.

2. **Applicability explanation (§6)** — `applicability_explain(ctx)` returns
   `ApplicabilityReport(score, reasons, penalties)`; `applicability(ctx)` is
   re-implemented as `applicability_explain(ctx).score` so scoring weights,
   0–100 cap, and the ICS zero-gate stay bit-identical.

3. **ModuleContext (§2)** — additive defaulted fields: `sessions`, `findings`,
   `hypotheses`, `evidence_refs`, `access_achieved`, `privilege_level`,
   `phase`. Orchestrator ctx builders (612/2042) and `run_attack_module` start
   passing what they already hold in `AttackState`. Other constructors default.

4. **Structured results (§7)** — `ModuleResult` gains `failure_class`,
   `retryable`, `confidence`, `produced_artifacts`, `follow_ups`,
   `unlocked_capabilities` (all empty/None defaults; `to_dict` drops empties as
   today; `to_result` reads them back). Adapter contract untouched.

5. **Failure taxonomy (§5)** — NEW single source: `tools/failure_taxonomy.py`
   (`FailureClass` enum, `classify_failure()`, `RecoveryAction` enum,
   `recovery_for()` + hints). `RetryEngine.should_retry`, the exploit loop's
   replan prompts, and the reflection taxonomy express on top of it. The three
   existing classifiers keep their public APIs (tests depend).

6. **Task graph (§3)** — extend `AttackStep` with `hypothesis`, `priority`,
   `status` (pending/running/done/failed/blocked/cancelled), `attempt_count`,
   `failure_class`, `failure_reason`, `capability`, `expected_evidence`,
   `confidence`, `created_from`. Extend `AttackPlan` with `ready_steps()`,
   `next_step()`, `add_step()`, `cancel_step()`, `fail_step()` over the
   existing `depends_on` edges. `to_json`/`from_json` stay tolerant;
   `session_manager.SessionState.plan` embedding keeps loading.

7. **Assessment state store (§2/§11/§16)** — NEW `tools/assessment_state.py`:
   `AssessmentState` (goal, phase, hypotheses, notes, per-run) persisted to
   `<workspace>/plans/<ip>_assessment.json`; `aggregate_state()` reads the
   existing stores (plan JSON, recon_result.json, cred vault summary, audit
   JSONL rollup) and merges with owned hypotheses/notes. Raw output stays in
   artifacts; the snapshot carries only compact refs (evidence IDs =
   `exploit_audit:<target>:<attempt_id>` convention already used).

8. **AI-facing MCP tools (§16)** — NEW `tools/mcp_tools/assessment_state.py`
   registering six tools (double-registration rule: registry `__all__` +
   server register call + docs):
   `get_assessment_state(target_ip)` RA-gated; `query_capabilities(scope,
   service)` + `get_capability_details(name)` audit-gated RO;
   `get_evidence(target_ip, limit, tool)` RA-gated (reuses mitre filtering);
   `record_hypothesis(target_ip, ...)` + `update_task(target_ip, ...)` RA-gated
   (state files are LLM-writable → handler re-validates, the
   run_campaign_step:2516 precedent). Return-block convention:
   `ASSESSMENT_STATE: ...` / `CAPABILITIES: ...` UPPER_SNAKE + KEY: value lines,
   `BLOCKED:`/`ERROR:` prefixes only.

9. **Agent loop integration (§4/§22)** — new tools added to the universal tool
   set (never phase-hidden); new prompt section (kwarg + `""`-when-off, the
   established pattern) on hypothesis-driven workflow; `_blocked_replan_prompt`
   gains the classified failure + recovery hint; decision log hook at the
   outcome-normalization point. All asserted substrings/markers preserved.

10. **Decision log (§17)** — NEW `tools/decision_log.py`, one append-only
    `decision_log.jsonl` per run dir: `{round, tool, reason, failure_class,
    outcome, success, evidence_refs}`. Never raw CoT — concise fields only.

11. **Model-role routing (§13)** — `ModelRouter.get_client_for_role(role,
    fallback=None)` reading `models.roles.<role>` → alias → `get_client`
    (reverse-lookup already handles ids). Default: every role resolves to the
    default alias — byte-identical behavior today. Role call sites opt-in.

12. **Orchestrator upgrades (§5/§9)** — `RetryEngine.should_retry` delegates to
    the taxonomy (permanent classes → no retry; `prerequisite_missing` → emit a
    prerequisite task resolved via `find_producers`); `_module_context` /
    executor ctx gain access/priv/sessions from `AttackState`;
    `max_pivot_depth: 0` and the scope-gate check are untouched.

13. **Module metadata sweep (§19)** — set `requires`/`produces`/`read_only`/
    `cost`/`phase_hint` on the ~75 classes (adds only; no behavior change).
    The composition chains from the attack-modules audit §Q4 become explicit.

14. **Config (§23)** — new `agent` block (budgets/toggles, all defaulting to
    today's behavior) + `models.roles` block; `CONFIG_SCHEMA` entries (auto-
    whitelist), `config.yaml` mirror, defensive `.get` at every consumption
    site (config_cli merges no defaults).

15. **Simulations (§18)** — `tests/test_task_graph_simulations.py`: scripted
    scenario harness driving ready_steps + failure classification + recovery
    over mocked module runs (the 9 scenarios from the prompt).

## Explicitly NOT done (recorded for the summary)

- No new MCP tool rewrites of write/run_python_file (helper-code safety already
  = static body scan + allowlist + verify_poc self-heal; we expose the repair
  budget via config).
- No rewrite of `_DEFAULT_AGENT_MAP` / agent naming (test-locked).
- No Flow B file edits, ever. No target-lock weakening: every new
  target-touching tool uses the same `@require_allowlist` / audit machinery.

## Backwards-compat guardrails observed (from audit §risks)

byte-identical `to_json()` / `applicability` scoring / status-string looseness;
`_sync_patchable_symbols` extended if new patch seams appear; markers
(COMPACTED_CONTEXT etc.) untouched; `_EXC_GROUP_CATCH` in all MCP-adjacent
async code; `PUBLIC_USAGE_FIELDS` append-only; new dataclass fields always
defaulted; monkeypatch shims (`mcp_exploit_server._get_model_router`,
`_run_with_pgrp_timeout`, `_consultation_count`) reused, never bypassed.
