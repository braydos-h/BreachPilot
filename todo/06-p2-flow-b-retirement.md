# P2 — Retire Flow B incrementally

Owner: _unassigned_  
Tracking issue/PR: _not created_  
Status: Blocked by reliable Flow A live evaluation

## Goal

Remove the frozen legacy orchestration path after identifying its remaining
consumers and proving that Flow A covers required behavior.

## Why this matters

Two execution models increase the chance that state handling, sandboxing,
outcome classification, reporting, and tool behavior diverge. Flow A is the
canonical product path; Flow B should remain frozen until it can be retired,
not extended.

## Tasks

- [ ] Inventory direct and indirect imports of root compatibility shims and
  `legacy.*` modules.
- [ ] Identify external users, scripts, tests, docs, data migrations, and report
  formats that still rely on Flow B.
- [ ] Classify each dependency as migrate, preserve temporarily, or remove.
- [ ] Map required Flow B behavior to a tested Flow A equivalent.
- [ ] Add missing Flow A characterization/live-eval coverage before migration.
- [ ] Publish a deprecation timeline and upgrade instructions.
- [ ] Remove consumers in small batches, preserving schema compatibility where
  explicitly required.
- [ ] Delete compatibility shims only after their announced support window.
- [ ] Remove dead Flow B docs, tests, and configuration after the code is gone.
- [ ] Re-run docs truth guards and package smoke tests after each phase.

## Constraints

- Do not edit frozen Flow B safety files as part of unrelated work.
- Do not delete `db.py` or shared schemas until every Flow A/shared consumer is
  identified.
- Do not begin removals solely to reduce line count; require migration evidence.

## Acceptance criteria

- Every remaining Flow B consumer is named and has a disposition.
- Required behaviors are covered by Flow A tests and live evaluation.
- Users receive a documented migration path and deprecation window.
- Removal occurs incrementally without weakening scope, evidence, or reporting
  guarantees.
- The final architecture and user docs describe one execution model.

