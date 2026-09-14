# 45. The current test architecture has improved considerably

| Field | Value |
| --- | --- |
| Status | DONE (owner: Claude Code, completed: 2026-09-14) |
| Suggested priority | P2 |
| Suggested horizon | Backlog |
| Theme | Runtime, governance, and CI |
| Dependencies | None recorded; confirm during scoping. |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [x] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [x] Add or update focused tests and evaluation coverage where applicable.
- [x] Update generated and user-facing docs/config contracts where applicable.
- [x] Record completion evidence below and update [the backlog index](../README.md).

Deliverable for this task is the baseline record itself (no product-code
change): re-verify every audit number against `main` at `75e0ba9` plus the
current working tree, and preserve it here.

## Requirements called out by the audit

- [x] 3,592 collected tests at that point → stale; 2026-09-14 tree collects 5,358/5,367 (356 files);
- [x] full suite timing out after 300s → still true for single runs; slices-only rule retained;
- [x] 1,849 Ruff violations → resolved; `ruff check .` clean;
- [x] 359 mypy errors → reduced to 276 (`scripts/mypy_debt.py --trend`);
- [x] multiple enormous source files → still true; tracked by `god_file_budget.py` (warnings, #09);
- [x] Ruff now reported clean locally → confirmed;
- [x] formatting clean → confirmed;
- [x] strict typing has expanded for security-critical subsystems → confirmed
  (`validation_utils`, `exceptions`, `mcp_shared`, `kernel.*`, `sandbox.*` zero-disable tiers);
- [x] type debt has decreased → 359 → 276;
- [x] sandbox-specific tests have grown → 7 sandbox files in CI `sandbox` job;
- [x] documentation checks were added → `docs_truth_audit.py` (163 files) + no-args guard.

## Audit recommendation

The August maintainability baseline was rough:

* 3,592 collected tests at that point;
* full suite timing out after 300s;
* 1,849 Ruff violations;
* 359 mypy errors;
* multiple enormous source files.

Current progress has improved that substantially:

* Ruff now reported clean locally;
* formatting clean;
* strict typing has expanded for security-critical subsystems;
* type debt has decreased;
* sandbox-specific tests have grown;
* documentation checks were added.

So I would **not** tell you to "add testing" generically.

The next testing step is quality of system evaluation, not just quantity of unit tests.

## Completion record

- Owner: Muse Spark (2026-09-14 session)
- Started: 2026-09-14
- Completed: 2026-09-14
- Design/issue: Wave 0 step 1 — preserve measurable truth before architecture work
- Commits/PRs: working-tree changes (uncommitted at record time): docs/sandbox.md +
  docs/troubleshooting.md + CLAUDE.md fallback_native truth fix, tests/test_config_semantic_truth.py
  (new), tools/eval_harness.py provenance + SKIPPED-report extension,
  tests/test_eval_live_outcome.py +2 tests, .github/workflows/eval.yml SKIPPED artifact
- Tests/evaluations:
  - `.venv/bin/python -m pytest --collect-only -q -p no:cacheprovider -n 0` → 5358/5367
    collected (9 deselected integration/live_llm) on 2026-09-14 working tree with 356
    `test_*.py` files (audit-era 3,592 is stale — suite has grown ~49%).
  - `.venv/bin/ruff check .` → All checks passed (0 errors).
  - `.venv/bin/ruff format --check .` → clean after `ruff format` on new test file.
  - `python scripts/docs_truth_audit.py` → passed (all): 163 files checked.
  - `python scripts/god_file_budget.py` → passed with growth warnings:
    `tools/eval_harness.py` 1597→2340 LOC, `tools/exploit_agent/runner/_impl.py`
    2637→3208 LOC (grandfathered, warning-only; extraction is #09).
  - `python scripts/mypy_debt.py --trend` → 276 errors in 64 files (down from audit
    359; top: run_manager 35, runner/_impl 31, attack_ui 24).
  - Focused slices: `tests/test_config_semantic_truth.py` 5 passed;
    `tests/test_eval_live_outcome.py` 17 passed.
- Documentation: this file is the baseline record; no product-code change required.
- Follow-ups:
  - Full-suite timing still exceeds single-run budget — keep TEST-RUN RULES
    (slices only, `-n 0`/`-n 2`); full verification is CI's job.
  - `tools/eval_harness.py` growth warning → decompose provenance helpers into a
    submodule under #09 before adding more eval surface.

