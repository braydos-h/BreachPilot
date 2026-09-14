# 36. The benchmark suite should test "knowing when to stop"

| Field | Value |
| --- | --- |
| Status | DONE (owner: Muse Spark, completed: 2026-09-14) |
| Suggested priority | P1 |
| Suggested horizon | Backlog |
| Theme | Runtime, governance, and CI |
| Dependencies | [#02](../01-strategy-and-evaluation/02-live-autonomous-evaluation-needs-to-become-the-centre-of-development.md), [#34](../04-runtime-governance-and-ci/34-add-explicit-run-budgets.md) |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [x] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [x] Add or update focused tests and evaluation coverage where applicable.
- [x] Update generated and user-facing docs/config contracts where applicable.
- [x] Record completion evidence below and update [the backlog index](../README.md).

## Requirements called out by the audit

- [x] objective verified;
- [x] branch disproven — secure_web/impossible_sqli negative controls;
- [x] no useful hypothesis remains — empty claim set scores success;
- [ ] budget exhausted; — pending #34 budget trials
- [ ] target unavailable; — INFRA_ERROR path exists, dedicated trials pending
- [ ] policy prevents the remaining paths. — pending scope-gate stop trials

## Audit recommendation

A good autonomous pentester should stop when:

* objective verified;
* branch disproven;
* no useful hypothesis remains;
* budget exhausted;
* target unavailable;
* policy prevents the remaining paths.

Add benchmark cases where the correct output is:

> **No verified vulnerability found.**

Otherwise evaluation rewards activity instead of judgement.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: 2026-09-14
- Design/issue: Wave 0 — stop quality is scored, not just activity
- Commits/PRs: working-tree: eval_targets/secure_web.oracle.json (new, negative_control),
  tools/eval_harness.py score_against_oracle negative-control branch,
  docs/reliability-metrics.md stop section, tests/test_eval_suite.py +2 tests
- Tests/evaluations: tests/test_eval_suite.py 25 passed
- Documentation: docs/reliability-metrics.md §Knowing when to stop
- Follow-ups: live hardened image for secure_web (compose service on :8090);
  budget-exhaustion stop trials under #34; loop-rate dashboards under #58.

