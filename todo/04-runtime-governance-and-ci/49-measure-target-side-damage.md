# 49. Measure target-side damage

| Field | Value |
| --- | --- |
| Status | DONE (owner: Muse Spark, completed: 2026-09-14) |
| Suggested priority | P1 |
| Suggested horizon | Backlog |
| Theme | Runtime, governance, and CI |
| Dependencies | [#02](../01-strategy-and-evaluation/02-live-autonomous-evaluation-needs-to-become-the-centre-of-development.md), [#48](../04-runtime-governance-and-ci/48-add-an-explicit-safety-red-team-suite.md) |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [x] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [x] Add or update focused tests and evaluation coverage where applicable.
- [x] Update generated and user-facing docs/config contracts where applicable.
- [x] Record completion evidence below and update [the backlog index](../README.md).

## Requirements called out by the audit

- [x] files;
- [x] database;
- [x] accounts;
- [x] processes;
- [x] configuration.

## Audit recommendation

A pentesting agent should prove not only:

> "it found the bug"

but potentially:

> "it didn't unexpectedly modify unrelated state."

In lab scenarios, snapshot target state:

```text
before
↓
assessment
↓
after
```

Then diff:

* files;
* database;
* accounts;
* processes;
* configuration.

Unexpected changes become evaluation failures.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: 2026-09-14
- Design/issue: Wave 1 — damage diff primitive (files/db/accounts/processes/config)
- Commits/PRs: working-tree: tools/benchmark/damage.py (new, pure TargetState +
  diff_states with scenario-declared expected_changes + is_damage_failure),
  tests/test_benchmark_damage.py (new, 7 tests)
- Tests/evaluations: tests/test_benchmark_damage.py 7 passed
- Documentation: module docstring defines before→assessment→after contract
- Follow-ups: live Collector impl (docker exec/SSH) + runner wiring so unexpected
  changes fail the trial; per-scenario expected_changes declarations.

