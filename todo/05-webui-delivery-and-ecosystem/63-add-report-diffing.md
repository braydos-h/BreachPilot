# 63. Add report diffing

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14 — gap confirmed) |
| Suggested priority | P1 |
| Suggested horizon | 60-day |
| Theme | WebUI, delivery, and ecosystem |
| Dependencies | [#04](../01-strategy-and-evaluation/04-finding-verification-should-become-the-centre-of-the-data-model.md), [#05](../01-strategy-and-evaluation/05-build-vulnerability-regression-testing.md), [#62](../05-webui-delivery-and-ecosystem/62-reports-need-two-layers.md) |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [ ] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [ ] Add or update focused tests and evaluation coverage where applicable.
- [ ] Update generated and user-facing docs/config contracts where applicable.
- [ ] Record completion evidence below and update [the backlog index](../README.md).

## Audit recommendation

Between runs:

```text
Previous                     Current

SQL injection     OPEN   →   FIXED
IDOR              OPEN   →   OPEN
JWT issue          —     →   NEW
XSS               OPEN   →   REGRESSED
```

This turns BreachPilot into a continuous testing product instead of a single-run tool.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: revalidation slice (no code change yet)
- Design/issue: Wave 4 — diff findings/retest/coverage between assessments
- Commits/PRs: none yet; revalidation: no report diff found (eval baselines have
  check_regression for scores, not findings)
- Tests/evaluations: n/a
- Documentation: n/a
- Follow-ups: finding/retest/coverage diff reusing lifecycle states.

