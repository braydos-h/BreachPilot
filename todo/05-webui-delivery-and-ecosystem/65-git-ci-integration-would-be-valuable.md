# 65. Git/CI integration would be valuable

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14 — gap confirmed) |
| Suggested priority | P1 |
| Suggested horizon | 90-day |
| Theme | WebUI, delivery, and ecosystem |
| Dependencies | [#05](../01-strategy-and-evaluation/05-build-vulnerability-regression-testing.md), [#32](../03-product-and-assessment-workflows/32-create-a-proper-public-api-contract.md), [#63](../05-webui-delivery-and-ecosystem/63-add-report-diffing.md) |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [ ] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [ ] Add or update focused tests and evaluation coverage where applicable.
- [ ] Update generated and user-facing docs/config contracts where applicable.
- [ ] Record completion evidence below and update [the backlog index](../README.md).

## Audit recommendation

For staging environments:

```text
Pull request
↓
deploy preview
↓
BreachPilot targeted assessment
↓
SARIF / PR status
```

Only fail the PR on:

```text
new independently VERIFIED critical/high finding
```

Not vague model suspicions.

This is an excellent place for your verification model to differentiate the project.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: revalidation slice (no code change yet)
- Design/issue: Wave 5 (90-day) — preview-env assessments failing only on new
  VERIFIED findings at threshold severity
- Commits/PRs: none yet; revalidation: no preview/CI assessment integration found
- Tests/evaluations: n/a
- Documentation: n/a
- Follow-ups: CI action + severity gate + new-vs-baseline finding comparison.

