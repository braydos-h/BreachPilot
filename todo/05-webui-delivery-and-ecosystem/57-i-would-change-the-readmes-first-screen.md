# 57. I would change the README's first screen

| Field | Value |
| --- | --- |
| Status | DONE (owner: Muse Spark, completed: 2026-09-14 — via #01) |
| Suggested priority | P2 |
| Suggested horizon | Backlog |
| Theme | WebUI, delivery, and ecosystem |
| Dependencies | None recorded; confirm during scoping. |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [ ] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [ ] Add or update focused tests and evaluation coverage where applicable.
- [ ] Update generated and user-facing docs/config contracts where applicable.
- [ ] Record completion evidence below and update [the backlog index](../README.md).

## Audit recommendation

Something closer to:

```text
BreachPilot
Autonomous penetration testing with proof.

Give BreachPilot an authorized target. It maps the attack surface,
forms hypotheses, executes tests inside a target-locked disposable
sandbox, independently verifies findings, and produces evidence-backed
reports.

Verified benchmark: 74%
False-positive compromise claims: 0.8%
Scope escapes in containment suite: 0
```

Then screenshots.

Then:

```text
How it works
Safety
Benchmarks
Quick start
```

Counts can be lower on the page.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: 2026-09-14 via #01 slice
- Design/issue: Wave 7 — measured claims on the first screen
- Commits/PRs: README headline → reliability-led + generated-catalog links;
  stale 139/153 counts replaced with 146/167 + reliability contract link
- Tests/evaluations: test_readme_headline_leads_with_reliability_not_stale_counts
- Documentation: docs/reliability-metrics.md
- Follow-ups: none open.

