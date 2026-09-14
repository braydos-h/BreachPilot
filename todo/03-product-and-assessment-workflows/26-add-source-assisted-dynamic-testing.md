# 26. Add source-assisted dynamic testing

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14 — gap confirmed) |
| Suggested priority | P1 |
| Suggested horizon | 90-day |
| Theme | Product and assessment workflows |
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

Another major opportunity:

```text
Git repository
      +
Running staging application
      ↓
BreachPilot
```

Use source context only for hypothesis generation:

```text
routes
API schemas
ORM models
authorization middleware
dangerous sinks
feature flags
```

Then **prove the vulnerability dynamically**.

Don't simply report SAST matches.

This gives you a strong combination:

> source-assisted autonomous black-box verification.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: revalidation slice (no code change yet)
- Design/issue: Wave 5 (90-day) — repo + target → hypotheses → dynamic proof
- Commits/PRs: none yet; revalidation: no source-assisted flow found
- Tests/evaluations: n/a
- Documentation: n/a
- Follow-ups: source-sink hypothesis generation feeding HypothesisState +
  dynamic proof via verify probes.

