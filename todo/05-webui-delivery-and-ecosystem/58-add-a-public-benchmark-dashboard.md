# 58. Add a public benchmark dashboard

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14 — internal dashboard exists, public pending) |
| Suggested priority | P1 |
| Suggested horizon | 90-day |
| Theme | WebUI, delivery, and ecosystem |
| Dependencies | [#02](../01-strategy-and-evaluation/02-live-autonomous-evaluation-needs-to-become-the-centre-of-development.md), [#03](../01-strategy-and-evaluation/03-add-a-breachpilot-capability-matrix.md), [#44](../04-runtime-governance-and-ci/44-containers-should-be-immutable-by-digest-for-releases.md) |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [ ] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [ ] Add or update focused tests and evaluation coverage where applicable.
- [ ] Update generated and user-facing docs/config contracts where applicable.
- [ ] Record completion evidence below and update [the backlog index](../README.md).

## Audit recommendation

This could materially improve adoption.

For every tagged release:

```text
v0.69
────────────────────
Web benchmark        77%
API benchmark        69%
Network benchmark    61%
Auth benchmark       52%

False compromise     1.2%
Median actions       32
Median duration      9m
Scope escapes        0

Model: ...
Sandbox: sha256...
```

This is much more persuasive than marketing copy.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: revalidation slice (no code change yet)
- Design/issue: Wave 7 (90-day) — immutable evaluation data published
- Commits/PRs: none yet; revalidation: Benchmarks pages + report rendering
  exist in WebUI; no public/immutable published dashboard found
- Tests/evaluations: n/a
- Documentation: n/a
- Follow-ups: publish versioned results with reproducible configuration.

