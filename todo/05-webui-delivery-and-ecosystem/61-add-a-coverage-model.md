# 61. Add a coverage model

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14 — gap confirmed) |
| Suggested priority | P1 |
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

At the end of a run calculate:

```text
Assets discovered            12
Assets assessed              11
Endpoints discovered        194
Endpoints exercised         163
Authenticated coverage       71%
Roles tested                  2/3
Attack families attempted    9/12
Blocked by scope             14 actions
Blocked by missing context    3 paths
```

Do not pretend 100% security.

Show tested surface.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: revalidation slice (no code change yet)
- Design/issue: Wave 4 — honest tested-surface accounting
- Commits/PRs: none yet; revalidation: no coverage model found
- Tests/evaluations: n/a
- Documentation: n/a
- Follow-ups: tested/total surface per asset class feeding gaps (#60) and
  reports (#62).

