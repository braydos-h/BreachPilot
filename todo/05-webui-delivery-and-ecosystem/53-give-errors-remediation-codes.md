# 53. Give errors remediation codes

| Field | Value |
| --- | --- |
| Status | DONE (owner: Muse Spark, completed: 2026-09-14 — registry slice; UI rendering pending) |
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

Instead of:

```text
Docker unavailable
```

return:

```text
BP-SBX-003
Sandbox worker image missing.

Run:
docker build ...

Docs:
Sandbox → Worker image
```

Stable codes dramatically improve supportability.

You already have structured `SANDBOX_*` classes; generalize the pattern.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: registry slice done 2026-09-14
- Design/issue: Wave 6 — one code table for backend + UI
- Commits/PRs: working-tree: tools/api/remediation.py (new: 12 append-only
  codes with title/fix/docs + fallback), tests/test_api_remediation.py (new,
  3 tests incl. docs-existence guard)
- Tests/evaluations: 3 passed
- Documentation: module contract (codes append-only; UI renders REMEDIATION[code])
- Follow-ups: render remediation in WebUI error surfaces; include code in the
  error envelope at call sites.

