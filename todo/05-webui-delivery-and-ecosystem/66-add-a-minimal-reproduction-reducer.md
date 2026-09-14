# 66. Add a "minimal reproduction" reducer

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14 — pending) |
| Suggested priority | P1 |
| Suggested horizon | Backlog |
| Theme | WebUI, delivery, and ecosystem |
| Dependencies | [#04](../01-strategy-and-evaluation/04-finding-verification-should-become-the-centre-of-the-data-model.md), [#28](../03-product-and-assessment-workflows/28-make-evidence-excellent.md) |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [ ] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [ ] Add or update focused tests and evaluation coverage where applicable.
- [ ] Update generated and user-facing docs/config contracts where applicable.
- [ ] Record completion evidence below and update [the backlog index](../README.md).

## Audit recommendation

For a finding with 20 actions, attempt to reduce it to the smallest deterministic path.

For example:

```text
full autonomous trace:
37 actions

reduced reproduction:
1. POST /login ...
2. GET /api/export?id=...
3. observe another tenant's record
```

That makes reports dramatically more useful.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: revalidation slice (no code change yet)
- Design/issue: Wave 4 — deterministic minimal reproductions from traces
- Commits/PRs: none yet; revalidation: no trace reducer found (counterfactual
  replay exists for failed actions, not finding minimization)
- Tests/evaluations: n/a
- Documentation: n/a
- Follow-ups: delta-debugger over action traces preserving VERIFIED verdict.

