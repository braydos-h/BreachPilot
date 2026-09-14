# 25. Add differential authorization testing

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14 — gap confirmed) |
| Suggested priority | P1 |
| Suggested horizon | 60-day |
| Theme | Product and assessment workflows |
| Dependencies | [#23](../03-product-and-assessment-workflows/23-authenticated-web-testing-should-be-a-major-p1.md), [#24](../03-product-and-assessment-workflows/24-import-openapi-postman-har-burp-data.md) |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [ ] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [ ] Add or update focused tests and evaluation coverage where applicable.
- [ ] Update generated and user-facing docs/config contracts where applicable.
- [ ] Record completion evidence below and update [the backlog index](../README.md).

## Audit recommendation

This is a very good fit for autonomous agents.

Example:

```text
GET /api/users/123/orders/88

User A → 200
User B → 200
Anonymous → 401
```

Agent identifies:

```text
resource 88 belongs to A
B obtained it
```

Then independently verifies with additional IDs/objects.

This is much harder for static/template scanning and therefore a good area for BreachPilot to differentiate.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: revalidation slice (no code change yet)
- Design/issue: Wave 5 — independently verified authz differentials
- Commits/PRs: none yet; revalidation: no differential authorization testing
  found (requires #23 profiles + #24 operation graph + oracle verdicts)
- Tests/evaluations: n/a
- Documentation: n/a
- Follow-ups: same-operation × identities matrix with oracle-confirmed
  allow/deny expectations.

