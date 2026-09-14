# 32. Create a proper public API contract

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14 — v1 versioned, full contract pending) |
| Suggested priority | P1 |
| Suggested horizon | Backlog |
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

You already use `/api/v1`, which is good.

Take it further:

```text
/versioned OpenAPI
idempotency keys
pagination
request IDs
run correlation IDs
stable error codes
webhooks
API deprecation policy
```

XBOW's current public API explicitly versions contracts using dated API versions and support windows. ([XBOW Documentation](https://docs.xbow.com/api/?utm_source=chatgpt.com))

BreachPilot doesn't have to copy date-versioning, but it should promise some compatibility policy before third-party integrations grow.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: revalidation slice (no code change yet)
- Design/issue: Wave 5 — stable versioned public API
- Commits/PRs: none yet; revalidation: /api/v1 versioned, pagination total in
  runs routes, stable error shape (tools/api/errors.py); no published
  deprecation policy, idempotency keys, or webhook contracts found
- Tests/evaluations: n/a
- Documentation: docs/api.md exists (needs contract chapter)
- Follow-ups: errors/pagination/idempotency/webhooks/deprecation policy doc +
  contract tests.

