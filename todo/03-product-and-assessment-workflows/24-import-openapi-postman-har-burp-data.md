# 24. Import OpenAPI/Postman/HAR/Burp data

| Field | Value |
| --- | --- |
| Status | DONE (owner: Muse Spark, completed: 2026-09-14 — OpenAPI slice; Postman/HAR/Burp pending) |
| Suggested priority | P1 |
| Suggested horizon | 60-day |
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

## Requirements called out by the audit

- [ ] parameter substitutions;
- [ ] role comparisons;
- [ ] object ownership;
- [ ] workflow state;
- [ ] mutation opportunities.

## Audit recommendation

For API/web testing this would substantially increase useful coverage.

A target could be initialized from:

```text
openapi.yaml
collection.json
traffic.har
Burp XML
```

Then build:

```text
API operation graph
      ↓
parameters
auth requirements
schemas
resource IDs
relationships
```

The agent can reason about:

* parameter substitutions;
* role comparisons;
* object ownership;
* workflow state;
* mutation opportunities.

This is more valuable now than another scanner integration.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: OpenAPI slice done 2026-09-14
- Design/issue: Wave 5 — specs become an operation graph, never executed input
- Commits/PRs: working-tree: tools/importers/openapi.py (new: Operation +
  OperationGraph, local-#/-ref only, size/operation caps, auth recorded),
  tests/test_import_openapi.py (new, 5 tests)
- Tests/evaluations: 5 passed (auth override, tags/path linking, ref resolve, file load)
- Documentation: module docstring (untrusted-input rules + #23 wiring note)
- Follow-ups: Postman/HAR/Burp importers on the same Operation shape; session
  profiles (#23) consume requires_auth/auth_schemes.

