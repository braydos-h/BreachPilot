# 29. Evidence provenance should be immutable

| Field | Value |
| --- | --- |
| Status | DONE (owner: Muse Spark, completed: 2026-09-14 — revalidated) |
| Suggested priority | P1 |
| Suggested horizon | Backlog |
| Theme | Product and assessment workflows |
| Dependencies | [#28](../03-product-and-assessment-workflows/28-make-evidence-excellent.md) |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [ ] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [ ] Add or update focused tests and evaluation coverage where applicable.
- [ ] Update generated and user-facing docs/config contracts where applicable.
- [ ] Record completion evidence below and update [the backlog index](../README.md).

## Audit recommendation

You already have tamper-evident audit concepts.

Extend that philosophy to finding evidence.

Use content-addressed artifacts:

```text
sha256(data) → evidence ID
```

Report files reference hashes.

This lets somebody later prove:

> the HTML response in the PDF is the same artifact originally collected during the assessment.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: 2026-09-14 (revalidation)
- Design/issue: Wave 4 — tamper-evident provenance
- Commits/PRs: none; revalidation: content-hash dedup store (EvidenceStoreV2.put
  idempotent), ProvenanceChain/Tracker, SHA-256 audit chain on every action
- Tests/evaluations: evidence suites green
- Documentation: n/a
- Follow-ups: none open; keep every new surface hash-chained.

