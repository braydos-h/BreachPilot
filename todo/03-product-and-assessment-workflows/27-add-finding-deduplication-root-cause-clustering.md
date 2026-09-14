# 27. Add finding deduplication/root-cause clustering

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14 — exact dedup exists, clustering pending) |
| Suggested priority | P1 |
| Suggested horizon | Backlog |
| Theme | Product and assessment workflows |
| Dependencies | [#04](../01-strategy-and-evaluation/04-finding-verification-should-become-the-centre-of-the-data-model.md), [#69](../06-data-security-and-release/69-introduce-an-observation-schema.md), [#70](../06-data-security-and-release/70-separate-facts-from-hypotheses.md) |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [ ] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [ ] Add or update focused tests and evaluation coverage where applicable.
- [ ] Update generated and user-facing docs/config contracts where applicable.
- [ ] Record completion evidence below and update [the backlog index](../README.md).

## Audit recommendation

Autonomous scanners can easily generate twelve manifestations of one underlying defect.

Introduce a fingerprint:

```text
weakness class
sink/source
endpoint template
root cause
auth boundary
parameter
```

Then cluster:

```text
Broken tenant authorization
  ├── GET /invoices/{id}
  ├── GET /files/{id}
  ├── PATCH /profile/{id}
  └── DELETE /notes/{id}
```

Report:

> One systemic authorization defect, reproduced across four endpoints.

Much more useful.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: revalidation slice (no code change yet)
- Design/issue: Wave 4 — cluster manifestations by root cause
- Commits/PRs: none yet; revalidation: content-hash exact dedup exists
  (EvidenceStoreV2); no root-cause clustering found
- Tests/evaluations: n/a
- Documentation: n/a
- Follow-ups: root-cause clustering (same service/misconfig/CVE family) +
  manifestation merge with evidence union.

