# 30. Add reproducible "finding bundles"

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14 — replay manifest exists for benchmarks, finding bundles pending) |
| Suggested priority | P1 |
| Suggested horizon | Backlog |
| Theme | Product and assessment workflows |
| Dependencies | [#28](../03-product-and-assessment-workflows/28-make-evidence-excellent.md), [#29](../03-product-and-assessment-workflows/29-evidence-provenance-should-be-immutable.md) |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [ ] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [ ] Add or update focused tests and evaluation coverage where applicable.
- [ ] Update generated and user-facing docs/config contracts where applicable.
- [ ] Record completion evidence below and update [the backlog index](../README.md).

## Audit recommendation

A finding export could be:

```text
BP-2026-0042/
├── finding.json
├── README.md
├── reproduction.yaml
├── request.txt
├── response.txt
├── screenshot.png
├── evidence-manifest.json
└── hashes.txt
```

This is useful for security teams and bug bounty submissions.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: revalidation slice (no code change yet)
- Design/issue: Wave 4 — one artifact reproduces one finding
- Commits/PRs: none yet; revalidation: benchmark replay manifests exist;
  no per-finding bundle (probe + evidence + environment + digest) found
- Tests/evaluations: n/a
- Documentation: n/a
- Follow-ups: finding-bundle schema reusing RunProvenance + damage snapshot.

