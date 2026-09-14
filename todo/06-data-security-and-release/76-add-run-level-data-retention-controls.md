# 76. Add run-level data retention controls

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14 — gap confirmed, design pending) |
| Suggested priority | P1 |
| Suggested horizon | Backlog |
| Theme | Data, security, and release |
| Dependencies | [#28](../03-product-and-assessment-workflows/28-make-evidence-excellent.md), [#29](../03-product-and-assessment-workflows/29-evidence-provenance-should-be-immutable.md), [#74](../06-data-security-and-release/74-secrets-should-be-opaque-references.md) |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [ ] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [ ] Add or update focused tests and evaluation coverage where applicable.
- [ ] Update generated and user-facing docs/config contracts where applicable.
- [ ] Record completion evidence below and update [the backlog index](../README.md).

## Audit recommendation

Security testing artifacts can be very sensitive.

Support:

```text
retain indefinitely
retain 30 days
delete after report
never store response bodies containing matching secrets
```

Also provide:

> Purge run

which removes:

```text
raw evidence
loot
screenshots
model transcripts
credential-derived artifacts
```

while optionally retaining report metadata.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: revalidation slice (no code change yet)
- Design/issue: Wave 3 — retention policies with verifiable purge
- Commits/PRs: none yet; revalidation: no retention-policy config or purge
  path found (workspace/reports/api_runtime retention is unbounded)
- Tests/evaluations: n/a
- Documentation: n/a
- Follow-ups: run-level retention policy (config + per-run override) with
  cryptographic purge proof; default-sane retention windows.

