# 20. "Guided" should probably become the default user experience

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14 — survey done) |
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

The current README says Attack means `full_access`, with in-scope actions auto-approved.

That makes sense for your lab-focused architecture.

For broader adoption, I would expose three clear user-facing modes:

```text
RECON
No exploitation.

GUIDED
Autonomous investigation.
Approval at meaningful impact boundaries.

AUTONOMOUS
Full in-scope operation inside enforced sandbox.
```

Not approvals for every command—that becomes unusable.

Approval should be based on **effects**:

```text
credential use
state modification
account creation
persistence
DoS-like load
destructive operation
pivot/lateral movement
sensitive data extraction
```

This also lets teams gradually build confidence before using autonomous mode.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: survey slice (no code change yet)
- Design/issue: Wave 6 — Guided as default, effect-based approvals
- Commits/PRs: none yet; revalidation: mode/experience default not assessed
  beyond routes present
- Tests/evaluations: n/a
- Documentation: n/a
- Follow-ups: default-mode decision + effect-based approval UX + journey test.

