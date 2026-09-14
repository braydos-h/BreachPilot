# 74. Secrets should be opaque references

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14 — vault solid, true opacity pending) |
| Suggested priority | P1 |
| Suggested horizon | Backlog |
| Theme | Data, security, and release |
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

- [ ] model transcripts;
- [ ] reports;
- [ ] audit logs;
- [ ] peer-agent context;
- [ ] external model APIs.

## Audit recommendation

The model rarely needs to see:

```text
hunter2
```

It needs:

```text
credential://target/admin-1
```

The tool executor resolves the secret only at execution.

This reduces accidental leakage into:

* model transcripts;
* reports;
* audit logs;
* peer-agent context;
* external model APIs.

Expand your credential store around this principle.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: revalidation slice (no code change yet)
- Design/issue: Wave 3 — raw credentials never reach model/audit/report surfaces
- Commits/PRs: none yet; revalidation: Fernet vault at rest, masked summaries by
  default, include_secret gated on username + full_access; but reveal still
  places cleartext in model context (reference, not capability)
- Tests/evaluations: credential suites green in CI (Tier 1)
- Documentation: n/a
- Follow-ups: opaque secret handles resolved only inside authorized executors;
  audit/report/peer-agent surfaces keep handles.

