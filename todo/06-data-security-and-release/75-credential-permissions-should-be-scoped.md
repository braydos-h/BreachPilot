# 75. Credential permissions should be scoped

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14 — target scoping exists, full matrix pending) |
| Suggested priority | P1 |
| Suggested horizon | Backlog |
| Theme | Data, security, and release |
| Dependencies | [#74](../06-data-security-and-release/74-secrets-should-be-opaque-references.md) |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [ ] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [ ] Add or update focused tests and evaluation coverage where applicable.
- [ ] Update generated and user-facing docs/config contracts where applicable.
- [ ] Record completion evidence below and update [the backlog index](../README.md).

## Audit recommendation

Example:

```text
credential:
  target: api.example.com
  roles: [admin]
  protocols: [https]
  tools: [browser, http]
  allow_model_visibility: false
```

Then a shell tool cannot automatically dump/use every credential simply because the agent knows a credential exists.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: revalidation slice (no code change yet)
- Design/issue: Wave 3 — least-privilege credentials
- Commits/PRs: none yet; revalidation: records carry target_host and confirmed
  state; no role/protocol/tool/visibility scoping matrix found
- Tests/evaluations: n/a
- Documentation: n/a
- Follow-ups: scope matrix (target × role × protocol × tool × visibility) +
  denial tests.

