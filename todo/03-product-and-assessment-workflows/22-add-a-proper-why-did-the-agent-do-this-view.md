# 22. Add a proper "why did the agent do this?" view

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

For each action, record structured reason codes:

```json
{
  "objective": "validate reset token hypothesis",
  "evidence_refs": ["ev_182", "ev_190"],
  "branch": "auth.reset_predictability",
  "expected_information_gain": "high",
  "risk": "low",
  "alternatives_rejected": [
    "sql_injection",
    "credential_spray"
  ]
}
```

Then operators can understand autonomous behaviour without needing opaque model reasoning.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: survey slice (no code change yet)
- Design/issue: Wave 6 — reason codes + evidence + alternatives without CoT leak
- Commits/PRs: none yet; revalidation: decision_log + deep-error records exist
  backend-side; no why-view confirmed
- Tests/evaluations: n/a
- Documentation: n/a
- Follow-ups: why-view from decision logs + Observation summaries (never raw CoT).

