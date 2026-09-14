# 60. A major competitive opportunity: "assessment gaps"

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14 — gap confirmed) |
| Suggested priority | P1 |
| Suggested horizon | 60-day |
| Theme | WebUI, delivery, and ecosystem |
| Dependencies | [#61](../05-webui-delivery-and-ecosystem/61-add-a-coverage-model.md) |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [ ] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [ ] Add or update focused tests and evaluation coverage where applicable.
- [ ] Update generated and user-facing docs/config contracts where applicable.
- [ ] Record completion evidence below and update [the backlog index](../README.md).

## Audit recommendation

XBOW has an interesting concept around assessment gaps. ([XBOW Documentation](https://docs.xbow.com/console/guidance/interpreting-results/?utm_source=chatgpt.com))

BreachPilot should explicitly state what it **couldn't test**.

Example report:

```text
Coverage gaps
──────────────────────────
⚠ OAuth SSO
  Authentication could not be established.

⚠ iOS API
  No mobile client traffic supplied.

⚠ /billing/*
  Excluded from operator scope.

⚠ SMTP
  Tool unavailable in sandbox image.

⚠ Admin role
  No admin credential supplied.
```

This makes "no vulnerabilities found" vastly more meaningful.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: revalidation slice (no code change yet)
- Design/issue: Wave 4 — explicit untested-surface record
- Commits/PRs: none yet; revalidation: no assessment-gaps model found
- Tests/evaluations: n/a
- Documentation: n/a
- Follow-ups: gap taxonomy (blocked/unauthorized/out-of-window/tool-missing) +
  UI + report section; needs coverage model (#61).

