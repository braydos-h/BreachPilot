# 31. Integrations should follow the finding lifecycle

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14 — ticketing exists, lifecycle wiring pending) |
| Suggested priority | P1 |
| Suggested horizon | 90-day |
| Theme | Product and assessment workflows |
| Dependencies | [#04](../01-strategy-and-evaluation/04-finding-verification-should-become-the-centre-of-the-data-model.md), [#05](../01-strategy-and-evaluation/05-build-vulnerability-regression-testing.md), [#30](../03-product-and-assessment-workflows/30-add-reproducible-finding-bundles.md), [#32](../03-product-and-assessment-workflows/32-create-a-proper-public-api-contract.md) |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [ ] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [ ] Add or update focused tests and evaluation coverage where applicable.
- [ ] Update generated and user-facing docs/config contracts where applicable.
- [ ] Record completion evidence below and update [the backlog index](../README.md).

## Audit recommendation

Don't simply add generic webhook support.

Start with:

```text
GitHub Issues
Jira
Linear
SARIF
Slack/Teams notification
generic webhook
```

Workflow:

```text
VERIFIED
   ↓
Create ticket
   ↓
Store external ID
   ↓
Observe remediation state
   ↓
Retest
   ↓
Update ticket
```

XBOW is already moving this way with its Jira integration, including maintaining XBOW as the vulnerability source of truth and Jira as the remediation workflow. ([XBOW Documentation](https://docs.xbow.com/integrations/jira-integration/introduction/?utm_source=chatgpt.com))

BreachPilot should adopt a similar conceptual boundary.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: revalidation slice (no code change yet)
- Design/issue: Wave 5 (90-day) — integrations keyed on lifecycle states
- Commits/PRs: none yet; revalidation: Jira/GitHub issue creation exists;
  not keyed on VERIFIED/retest states via finding_lifecycle
- Tests/evaluations: n/a
- Documentation: n/a
- Follow-ups: emit on VERIFIED, update on STILL_OPEN/FIXED, close on FIXED.

