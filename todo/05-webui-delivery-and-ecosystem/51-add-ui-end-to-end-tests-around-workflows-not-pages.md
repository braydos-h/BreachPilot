# 51. Add UI end-to-end tests around workflows, not pages

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14 — unit tests exist, journeys pending) |
| Suggested priority | P1 |
| Suggested horizon | 30-day |
| Theme | WebUI, delivery, and ecosystem |
| Dependencies | [#18](../03-product-and-assessment-workflows/18-redesign-the-webui-around-assessment-not-internal-architecture.md), [#19](../03-product-and-assessment-workflows/19-assessment-creation-should-be-a-wizard.md), [#50](../05-webui-delivery-and-ecosystem/50-webui-needs-component-decomposition-too.md) |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [ ] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [ ] Add or update focused tests and evaluation coverage where applicable.
- [ ] Update generated and user-facing docs/config contracts where applicable.
- [ ] Record completion evidence below and update [the backlog index](../README.md).

## Audit recommendation

Playwright journeys:

```text
fresh install
→ configure model
→ create scope
→ start localhost assessment
→ observe progress
→ verify finding
→ open evidence
→ generate report
→ retest finding
```

Another:

```text
Docker missing
→ launch autonomous assessment
→ execution blocked
→ UI explains exact fix
```

Another:

```text
target outside scope
→ launch blocked
→ scope preview explains why
```

This catches bugs that individual component tests won't.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: survey slice (no code change yet)
- Design/issue: Wave 6 (30-day) — Playwright journeys for workflows + failures
- Commits/PRs: none yet; revalidation: vitest per-route unit tests exist; no
  Playwright journey specs found in webui/
- Tests/evaluations: n/a
- Documentation: n/a
- Follow-ups: Playwright journeys (configure→launch→verify→report→retest +
  failure modes) in CI browser tier.

