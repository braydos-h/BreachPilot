# 21. Add an "agent plan" view

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14 — survey done) |
| Suggested priority | P1 |
| Suggested horizon | 60-day |
| Theme | Product and assessment workflows |
| Dependencies | [#22](../03-product-and-assessment-workflows/22-add-a-proper-why-did-the-agent-do-this-view.md), [#69](../06-data-security-and-release/69-introduce-an-observation-schema.md), [#70](../06-data-security-and-release/70-separate-facts-from-hypotheses.md) |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [ ] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [ ] Add or update focused tests and evaluation coverage where applicable.
- [ ] Update generated and user-facing docs/config contracts where applicable.
- [ ] Record completion evidence below and update [the backlog index](../README.md).

## Audit recommendation

You have a DAG already.

Expose it as a first-class product feature.

Example:

```text
Objective: Obtain authenticated admin access

✓ Discover services
  ↓
✓ Identify web app :8080
  ↓
✓ Enumerate authentication
  ↓
├─ ✕ default credentials
├─ ✕ SQL injection
└─ ● reset-token weakness
      ↓
    ● validate token prediction
      ↓
    ○ confirm authenticated access
```

Click each node to see:

```text
Hypothesis
Evidence
Actions attempted
Why branch selected
Why branch abandoned
Verification state
Cost/time
```

This is far more valuable than displaying raw chain-of-thought.

It's an auditable **decision trace**.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: survey slice (no code change yet)
- Design/issue: Wave 6 — structured plan + branch state rendering
- Commits/PRs: none yet; revalidation: plan DAG exists backend-side
  (attack_planner); no dedicated plan view confirmed
- Tests/evaluations: n/a
- Documentation: n/a
- Follow-ups: plan DAG view with branch states + checkpoint affordances.

