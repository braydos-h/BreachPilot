# 35. Add "information gain" as a planner concept

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14 — concept located, planner wiring pending) |
| Suggested priority | P1 |
| Suggested horizon | Backlog |
| Theme | Runtime, governance, and CI |
| Dependencies | [#22](../03-product-and-assessment-workflows/22-add-a-proper-why-did-the-agent-do-this-view.md), [#34](../04-runtime-governance-and-ci/34-add-explicit-run-budgets.md), [#69](../06-data-security-and-release/69-introduce-an-observation-schema.md), [#70](../06-data-security-and-release/70-separate-facts-from-hypotheses.md) |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [ ] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [ ] Add or update focused tests and evaluation coverage where applicable.
- [ ] Update generated and user-facing docs/config contracts where applicable.
- [ ] Record completion evidence below and update [the backlog index](../README.md).

## Audit recommendation

A common autonomous pentesting failure mode is doing more enumeration because enumeration is easy.

You already implemented an attack-focus controller to combat drift.

Formalize it further.

Each candidate action:

```text
expected information gain
likelihood of objective progress
cost
noise
risk
duplicate similarity
```

Score something like:

```text
utility =
  progress
+ information_gain
- cost
- repetition
- noise
- risk
```

This makes branch selection explainable and measurable.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: revalidation slice (no code change yet)
- Design/issue: Wave 2 — measurable action utility
- Commits/PRs: none yet; revalidation: BeliefState.top_unresolved ranks by
  uncertainty and next_discriminating_check picks un-attempted checks — the
  uncertainty half of info-gain exists, but no expected-utility/cost scoring
  drives planner choices anywhere
- Tests/evaluations: belief uncertainty ranking covered by test_intelligence_belief.py
- Documentation: n/a
- Follow-ups: add expected-information-gain + cost scorer consumed by the planner
  and the checkpoint continue/change_goal branch.

