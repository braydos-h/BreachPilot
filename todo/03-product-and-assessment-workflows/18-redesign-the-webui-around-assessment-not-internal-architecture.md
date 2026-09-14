# 18. Redesign the WebUI around "Assessment", not internal architecture

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14 — survey done) |
| Suggested priority | P1 |
| Suggested horizon | 60-day |
| Theme | Product and assessment workflows |
| Dependencies | [#04](../01-strategy-and-evaluation/04-finding-verification-should-become-the-centre-of-the-data-model.md), [#19](../03-product-and-assessment-workflows/19-assessment-creation-should-be-a-wizard.md), [#21](../03-product-and-assessment-workflows/21-add-an-agent-plan-view.md), [#28](../03-product-and-assessment-workflows/28-make-evidence-excellent.md), [#50](../05-webui-delivery-and-ecosystem/50-webui-needs-component-decomposition-too.md) |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [ ] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [ ] Add or update focused tests and evaluation coverage where applicable.
- [ ] Update generated and user-facing docs/config contracts where applicable.
- [ ] Record completion evidence below and update [the backlog index](../README.md).

## Requirements called out by the audit

- [ ] Artifacts;
- [ ] Attack Modules;
- [ ] Benchmarks;
- [ ] Connections;
- [ ] Goals;
- [ ] Graph;
- [ ] settings/help;
- [ ] other run-related surfaces.

## Audit recommendation

The React side is already substantial.

Current routes/features include things such as:

* Artifacts;
* Attack Modules;
* Benchmarks;
* Connections;
* Goals;
* Graph;
* settings/help;
* other run-related surfaces.

Some pages are already very large—for example `ConnectionsPage.tsx` is about 56 KB and `BenchmarkRunPage.tsx` about 50 KB.

I would simplify the operator mental model.

## Main navigation

```text
Assessments
Assets
Findings
Regressions
Integrations
Benchmarks
System
```

Not:

```text
internal implementation capability A
internal module B
internal graph C
```

### Primary dashboard

```text
┌─────────────────────────────────────────────┐
│ BreachPilot                                 │
│ 3 active assessments                        │
├───────────────┬────────────┬────────────────┤
│ Verified      │ Suspected  │ Fixed          │
│      7        │     12     │      31        │
├───────────────┴────────────┴────────────────┤
│ Active                                        │
│ api.example.com ███████░  Verification       │
│ lab.internal   ███░░░░░  Recon               │
├─────────────────────────────────────────────┤
│ Critical findings                            │
│ SQL injection     VERIFIED         9.8       │
│ IDOR              VERIFIED         8.1       │
└─────────────────────────────────────────────┘
```

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: survey slice (no code change yet)
- Design/issue: Wave 6 — Assessments → Findings → Evidence → Retest navigation
- Commits/PRs: none yet; revalidation: nav is feature-page oriented
  (AttackModules, Skills, Memory, Graph, Benchmarks, ...) confirming the audit
- Tests/evaluations: n/a
- Documentation: n/a
- Follow-ups: assessment-centered nav + routes; finding lifecycle states as
  first-class UI (PROPOSED/APPROVED/VERIFIED/STILL_OPEN/FIXED).

