# 14. Add skill A/B testing

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14 — feedback exists, A/B harness pending) |
| Suggested priority | P2 |
| Suggested horizon | Backlog |
| Theme | Architecture and agent security |
| Dependencies | [#02](../01-strategy-and-evaluation/02-live-autonomous-evaluation-needs-to-become-the-centre-of-development.md), [#13](../02-architecture-and-agent-security/13-skills-need-versioning-and-provenance.md) |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [ ] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [ ] Add or update focused tests and evaluation coverage where applicable.
- [ ] Update generated and user-facing docs/config contracts where applicable.
- [ ] Record completion evidence below and update [the backlog index](../README.md).

## Audit recommendation

Because the evaluation infrastructure exists, evaluate alternative strategies.

Example:

```text
SQL injection target

Skill A
  success 72%
  median 24 actions
  $0.31/run

Skill B
  success 77%
  median 51 actions
  $0.82/run

Skill C
  success 68%
  median 17 actions
  $0.20/run
```

Then route based on desired objective:

```text
fast
cheap
highest-confidence
stealth
```

This turns your skills system into a learning system rather than a prompt directory.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: revalidation slice (no code change yet)
- Design/issue: Wave 3 — repeatable skill comparison
- Commits/PRs: none yet; revalidation: skill_feedback.py + ExperienceStore give
  Bayesian outcome tracking; no controlled A/B assignment, objective routing,
  or repeatability harness found
- Tests/evaluations: n/a
- Documentation: n/a
- Follow-ups: A/B assignment + objective-aware routing + provider-compare-style
  reporting for skill variants.

