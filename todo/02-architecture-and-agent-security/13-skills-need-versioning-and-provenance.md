# 13. Skills need versioning and provenance

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14 — version field exists, history pending) |
| Suggested priority | P2 |
| Suggested horizon | Backlog |
| Theme | Architecture and agent security |
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

The skill system is a promising differentiator.

But as the corpus grows, treat skills almost like packages.

A skill should record:

```text
skill_id
version
author
source
supported vulnerability classes
compatible tool families
prompt/instructions hash
evaluation scenarios
historical success rate
last validated model
last validated date
risk
```

Then selection can consider actual measured performance:

```text
P(skill succeeds | target fingerprint, model, vuln family)
```

rather than purely semantic relevance.

You're already storing Bayesian/cross-mission feedback.

Push that idea further.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: revalidation slice (no code change yet)
- Design/issue: Wave 3 — versioned, attributable skills
- Commits/PRs: none yet; revalidation: skill metadata carries version
  (skill_registry.py) and skill_feedback records outcomes; no evaluation-history
  log or provenance chain per skill version found
- Tests/evaluations: n/a
- Documentation: n/a
- Follow-ups: per-version evaluation history + provenance record; pin skill
  catalog hash in run provenance (tool side done via tool_catalog_hash).

