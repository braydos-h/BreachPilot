# 46. Create a CI pyramid

| Field | Value |
| --- | --- |
| Status | DONE (owner: Muse Spark, completed: 2026-09-14) |
| Suggested priority | P1 |
| Suggested horizon | 30-day |
| Theme | Runtime, governance, and CI |
| Dependencies | [#02](../01-strategy-and-evaluation/02-live-autonomous-evaluation-needs-to-become-the-centre-of-development.md) — slice 1 satisfied (SKIPPED visibility) |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [x] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [x] Add or update focused tests and evaluation coverage where applicable.
- [x] Update generated and user-facing docs/config contracts where applicable.
- [x] Record completion evidence below and update [the backlog index](../README.md).

Revalidated 2026-09-14: ci.yml already has all Tier 1/2 jobs; eval.yml has
eval-unit + nightly-eval. Missing piece was the documented pyramid contract and
a guard against silent-green drift — that is this slice. No product-code change.

## Audit recommendation

Something like:

### PR / ~5–10 min

```text
lint
types
unit
frontend unit
policy property tests
package build
```

### PR / ~15–25 min

```text
Docker sandbox integration
browser smoke
API contract
selected autonomous lab
```

### Nightly

```text
complete autonomous scenario corpus
multiple models
multiple seeds/trials
performance tests
long sessions
```

### Release

```text
full matrix
5–10 stochastic trials
installer matrix
sandbox escape/regression suite
SBOM/signing
upgrade/rollback testing
```

That avoids turning every code change into a one-hour feedback cycle.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: 2026-09-14
- Design/issue: Wave 0 — document and lock the pyramid tiers
- Commits/PRs: working-tree: docs/ci-pyramid.md (new), tests/test_ci_pyramid.py (new, 4 tests)
- Tests/evaluations: tests/test_ci_pyramid.py 4 passed
- Documentation: docs/ci-pyramid.md maps Tier 1 (PR fast) / Tier 2 (PR integration) /
  Tier 3 (nightly live) / Tier 4 (release gate → #80)
- Follow-ups: Tier 4 enforcement lives in #80; Level B per-PR lab trigger lives in #02.

