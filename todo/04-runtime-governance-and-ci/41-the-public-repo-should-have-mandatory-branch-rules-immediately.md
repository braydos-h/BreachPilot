# 41. The public repo should have mandatory branch rules immediately

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14; BLOCKED: repo-admin must apply the ruleset — exact gh commands in docs/branch-protection.md) |
| Suggested priority | P0 |
| Suggested horizon | 30-day |
| Theme | Runtime, governance, and CI |
| Dependencies | None recorded; confirm during scoping. |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [x] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [x] Add or update focused tests and evaluation coverage where applicable.
- [x] Update generated and user-facing docs/config contracts where applicable.
- [x] Record completion evidence below and update [the backlog index](../README.md).

## Audit recommendation

`main` is currently reported by GitHub as **unprotected**.

You already wrote the appropriate governance plan.

Implement it.

At minimum:

```text
No force pushes
No deletion
PR required
CI required
CodeQL required
Dependency review required
```

If you're solo:

```text
required human approvals: 0
```

is perfectly reasonable.

The important rule is:

> code doesn't land without automated verification.

This should be done before 0.69.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: in-repo part done; EXTERNAL part BLOCKED (see below)
- Design/issue: Wave 1 — code cannot land without automated verification
- Commits/PRs: working-tree: docs/branch-protection.md (new, exact ruleset + gh commands),
  scripts/release_gate.py branch-rules-applied EXTERNAL box, .github/workflows/ci.yml
  already aggregates to `CI success`
- Tests/evaluations: gate box present; application verifiable via gh api rulesets
- Documentation: docs/branch-protection.md
- Follow-ups (BLOCKED, needs repo admin): run the gh api commands in
  docs/branch-protection.md, record ruleset ID + date here, then flip the gate box.

