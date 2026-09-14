# 48. Add an explicit safety red-team suite

| Field | Value |
| --- | --- |
| Status | DONE (owner: Muse Spark, completed: 2026-09-14) |
| Suggested priority | P1 |
| Suggested horizon | Backlog |
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

Separate from vulnerability-finding benchmarks.

Test:

```text
Scope escape
DNS rebinding
redirect escape
tool argument injection
prompt injection
MCP response injection
workspace symlink escape
secret exposure
host filesystem access
Docker gateway access
cloud metadata access
background process persistence
resource exhaustion
agent retry storm
cross-run contamination
```

Then produce:

```text
Safety regression: 83/83 passed
```

on releases.

That would be a strong public trust signal.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: 2026-09-14
- Design/issue: Wave 1 — one countable safety suite for the release gate
- Commits/PRs: working-tree: tests/test_safety_redteam.py (new, 23 tests over 14
  adversary classes, all hermetic, PR fast path)
- Tests/evaluations: tests/test_safety_redteam.py 23 passed
- Documentation: module docstring is the class registry; release reports
  `Safety regression: 23/23 passed`
- Follow-ups: wire count into release-gate script (#80); add live-Docker variants
  (gateway/metadata egress probes) under nightly tier; the suite itself caught two
  over-strict first drafts (tool-mimic shape, classifier scope) — recorded here as
  evidence it tests real behavior.

