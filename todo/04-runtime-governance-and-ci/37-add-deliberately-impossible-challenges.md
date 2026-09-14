# 37. Add deliberately impossible challenges

| Field | Value |
| --- | --- |
| Status | DONE (owner: Muse Spark, completed: 2026-09-14) |
| Suggested priority | P1 |
| Suggested horizon | Backlog |
| Theme | Runtime, governance, and CI |
| Dependencies | [#02](../01-strategy-and-evaluation/02-live-autonomous-evaluation-needs-to-become-the-centre-of-development.md), [#04](../01-strategy-and-evaluation/04-finding-verification-should-become-the-centre-of-the-data-model.md) |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [x] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [x] Add or update focused tests and evaluation coverage where applicable.
- [x] Update generated and user-facing docs/config contracts where applicable.
- [x] Record completion evidence below and update [the backlog index](../README.md).

## Audit recommendation

For example:

```text
Scenario has an apparent SQL injection signal,
but controlled verification demonstrates it is not exploitable.
```

A strong system should mark:

```text
REFUTED
```

not keep retrying until hallucinating success.

Your `OutcomeJudge` / verifier separation is ideal for this.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: 2026-09-14
- Design/issue: Wave 0 — decoy signal must REFUTE, never hallucinate
- Commits/PRs: working-tree: eval_targets/impossible_sqli.oracle.json (new,
  decoy SQL-error string + guard flag proving parameterized queries),
  tools/eval_harness.py negative-control scoring, tests/test_eval_suite.py +2 tests
- Tests/evaluations: tests/test_eval_suite.py 25 passed (empty=success, claim=FP)
- Documentation: docs/reliability-metrics.md stop section; oracle decoy_signal field
- Follow-ups: live decoy image on :8091; verifier-separation proof under #04.

