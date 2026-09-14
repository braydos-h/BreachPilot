# 34. Add explicit run budgets

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

Expose:

```text
maximum wall time
maximum model cost
maximum tokens
maximum active requests
maximum tool calls
maximum exploit attempts
maximum retries per hypothesis
maximum browser actions
maximum discovered assets
```

And support:

```text
Budget exhausted
→ save checkpoint
→ explain remaining high-value hypotheses
→ user may extend
```

This is both useful UX and protection against agent loops.

OWASP specifically calls out recursive tool/budget abuse as an agent risk. ([OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html?utm_source=chatgpt.com))

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: 2026-09-14 (tracker semantics; runner migration pending)
- Design/issue: Wave 2 — typed budgets with #36 stop reasons
- Commits/PRs: working-tree: tools/kernel/budgets.py (new: BudgetLimits +
  BudgetUsage + BudgetTracker with per-dimension exhausted() + stop_reason()),
  tests/test_kernel_contracts.py (3 budget tests)
- Tests/evaluations: 3 passed (dimension reporting, negative-delta guard, time limit)
- Documentation: module docstring maps dimensions to the stop taxonomy
- Follow-ups: migrate runner max_rounds/time checks onto BudgetTracker; add
  token/cost/request/browser/asset accounting at dispatch sites.

