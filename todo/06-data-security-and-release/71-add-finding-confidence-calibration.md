# 71. Add finding confidence calibration

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14 — confidence exists, calibration pending) |
| Suggested priority | P1 |
| Suggested horizon | Backlog |
| Theme | Data, security, and release |
| Dependencies | [#04](../01-strategy-and-evaluation/04-finding-verification-should-become-the-centre-of-the-data-model.md), [#70](../06-data-security-and-release/70-separate-facts-from-hypotheses.md) |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [ ] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [ ] Add or update focused tests and evaluation coverage where applicable.
- [ ] Update generated and user-facing docs/config contracts where applicable.
- [ ] Record completion evidence below and update [the backlog index](../README.md).

## Audit recommendation

Over time compare the agent's self-confidence to actual verification.

If it says:

```text
90% confidence
```

on 100 hypotheses, roughly 90 should verify if calibrated.

Then calibrate prompts/models accordingly.

This is a much better measure than subjective model confidence.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: revalidation slice (no code change yet)
- Design/issue: Wave 4 — calibrate stated confidence against verifier outcomes
- Commits/PRs: none yet; revalidation: belief confidence + thresholds exist;
  no calibration loop comparing predicted confidence vs VERIFIED/HOLDING rates
- Tests/evaluations: n/a
- Documentation: n/a
- Follow-ups: calibration dataset (confidence → verifier outcome) + reliability
  diagram + threshold tuning.

