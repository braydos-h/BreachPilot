# 38. Benchmark across model providers

| Field | Value |
| --- | --- |
| Status | DONE (owner: Muse Spark, completed: 2026-09-14) |
| Suggested priority | P1 |
| Suggested horizon | 60-day |
| Theme | Runtime, governance, and CI |
| Dependencies | [#02](../01-strategy-and-evaluation/02-live-autonomous-evaluation-needs-to-become-the-centre-of-development.md) |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [x] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [x] Add or update focused tests and evaluation coverage where applicable.
- [x] Update generated and user-facing docs/config contracts where applicable.
- [x] Record completion evidence below and update [the backlog index](../README.md).

## Audit recommendation

You support multiple model backends.

Treat them like execution engines and publish something internally:

```text
                   Verified   False+   Actions   Cost
Model A               71%      1.8%       35    $0.42
Model B               74%      0.9%       51    $1.20
Model C local          53%      3.1%       64    $0.05
```

Then the router could intelligently choose a model.

Example:

```text
recon classification → cheaper/local
complex auth reasoning → high-capability model
report generation → cheap model
independent verification → separate model / deterministic verifier
```

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: 2026-09-14
- Design/issue: Wave 0 — comparable provider table for router decisions
- Commits/PRs: working-tree: tools/benchmark/provider_compare.py (new, pure),
  tests/test_benchmark_provider_compare.py (new, 3 tests)
- Tests/evaluations: tests/test_benchmark_provider_compare.py 3 passed
- Documentation: module docstring defines per-role routing use
- Follow-ups: wire into benchmark report + WebUI dashboard (#58); repeated-trials
  data collection under #02 Level C; router policy under #14.

