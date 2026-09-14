# 03. Add a "BreachPilot Capability Matrix"

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14 — comparison primitive exists, matrix pending) |
| Suggested priority | P1 |
| Suggested horizon | Backlog |
| Theme | Strategy and evaluation |
| Dependencies | [#02](../01-strategy-and-evaluation/02-live-autonomous-evaluation-needs-to-become-the-centre-of-development.md) |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [ ] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [ ] Add or update focused tests and evaluation coverage where applicable.
- [ ] Update generated and user-facing docs/config contracts where applicable.
- [ ] Record completion evidence below and update [the backlog index](../README.md).

## Audit recommendation

This would be an excellent product differentiator.

Have an automatically generated page:

| Capability          | Detection | Exploitation | Independent verification | Authenticated | Benchmark pass |
| ------------------- | --------: | -----------: | -----------------------: | ------------: | -------------: |
| SQLi                |         ✓ |            ✓ |                        ✓ |             ✓ |            91% |
| XSS                 |         ✓ |            ✓ |                        ✓ |             ✓ |            82% |
| IDOR                |         ✓ |            ✓ |                        ✓ |             ✓ |            67% |
| SSRF                |         ✓ |            ✓ |                        ✓ |             — |            79% |
| RCE                 |         ✓ |            ✓ |                        ✓ |             ✓ |            73% |
| JWT                 |         ✓ |            ✓ |                        ✓ |             ✓ |            63% |
| OAuth               |         ✓ |      partial |                        ✓ |             ✓ |            48% |
| AD lateral movement |         ✓ |      partial |                  partial |           n/a |            39% |

Do not manually edit it.

Generate it from the benchmark suite.

That turns product claims into empirical claims.

XBOW's current presentation is useful context here: it emphasizes **objective proof**, evidence, full exploit/reproduction trace, CWE/CVSS and assessment gaps, not the number of internal agent tools. ([XBOW Documentation](https://docs.xbow.com/console/guidance/interpreting-results/?utm_source=chatgpt.com))

BreachPilot should lean hard into this idea.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: revalidation slice (provider_compare from #38)
- Design/issue: Wave 7 — matrix generated from benchmark truth, never hand claims
- Commits/PRs: none yet; revalidation: tools/benchmark/provider_compare.py +
  docs/reliability-metrics.md exist; no generated matrix artifact found
- Tests/evaluations: n/a
- Documentation: n/a
- Follow-ups: generated matrix artifact from stored runs (suite × provider ×
  model) with Wilson CIs.

