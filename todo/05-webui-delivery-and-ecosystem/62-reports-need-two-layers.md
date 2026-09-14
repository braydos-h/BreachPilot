# 62. Reports need two layers

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14 — JSON/MD/HTML exist, SARIF + exec layer pending) |
| Suggested priority | P1 |
| Suggested horizon | Backlog |
| Theme | WebUI, delivery, and ecosystem |
| Dependencies | [#04](../01-strategy-and-evaluation/04-finding-verification-should-become-the-centre-of-the-data-model.md), [#28](../03-product-and-assessment-workflows/28-make-evidence-excellent.md), [#60](../05-webui-delivery-and-ecosystem/60-a-major-competitive-opportunity-assessment-gaps.md), [#61](../05-webui-delivery-and-ecosystem/61-add-a-coverage-model.md) |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [ ] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [ ] Add or update focused tests and evaluation coverage where applicable.
- [ ] Update generated and user-facing docs/config contracts where applicable.
- [ ] Record completion evidence below and update [the backlog index](../README.md).

## Audit recommendation

### Executive

```text
What matters
Critical findings
Risk trend
Coverage
What was not tested
```

### Technical

```text
Finding
Evidence
Reproduction
Request/response
Attack trace
CWE/CVSS
Remediation
Retest
```

Generate HTML + PDF + JSON + SARIF.

JSON becomes the durable interchange format.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: revalidation slice (no code change yet)
- Design/issue: Wave 4 — executive + technical layers, durable JSON + SARIF
- Commits/PRs: none yet; revalidation: enhanced_reporting writes JSON + Markdown
  + HTML; no executive/technical split and no SARIF found
- Tests/evaluations: n/a
- Documentation: n/a
- Follow-ups: two-layer template + SARIF export from VERIFIED findings.

