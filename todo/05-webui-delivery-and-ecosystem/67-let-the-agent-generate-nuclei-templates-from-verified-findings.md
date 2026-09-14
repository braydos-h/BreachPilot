# 67. Let the agent generate Nuclei templates from verified findings

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14 — gap confirmed) |
| Suggested priority | P1 |
| Suggested horizon | Backlog |
| Theme | WebUI, delivery, and ecosystem |
| Dependencies | [#05](../01-strategy-and-evaluation/05-build-vulnerability-regression-testing.md), [#66](../05-webui-delivery-and-ecosystem/66-add-a-minimal-reproduction-reducer.md), [#68](../05-webui-delivery-and-ecosystem/68-add-tool-adapters-instead-of-reimplementing-mature-scanners.md) |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [ ] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [ ] Add or update focused tests and evaluation coverage where applicable.
- [ ] Update generated and user-facing docs/config contracts where applicable.
- [ ] Record completion evidence below and update [the backlog index](../README.md).

## Audit recommendation

Not for all vulnerabilities, but when appropriate:

```text
Verified finding
↓
derive matcher + preconditions
↓
generate Nuclei template
↓
test against vulnerable target
↓
test against patched target
↓
accept only if both behave correctly
```

Nuclei's template ecosystem is huge, with ProjectDiscovery reporting over 12,000 templates and significant active use. ([ProjectDiscovery](https://projectdiscovery.io/nuclei?utm_source=chatgpt.com))

Instead of competing against that ecosystem, BreachPilot can leverage it.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: revalidation slice (no code change yet)
- Design/issue: Wave 4 — Nuclei templates only from VERIFIED findings
- Commits/PRs: none yet; revalidation: no template generation found
- Tests/evaluations: n/a
- Documentation: n/a
- Follow-ups: generator gated on VERIFIED + tests against vulnerable AND fixed
  controls (uses the impossible_sqli/secure_web oracles as fixed controls).

