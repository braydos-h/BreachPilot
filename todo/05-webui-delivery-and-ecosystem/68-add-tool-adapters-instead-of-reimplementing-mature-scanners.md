# 68. Add tool adapters instead of reimplementing mature scanners

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14 — wrapping exists, observation normalization pending) |
| Suggested priority | P1 |
| Suggested horizon | Backlog |
| Theme | WebUI, delivery, and ecosystem |
| Dependencies | None recorded; confirm during scoping. |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [ ] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [ ] Add or update focused tests and evaluation coverage where applicable.
- [ ] Update generated and user-facing docs/config contracts where applicable.
- [ ] Record completion evidence below and update [the backlog index](../README.md).

## Audit recommendation

Agent should excel at:

```text
selection
orchestration
context
hypothesis formation
correlation
verification
```

Let established tools excel at deterministic scanning.

Integrate outputs into a standard schema.

For example:

```text
nmap
nuclei
ffuf
sqlmap
ZAP
browser
custom exploit
```

all become:

```text
Observation[]
```

rather than each forcing the planner to understand completely different output conventions.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: revalidation slice (no code change yet)
- Design/issue: Wave 5 — mature scanners behind adapters, not rewrites
- Commits/PRs: none yet; revalidation: run_web_scan wraps nikto/nuclei/sqlmap/
  gobuster-class tools via argv (no reimplementation); output is parsed text
  blocks, not normalized Observations
- Tests/evaluations: web-scan suites green in CI
- Documentation: n/a
- Follow-ups: normalize adapter output into Observation (#69) records.

