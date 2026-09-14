# 72. Persistent memory must distinguish experience from truth

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14 — epistemic kinds land, memory wiring pending) |
| Suggested priority | P1 |
| Suggested horizon | Backlog |
| Theme | Data, security, and release |
| Dependencies | [#69](../06-data-security-and-release/69-introduce-an-observation-schema.md), [#70](../06-data-security-and-release/70-separate-facts-from-hypotheses.md) |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [ ] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [ ] Add or update focused tests and evaluation coverage where applicable.
- [ ] Update generated and user-facing docs/config contracts where applicable.
- [ ] Record completion evidence below and update [the backlog index](../README.md).

## Audit recommendation

Cross-run learning is useful, but it creates a poisoning/staleness problem.

Store:

```text
Lesson
├── context
├── source runs
├── success/failure count
├── model
├── timestamp
├── evidence
├── confidence
└── expiration/decay
```

Never turn:

> "Technique X worked once on nginx"

into:

> "Technique X works on nginx."

OWASP explicitly identifies memory poisoning as an agent-specific concern. ([OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html?utm_source=chatgpt.com))

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: revalidation slice (EpistemicKind foundation from #70)
- Design/issue: Wave 3 — experience must not silently become truth
- Commits/PRs: none yet; revalidation: ExperienceStore (Bayesian) and
  semantic_memory exist; EpistemicKind CLAIM vs VERIFIED now typed but not yet
  enforced at memory write/read
- Tests/evaluations: n/a
- Documentation: n/a
- Follow-ups: tag stored memories with EpistemicKind; VERIFIED memories require
  oracle_ref; readers must show kind.

