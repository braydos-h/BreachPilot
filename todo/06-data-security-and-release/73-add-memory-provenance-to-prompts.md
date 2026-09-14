# 73. Add memory provenance to prompts

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14 — skill wrapping exists, memory provenance pending) |
| Suggested priority | P1 |
| Suggested horizon | Backlog |
| Theme | Data, security, and release |
| Dependencies | [#72](../06-data-security-and-release/72-persistent-memory-must-distinguish-experience-from-truth.md) |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [ ] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [ ] Add or update focused tests and evaluation coverage where applicable.
- [ ] Update generated and user-facing docs/config contracts where applicable.
- [ ] Record completion evidence below and update [the backlog index](../README.md).

## Audit recommendation

When the agent receives a lesson, show:

```text
Prior experience:
Technique: ...
Based on 8 runs
5 successful / 3 failed
Last validated: ...
Confidence: 0.61
```

This reduces over-trust.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: revalidation slice (no code change yet)
- Design/issue: Wave 3 — prompts show provenance, age, support, confidence
- Commits/PRs: none yet; revalidation: skill spans are wrapped untrusted but
  carry no age/support/confidence annotations; memory spans carry none either
- Tests/evaluations: n/a
- Documentation: n/a
- Follow-ups: provenance-annotated context builder reusing EpistemicKind +
  belief confidence.

