# 64. Add scheduled assessments later

| Field | Value |
| --- | --- |
| Status | DEFERRED (owner: Muse Spark, 2026-09-14 — prerequisites unmet by design) |
| Suggested priority | Deferred |
| Suggested horizon | Later / intentionally deferred |
| Theme | WebUI, delivery, and ecosystem |
| Dependencies | [#02](../01-strategy-and-evaluation/02-live-autonomous-evaluation-needs-to-become-the-centre-of-development.md), [#33](../04-runtime-governance-and-ci/33-run-execution-needs-checkpoint-resume-semantics-everywhere.md), [#63](../05-webui-delivery-and-ecosystem/63-add-report-diffing.md) |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [ ] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [ ] Add or update focused tests and evaluation coverage where applicable.
- [ ] Update generated and user-facing docs/config contracts where applicable.
- [ ] Record completion evidence below and update [the backlog index](../README.md).

## Audit recommendation

After reliable evaluation and stable run execution:

```text
nightly
weekly
after deployment
after GitHub release
on webhook
```

But **do not prioritize this before reproducibility**.

Automating an unreliable autonomous agent just runs unreliability more often.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: deferral recorded (intentionally last per audit)
- Design/issue: Wave 7 — scheduling only after reliability gates are green
- Commits/PRs: none (deliberately)
- Tests/evaluations: prerequisites unmet: release gate NO-GO, repeated-trials
  EXTERNAL, checkpoint/resume done but reproducibility gate open
- Documentation: this deferral record
- Follow-ups: revisit after #02C + #33 + #80 GO.

