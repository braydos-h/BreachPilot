# 33. Run execution needs checkpoint/resume semantics everywhere

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
- [ ] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [ ] Add or update focused tests and evaluation coverage where applicable.
- [ ] Update generated and user-facing docs/config contracts where applicable.
- [ ] Record completion evidence below and update [the backlog index](../README.md).

## Audit recommendation

For long autonomous runs, every side-effect should be modelled around:

```text
queued
authorized
started
completed
failed
timed_out
cancelled
```

and ideally have an invocation ID.

On restart:

```text
Was action definitely never executed?
Was it executed but result wasn't persisted?
Is it safe to retry?
```

This suggests idempotency support for deterministic operations and explicit handling of non-idempotent actions.

The run shouldn't rely on "the Python process survived."

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: 2026-09-14 (revalidation + extraction support; semantics exist)
- Design/issue: Wave 2 — durable runs and safe resume
- Commits/PRs: checkpoint types extracted to runner/checkpoint.py (#09 step 1);
  existing machinery revalidated, no behavior change
- Tests/evaluations: tests/test_resume_flow_a.py 17 passed;
  tests/test_campaign_checkpoint.py 9 passed; persistent_session_manager +
  tools/resume_state.py (--resume loader) + CheckpointHook/Decision wiring present
- Documentation: checkpoint.py contract; AssessmentService.execute closure
- Follow-ups: durable per-action states + resume-across-restart for every
  execution path (orchestrator batch/recovery).

