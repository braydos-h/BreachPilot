# 78. Team features should come much later

| Field | Value |
| --- | --- |
| Status | DEFERRED (owner: Muse Spark, 2026-09-14 — prerequisites unmet by design) |
| Suggested priority | Deferred |
| Suggested horizon | Later / intentionally deferred |
| Theme | Data, security, and release |
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

Avoid prematurely building:

```text
organizations
billing
enterprise SSO
RBAC
hosted cloud
```

until autonomous reliability has become measurable.

Current repo has four stars and is moving extremely quickly.

Your scarce engineering time is better spent proving the engine works.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: deferral recorded (intentionally last per audit)
- Design/issue: Wave 7 — team/RBAC/remote last with a real security model
- Commits/PRs: none (deliberately); v1 stays loopback-only by design
- Tests/evaluations: n/a
- Documentation: this deferral record
- Follow-ups: remote deployment security model first; never a flag on v1.

