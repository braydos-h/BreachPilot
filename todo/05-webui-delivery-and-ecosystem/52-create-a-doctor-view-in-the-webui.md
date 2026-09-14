# 52. Create a "doctor" view in the WebUI

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14 — survey done) |
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

You have `--doctor`.

Expose it visually as an environment readiness page:

```text
Runtime
✓ Python
✓ nmap
✓ model backend
✓ API key
✓ Docker
✓ sandbox image
✓ browser image
✓ network policy test
✓ writable workspace

Assessment readiness
✓ target resolves
✓ scope valid
✓ credentials available
✓ model responding
```

And a button:

> **Fix / instructions**

Installation friction is one of the biggest risks for an open-source security platform with this many dependencies.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: survey slice (no code change yet)
- Design/issue: Wave 6 — readiness checks with actionable fixes
- Commits/PRs: none yet; revalidation: SystemPage + settings exist; doctor
  --json machine output exists backend-side; no dedicated doctor view confirmed
- Tests/evaluations: n/a
- Documentation: n/a
- Follow-ups: doctor view rendering --json checks with remediation codes (#53).

