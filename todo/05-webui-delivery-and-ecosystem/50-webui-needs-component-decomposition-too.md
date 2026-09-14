# 50. WebUI needs component decomposition too

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

The backend isn't the only place showing "feature accumulation."

Route files above ~50 KB suggest the React architecture is beginning to centralize too much.

Use feature slices:

```text
features/connections/
  api.ts
  types.ts
  ConnectionList.tsx
  ConnectionEditor.tsx
  ProviderCard.tsx
  CredentialForm.tsx
  hooks.ts
  tests/
```

and route components primarily compose features.

Same principle as the Python orchestrator.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: survey slice (no code change yet)
- Design/issue: Wave 6 — tested feature slices, not oversized routes
- Commits/PRs: none yet; revalidation: routes/ holds ~25 page components
  (RunPage, BenchmarksPage, SystemPage, ...); features/ has benchmarks/graph/
  help/settings slices started
- Tests/evaluations: vitest unit tests exist per-route (*.test.tsx)
- Documentation: n/a
- Follow-ups: split largest routes into features/ slices with journey tests.

