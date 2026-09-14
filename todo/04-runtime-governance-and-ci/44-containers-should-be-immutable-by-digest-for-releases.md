# 44. Containers should be immutable by digest for releases

| Field | Value |
| --- | --- |
| Status | DONE (owner: Muse Spark, completed: 2026-09-14) |
| Suggested priority | P1 |
| Suggested horizon | Backlog |
| Theme | Runtime, governance, and CI |
| Dependencies | [#42](../04-runtime-governance-and-ci/42-sign-releases-and-publish-provenance.md), [#43](../04-runtime-governance-and-ci/43-add-sbom-container-scanning-if-it-is-not-already-in-the-release-gate.md) |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [x] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [x] Add or update focused tests and evaluation coverage where applicable.
- [x] Update generated and user-facing docs/config contracts where applicable.
- [x] Record completion evidence below and update [the backlog index](../README.md).

## Audit recommendation

Don't let a release report merely say:

```text
breachpilot-sandbox:latest
```

Record:

```text
breachpilot-sandbox@sha256:...
```

Evaluation should use that exact digest.

Otherwise a benchmark isn't reproducible.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: 2026-09-14
- Design/issue: Wave 1 — releases report digests, never floating tags
- Commits/PRs: working-tree: .github/workflows/release.yml (resolves debian:12-slim
  base digest + records worker RepoDigests into release assets), docs/release.md,
  eval/benchmark provenance already carries sandbox_image_digest at runtime
- Tests/evaluations: provenance digest fields covered by test_eval_live_outcome.py
- Documentation: docs/release.md §digest pinning
- Follow-ups: first DIGESTS.md lands with the next tagged release; eval must then
  run the pinned digest.

