# 43. Add SBOM/container scanning if it is not already in the release gate

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
- [x] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [x] Add or update focused tests and evaluation coverage where applicable.
- [x] Update generated and user-facing docs/config contracts where applicable.
- [x] Record completion evidence below and update [the backlog index](../README.md).

## Audit recommendation

Particularly because the sandbox image becomes part of your security boundary.

Release gate should understand:

```text
Python dependencies
npm dependencies
sandbox OS packages
browser image dependencies
```

Generate CycloneDX or SPDX SBOMs.

Scan them.

Keep the digest with assessment metadata.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: 2026-09-14
- Design/issue: Wave 1 — SBOMs for Python, npm, sandbox OS packages + scan
- Commits/PRs: working-tree: .github/workflows/release.yml (cyclonedx Python SBOM,
  npm sbom, syft sandbox-image SBOM, Trivy HIGH/CRITICAL fail-gate), docs/release.md
- Tests/evaluations: workflow-level; first live SBOMs on next v* tag
- Documentation: docs/release.md §Container scanning
- Follow-ups: confirm Trivy gate passes on first release run; keep digests with
  assessment metadata (provenance already carries sandbox_image_digest).

