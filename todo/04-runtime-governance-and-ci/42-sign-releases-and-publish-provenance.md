# 42. Sign releases and publish provenance

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

Current HEAD is an unsigned Git commit according to GitHub's commit metadata.

You don't necessarily need every development commit signed.

But release assets should be.

I'd produce:

```text
Python artifact
Windows installer
SBOM
SHA256SUMS
signature
container image digest
provenance
```

Consider Sigstore/cosign for images/releases.

For a security product that executes powerful tooling, supply-chain trust matters disproportionately.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: 2026-09-14
- Design/issue: Wave 1 — supply-chain trust for a security product
- Commits/PRs: working-tree: .github/workflows/release.yml (SHA256SUMS +
  actions/attest-build-provenance Sigstore attestations for dist + SBOMs),
  docs/release.md
- Tests/evaluations: workflow YAML validated by gate presence checks; first live
  attestation happens on the next v* tag (keyless OIDC, no maintainer keys)
- Documentation: docs/release.md §What release.yml publishes
- Follow-ups: verify attestations on first tagged release.

