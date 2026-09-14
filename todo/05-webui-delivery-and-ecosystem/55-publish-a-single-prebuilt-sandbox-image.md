# 55. Publish a single prebuilt sandbox image

| Field | Value |
| --- | --- |
| Status | DONE (owner: Muse Spark, completed: 2026-09-14) |
| Suggested priority | P1 |
| Suggested horizon | Backlog |
| Theme | WebUI, delivery, and ecosystem |
| Dependencies | [#42](../04-runtime-governance-and-ci/42-sign-releases-and-publish-provenance.md), [#43](../04-runtime-governance-and-ci/43-add-sbom-container-scanning-if-it-is-not-already-in-the-release-gate.md), [#44](../04-runtime-governance-and-ci/44-containers-should-be-immutable-by-digest-for-releases.md), [#54](../05-webui-delivery-and-ecosystem/54-installation-should-have-a-minimal-useful-profile.md) |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [x] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [x] Add or update focused tests and evaluation coverage where applicable.
- [x] Update generated and user-facing docs/config contracts where applicable.
- [x] Record completion evidence below and update [the backlog index](../README.md).

## Audit recommendation

Building the worker image locally is great for development.

For end users, I'd eventually ship:

```text
ghcr.io/braydos-h/breachpilot-sandbox:v0.69.0
```

signed and pinned.

Installer:

```text
pull
verify signature
record digest
```

That makes onboarding much faster and more reproducible.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: 2026-09-14 (workflow; first push on next tag/weekly run)
- Design/issue: Wave 1 — prebuilt signed worker images for end users
- Commits/PRs: working-tree: .github/workflows/sandbox-image.yml (build base +
  browser variants, push ghcr.io/<owner>/breachpilot-sandbox:<version>[-browser],
  keyless cosign sign, DIGESTS.md artifact), docs/release.md §Prebuilt image
- Tests/evaluations: workflow-level; no registry creds needed (GITHUB_TOKEN)
- Documentation: docs/release.md installer verify path (pull → verify → record digest)
- Follow-ups: confirm first push + cosign verify; point install profiles at the
  pinned digest (#54).

