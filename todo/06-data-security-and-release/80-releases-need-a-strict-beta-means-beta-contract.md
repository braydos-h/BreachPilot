# 80. Releases need a strict "beta means beta" contract

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14; gate verdict NO-GO with 4 EXTERNAL boxes) |
| Suggested priority | P0 |
| Suggested horizon | Backlog |
| Theme | Data, security, and release |
| Dependencies | [#02](../01-strategy-and-evaluation/02-live-autonomous-evaluation-needs-to-become-the-centre-of-development.md), [#08](../01-strategy-and-evaluation/08-add-semantic-configuration-assertions.md), [#41](../04-runtime-governance-and-ci/41-the-public-repo-should-have-mandatory-branch-rules-immediately.md), [#42](../04-runtime-governance-and-ci/42-sign-releases-and-publish-provenance.md), [#43](../04-runtime-governance-and-ci/43-add-sbom-container-scanning-if-it-is-not-already-in-the-release-gate.md), [#44](../04-runtime-governance-and-ci/44-containers-should-be-immutable-by-digest-for-releases.md), [#46](../04-runtime-governance-and-ci/46-create-a-ci-pyramid.md), [#48](../04-runtime-governance-and-ci/48-add-an-explicit-safety-red-team-suite.md), [#51](../05-webui-delivery-and-ecosystem/51-add-ui-end-to-end-tests-around-workflows-not-pages.md), [#55](../05-webui-delivery-and-ecosystem/55-publish-a-single-prebuilt-sandbox-image.md) |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [x] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [x] Add or update focused tests and evaluation coverage where applicable.
- [x] Update generated and user-facing docs/config contracts where applicable.
- [x] Record completion evidence below and update [the backlog index](../README.md).

## Audit recommendation

Version is currently **0.68.4**, classified as Beta in `pyproject.toml`.

For `0.69`, I'd define a release bar.

## 0.69 release gate

I would not release until:

```text
[ ] Current main CI completely green
[ ] Linux sandbox integration green
[ ] Browser image build/smoke green
[ ] Python 3.11/3.12/3.13 installs green
[ ] Live evaluation cannot silently pass by skipping
[ ] At least one model backend provisioned for scheduled eval
[ ] Repeated autonomous trials recorded
[ ] False-compromise metric recorded
[ ] Stuck-loop metric recorded
[ ] Scope/safety suite green
[ ] Main branch rules enabled
[ ] SECURITY.md live
[ ] Release assets reproducible
[ ] Docs agree with actual safety defaults
```

That would make 0.69 mean something.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: gate implemented; release NOT approved (NO-GO — see externals)
- Design/issue: Wave 1 — make 0.69 mean something
- Commits/PRs: working-tree: scripts/release_gate.py (new, 9 local boxes + 4
  EXTERNAL), tests/test_release_gate.py (new, 3 tests), .github/workflows/release.yml
  (gate job blocks publishing on NO-GO), docs/release.md, docs/branch-protection.md
- Tests/evaluations: tests/test_release_gate.py 3 passed; `python
  scripts/release_gate.py` → NO-GO (all 9 local boxes ok; 4 EXTERNAL outstanding:
  live-eval-backend, repeated-trials, branch-rules-applied, sandbox-image-published)
- Documentation: docs/release.md; this task tracks the 14 audit boxes — 9 local
  boxes now machine-checked, 4 external + live-trial metrics pending
- Follow-ups: provision eval backend → record repeated trials → apply branch rules →
  push sandbox image → re-run gate to GO.

