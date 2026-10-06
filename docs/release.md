# Release process — reproducible, signed, digest-pinned (#42/#43/#44/#55/#80)

## 0.69 trust freeze (TODO 022)

0.69 is a trust/reliability release, not a feature release. Freeze: new
attack modules/skills/providers need release-owner sign-off; default answer
is "after 0.69". Feature PRs are labeled `post-0.69` unless trust-gated.

§52 burndown (in order): docs drift (TODO 003/004/016) → gate regex
(TODO 005) → gate satisfiability (TODO 002) → eval baseline (TODO 001) →
supply-chain/branch/image (TODO 024) → counts (TODO 010). Ship iff every row
is Green or EXTERNAL-with-evidence-path; `python scripts/release_gate.py` +
CI + Trivy + SBOM evidence linked from release notes. HEAD must show an
observed green run (TODO 024); no release on unobserved green.

## Supply chain (TODO 024)

Observable green HEAD + §52 rows evidenced: `branch-rules-applied`
(API-verified ruleset per `docs/branch-protection.md`),
`sandbox-image-published` (GHCR digest recorded), Python/WebUI/sandbox SBOMs,
Trivy with no unacceptable high/critical, SHA-locked actions (CI guard
green), coverage ≥80. On GO, the release workflow publishes installer +
`.sha256` + attestations (TODO 013), SBOMs, Trivy results, and Python
distributions as GitHub Release assets. It also retains a workflow artifact.
The scheduled/manual sandbox workflow publishes only the `nightly` GHCR
channel; it does not run for release tags. Verify:

```bash
gh run list --branch main   # HEAD health, link from release notes
gh api repos/OWNER/REPO/rulesets > branch-rules.json
python scripts/release_gate.py --branch-rules-file branch-rules.json \
  --sandbox-digest-file sandbox-artifacts/DIGESTS.md --eval-dir eval-artifacts \
  --benchmark-dir benchmark-artifacts --json
```

## Gate first

```bash
python scripts/release_gate.py
python scripts/release_gate.py --eval-dir eval-artifacts \
  --benchmark-dir benchmark-artifacts \
  --sandbox-digest-file sandbox-artifacts/DIGESTS.md \
  --branch-rules-file branch-rules.json --json
```

`GO` requires every local box green and no EXTERNAL box outstanding. Each
EXTERNAL is satisfiable via an evidence artifact (safe default is EXTERNAL
when the file is missing; present-but-invalid fails closed):

| Gate box | Artifact | Contract |
|---|---|---|
| `live-eval-backend` | `--eval-dir DIR` | At least one `report.json` with `live_outcome` `PASS` or `FAIL`, complete provenance, a full 40-character `code_revision` exactly matching the release checkout, and a report timestamp within 90 days. `SKIPPED` and `INFRA_ERROR` do not count. |
| `repeated-trials` | `--benchmark-dir DIR` | A completed benchmark `run.json` and matching `summary.json`; every listed scenario has at least five distinct persisted trial indices, the run requires the sandbox, the source tree is clean, its full `git_sha` exactly matches the release checkout, and the summary timestamp is within 90 days. |
| `branch-rules-applied` | `--branch-rules-file rules.json` | `gh api repos/OWNER/REPO/rulesets` JSON containing an active ruleset matching the full contract in `docs/governance/ruleset-main.json`: exact `main` scope, no bypass actors, deletion/non-fast-forward protection, the required pull-request rule, and all documented strict status checks. |
| `sandbox-image-published` | `sandbox-artifacts/DIGESTS.md`, downloaded from the `sandbox-digests` artifact | Base and browser GHCR digests, a full source revision exactly matching the release checkout, and UTC creation time within 90 days. Before gate evaluation, CI verifies both signatures with cosign against the exact identity `https://github.com/<owner>/<repo>/.github/workflows/sandbox-image.yml@refs/heads/main` and GitHub Actions OIDC issuer. |

When run by GitHub Actions, the release gate downloads `eval-reports` and
`benchmark-reports` from the latest successful scheduled Eval run on `main`,
and `sandbox-digests` from the latest successful scheduled sandbox-image run
into `sandbox-artifacts/DIGESTS.md`. Before invoking the gate, the workflow
extracts both immutable image references and verifies their signatures with
cosign; the digest file itself records the image tags, source revision, and
UTC creation time. `workflow_dispatch` accepts explicit source run IDs for
recovery. The gate checks report age and requires benchmark source revisions
to be clean; eval provenance must identify the current release checkout.
Missing artifacts stay EXTERNAL, while malformed or insufficient reports
fail. A local invocation of `release_gate.py` checks the supplied digest
metadata but does not perform the workflow's cosign verification step.

Without flags the gate keeps the 4 EXTERNALs (no silent green). With valid
artifacts it can reach `GO` (exit 0). Stale/invalid evidence is a `FAIL`,
not EXTERNAL, so bad provenance cannot be mistaken for missing provenance.

## What `release.yml` publishes per tag after GO

- Python sdist + wheel (`dist/*`) with `SHA256SUMS`.
- CycloneDX SBOMs: Python (`sbom-python.json`), npm (`sbom-webui.json`),
  sandbox base packages (`sbom-sandbox.json`) and browser-worker packages
  (`sbom-sandbox-browser.json`). Both sandbox inventories come from the exact
  cosign-verified base/browser digests published by `sandbox-image.yml` and
  listed in `sandbox-image-refs.txt`.
- Trivy SARIF reports for both pinned sandbox images; HIGH/CRITICAL findings
  fail the release gate.
- Versioned Linux and Windows installers (`install-<tag>.sh` and
  `install-<tag>.ps1`), each with a SHA-256 file and GitHub build attestation.
- SLSA-style provenance via `actions/attest-build-provenance` (Sigstore,
  no maintainer keys to manage) for distributions, SBOMs, image-reference
  metadata, and both installers.

## Prebuilt sandbox image (#55)

`sandbox-image.yml` builds and signs the `nightly` channel (+ `:nightly-browser`)
on its weekly schedule or a maintainer dispatch from `main`:

```text
ghcr.io/<owner>/breachpilot-sandbox:nightly
ghcr.io/<owner>/breachpilot-sandbox:nightly-browser
```

Installer verify path: pull → verify cosign signature → record digest →
run with `sandbox.image` set to the digest. Until a successful scheduled
image artifact is supplied, `scripts/release_gate.py` keeps
`sandbox-image-published` EXTERNAL.

## Container scanning (#43)

The release workflow verifies the sandbox workflow's signed base and browser
digests, pulls those immutable references, and runs Syft/Trivy against those
same images. It does not rebuild a different local image for the scan.
Findings and both image references ship alongside the release assets;
assessment metadata keeps the sandbox image digest with every run
(`sandbox_image_digest` in benchmark/eval provenance).

## Rollback

Every release is a tag; rollback is `git checkout <prev-tag>` + repull the
previous image digest. No migrations ship without a documented reverse
(the completion report for each wave lists schema/config migrations).
