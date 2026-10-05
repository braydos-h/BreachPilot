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
green), coverage ≥80. Release workflow publishes installer + `.sha256` +
attestation (TODO 013), SBOMs + Trivy + digests. Verify:

```bash
gh run list --branch main   # HEAD health, link from release notes
gh api repos/OWNER/REPO/rulesets > branch-rules.json
python scripts/release_gate.py --branch-rules-file branch-rules.json --sandbox-digest-file worker-digests.txt --eval-dir "$EVAL_DIR" --json
```

Set `EVAL_DIR` to a directory containing fresh JSON reports from an actual
evaluation run. This repository does not ship live evaluation artifacts.

## Gate first

```bash
python scripts/release_gate.py
python scripts/release_gate.py --eval-dir "$EVAL_DIR" --sandbox-digest-file worker-digests.txt --branch-rules-file branch-rules.json --json
```

`GO` requires every local box green and no EXTERNAL box outstanding. Each
EXTERNAL is satisfiable via an evidence artifact (safe default is EXTERNAL
when the file is missing; present-but-invalid fails closed):

| Gate box | Artifact | Contract |
|---|---|---|
| `live-eval-backend` | `--eval-dir DIR` + `--source-revision SHA` | At least one recursively discovered JSON report has complete known provenance from the release source revision, `PASS`, exact full-suite target coverage, zero false-positive claims, measured scope telemetry equal to 0, executed trial records, and a supported positive target with a captured flag plus a matching expected finding; mtime <90d |
| `repeated-trials` | same `--eval-dir` | At least five distinct full-suite run IDs with identical target coverage and identical model, configuration, prompt/catalog, sandbox, and source pins; targets within one suite report do not count as repeats |
| `branch-rules-applied` | `--branch-rules-file rules.json` | Active main ruleset requires every documented CI, eval, CodeQL, and dependency check; requires PRs; blocks deletion/force-push; and has no bypass actors (see `docs/branch-protection.md`) |
| `sandbox-image-published` | `--sandbox-digest-file digests.txt` | Text from the successful sandbox-image workflow with a `sha256:<hex>` image digest and a `Source commit` matching the release SHA |

Without flags the gate keeps the 4 EXTERNALs (no silent green). With valid
artifacts it can reach `GO` (exit 0). Stale/invalid evidence is a `FAIL`,
not EXTERNAL, so bad provenance cannot be mistaken for missing provenance.

## What `release.yml` publishes per tag

- A successful tag-triggered run creates a public GitHub Release only after the
  protected-main ancestry/CI check, GO gate, and artifact build complete. The
  gate selects successful eval and sandbox-image runs whose source SHA matches
  the tag commit; absent or unsuccessful evidence keeps NO-GO.
  It publishes the Python distributions
  and their `dist/SHA256SUMS`, all three SBOMs, sandbox digests, the Trivy
  report, and the versioned installer files. The job creates a draft release,
  uploads assets with the GitHub CLI, then publishes it. Reruns replace assets
  with matching names and preserve the release title and notes. A
  `workflow_dispatch` run from main evaluates the gate but does not build or
  create/update a public GitHub Release.
- Release permissions are job-scoped: dependency installation and artifact
  builds have read-only repository access and no OIDC token. A separate
  attestation job receives only OIDC/attestation rights, and the publisher
  downloads the finished artifact with `contents: write`; checkout
  credentials are not persisted in the build jobs.
- Python sdist + wheel (`dist/*`) with `SHA256SUMS`; both include the built
  WebUI under `tools/webui/dist/` so installed wheels can serve the SPA without
  a checkout or Node.js.
  The build uses the checked-out commit timestamp as `SOURCE_DATE_EPOCH`; the
  sdist normalizer sorts members and fixes ownership, permissions, tar times,
  and gzip time before checksums and attestations are produced. It preserves
  file payloads and symlink targets.
- CycloneDX SBOMs: Python (`sbom-python.json`), npm (`sbom-webui.json`),
  sandbox OS packages (`sbom-sandbox.json`, from the built worker image).
- SLSA-style provenance via `actions/attest-build-provenance` (Sigstore,
  no maintainer keys to manage) for `dist/*` and all SBOMs.
- Sandbox image digests: the workflow scans the tag-built digest-pinned image produced
  and signed by the sandbox-image workflow, then attaches `base-digest.txt`
  and the published worker digest evidence to the GitHub Release. The sandbox
  image workflow separately retains `DIGESTS.md` as an Actions artifact with
  the source commit bound to the release tag.
  Evaluation must run the pinned `breachpilot-sandbox@sha256:...` digest —
  never a floating tag — so benchmarks reproduce exactly.

## Prebuilt sandbox image (#55)

`sandbox-image.yml` builds `breachpilot-sandbox:<version>` (+ `:browser`
variant) on release tags, and `:nightly` variants from scheduled/manual main
runs; it pushes to GHCR with keyless cosign signing after the source commit's
CI succeeds:

```text
ghcr.io/<owner>/breachpilot-sandbox:v0.69.0
ghcr.io/<owner>/breachpilot-sandbox:v0.69.0-browser
```

The browser variant uses the exact base-image digest from the preceding build
step. `DIGESTS.md` records the source ref because cosign identity differs for
main-branch and version-tag builds.

Installer verify path: pull → verify cosign signature using the identity in
`DIGESTS.md` → record digest →
run with `sandbox.image` set to the digest. Until the first push lands,
`scripts/release_gate.py` keeps `sandbox-image-published` EXTERNAL.

## Container scanning (#43)

The release workflow scans all three SBOMs plus the worker image
(Trivy, HIGH/CRITICAL fail the gate). Findings ship alongside the release
notes; the assessment metadata keeps the image digest with every run
(`sandbox_image_digest` in benchmark/eval provenance).

## Rollback

Every release is a tag; rollback is `git checkout <prev-tag>` + repull the
previous image digest. No migrations ship without a documented reverse
(the completion report for each wave lists schema/config migrations).
