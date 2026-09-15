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
python scripts/release_gate.py --branch-rules-file branch-rules.json --sandbox-digest-file worker-digests.txt --eval-dir reports/eval/2026-09-15-baseline --json
```

## Gate first

```bash
python scripts/release_gate.py
python scripts/release_gate.py --eval-dir reports/eval/2026-09-15 --sandbox-digest-file worker-digests.txt --branch-rules-file branch-rules.json --json
```

`GO` requires every local box green and no EXTERNAL box outstanding. Each
EXTERNAL is satisfiable via an evidence artifact (safe default is EXTERNAL
when the file is missing; present-but-invalid fails closed):

| Gate box | Artifact | Contract |
|---|---|---|
| `live-eval-backend` | `--eval-dir DIR/*.json` | >=1 JSON with a `provenance` object carrying all 16 `RunProvenance` fields (see `scripts/release_gate.py:check_provenance_fields` + TODO 018); mtime <90d |
| `repeated-trials` | same `--eval-dir` | >=5 valid provenance files, or any file with `provenance.trials >= 5` (TODO 001: 5–10×/scenario) |
| `branch-rules-applied` | `--branch-rules-file rules.json` | JSON from `gh api repos/OWNER/REPO/rulesets` naming `main`, active enforcement, requiring CI checks (see `docs/branch-protection.md`) |
| `sandbox-image-published` | `--sandbox-digest-file digests.txt` | text containing `sha256:<hex>` (e.g. `worker-digests.txt` from `release.yml`); local digest mismatch fails |

Without flags the gate keeps the 4 EXTERNALs (no silent green). With valid
artifacts it can reach `GO` (exit 0). Stale/invalid evidence is a `FAIL`,
not EXTERNAL, so bad provenance cannot be mistaken for missing provenance.

## What `release.yml` publishes per tag

- Python sdist + wheel (`dist/*`) with `SHA256SUMS`.
- CycloneDX SBOMs: Python (`sbom-python.json`), npm (`sbom-webui.json`),
  sandbox OS packages (`sbom-sandbox.json`, from the built worker image).
- SLSA-style provenance via `actions/attest-build-provenance` (Sigstore,
  no maintainer keys to manage) for `dist/*` and all SBOMs.
- Sandbox image digests: the workflow resolves the base (`debian:12-slim`)
  to its digest at build time and records the built worker digest; both land
  in the release notes and in `docker/sandbox/DIGESTS.md` for that tag.
  Evaluation must run the pinned `breachpilot-sandbox@sha256:...` digest —
  never a floating tag — so benchmarks reproduce exactly.

## Prebuilt sandbox image (#55)

`sandbox-image.yml` builds `breachpilot-sandbox:<version>` (+ `:browser`
variant) on release tags and pushes to GHCR with keyless cosign signing:

```text
ghcr.io/<owner>/breachpilot-sandbox:v0.69.0
ghcr.io/<owner>/breachpilot-sandbox:v0.69.0-browser
```

Installer verify path: pull → verify cosign signature → record digest →
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
