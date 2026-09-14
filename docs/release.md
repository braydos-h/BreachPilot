# Release process — reproducible, signed, digest-pinned (#42/#43/#44/#55/#80)

## Gate first

```bash
python scripts/release_gate.py
```

`GO` requires every local box green and no EXTERNAL box outstanding. The
current EXTERNAL boxes (live backend, repeated trials, branch rules,
published image) each name their unblocking action. Do not ship on `NO-GO`.

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
