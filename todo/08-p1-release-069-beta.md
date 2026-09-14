# P1 — Ship the reliability-focused 0.69 beta

Owner: _unassigned_  
Tracking issue/PR: _not created_  
Status: Blocked by CI, live evaluation, and benchmark work

## Goal

Publish the next beta only after BreachPilot can demonstrate reproducible,
sandboxed autonomous behavior. Treat 0.69 as a reliability/evaluation release,
not a feature expansion release.

## Context

At assessment time the source reported 0.68.4, while the public GitHub
prerelease was effectively v0.49.2 from July and still referenced the old
`NetCheckAi` repository. Re-check both values before release work begins.

## Release blockers

- [ ] Latest `main` is green across supported Python versions and all required
  sandbox, browser, WebUI, package, lint, type, and security jobs.
- [ ] Live graded evaluation runs against a real backend and cannot confuse
  `SKIPPED` with `PASS`.
- [ ] A reproducible live report demonstrates independent compromise
  verification and acceptable false-positive/loop behavior.
- [ ] Scheduled XBEN compares against a versioned baseline without overwriting
  it.
- [ ] The benchmark uses the production sandbox execution path.
- [ ] `main` has an appropriate required-check ruleset.
- [ ] `SECURITY.md` and current release documentation are present.

## Automation tasks

- [ ] Define the final version, for example `0.69.0b1`, in every authoritative
  packaging location.
- [ ] Trigger releases from signed or protected version tags.
- [ ] Build wheel and source distribution from a clean checkout.
- [ ] Run package installation and import/CLI smoke tests on the built artifacts.
- [ ] Generate SHA-256 checksums.
- [ ] Generate an SBOM and attach provenance/attestation where supported.
- [ ] Produce release notes from reviewed changes and known limitations.
- [ ] Attach or link the exact live-eval and benchmark reports qualifying the
  release.
- [ ] Replace stale v0.49/`NetCheckAi` metadata and links.
- [ ] Document rollback/yank criteria for a bad beta.
- [ ] Verify the published artifacts by downloading and testing them after
  release.

## Exit criteria

- A known vulnerable lab target can be completed through the intended autonomous
  Plan → Recon → Exploit → Verify → Report path.
- The run remains explicitly scoped and uses the default-on sandbox.
- Failed branches do not create unbounded repeated actions.
- Compromise is reported only with independent evidence.
- Repeated graded runs meet the agreed regression thresholds.
- Published wheel, sdist, checksums, SBOM/provenance, notes, and qualification
  evidence correspond to the same tagged source revision.

## After the beta

Resume capability expansion only when the evaluation matrix identifies a
specific gap. New attack families should arrive with a scenario and oracle that
show the missing capability and prevent regression.

