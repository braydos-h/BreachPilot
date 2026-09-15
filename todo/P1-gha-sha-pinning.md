# P1 GitHub Actions use mutable major tags

## Problem
Workflows reference third-party GitHub Actions by mutable major tags rather than immutable commit SHAs. A compromised or re-pointed tag can silently change the code executed in CI without any change to this repository. This leaves the pipeline trust story weaker than the release artifact story.

## Why it matters
CI executes privileged build, test, and release steps on every push and PR. Mutable action references widen the supply-chain attack surface: tag takeover or upstream rewrite becomes remote code execution in the build. SHA pinning makes pipeline dependencies verifiable and reviewable, consistent with the reliability hardening expected for the 0.69 beta.

## Recommended action
SHA-pin all third-party GitHub Actions and enable automated updates with Dependabot version updates.

## Acceptance criteria
- [ ] All third-party Actions are pinned to full commit SHAs with a human-readable version comment
- [ ] No mutable major-only or floating tags remain for third-party Actions
- [ ] Dependabot is configured to propose Action SHA updates on a regular schedule
- [ ] A fresh CI run passes with pinned SHAs and no workflow errors
- [ ] Pinning policy is documented so new Actions are added SHA-pinned

## Audit ref
Secs 22, 33 + commit 995759f
