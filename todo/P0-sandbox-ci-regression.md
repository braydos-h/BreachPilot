# P0: Real-Docker sandbox CI failing at HEAD

## Problem
HEAD 995759f (version 0.68.4, ahead of the reliability-focused 0.69 beta) has the real-Docker sandbox CI failing, per audit Secs 7-8, 33. The failure is unresolved at HEAD, so the current commit is not green. The root cause is not yet classified as infrastructure flake versus product regression.

## Why it matters
The sandbox is the primary security boundary. A reliability release cannot ship while its main isolation boundary is red, because 995759f is not green.

## Recommended action
Reproduce the sandbox integration failure, classify it as infra versus code regression, land the fix, and gate the 0.69 release on green sandbox CI.

## Acceptance criteria
- [ ] Real-Docker sandbox integration failure reproduced from HEAD 995759f
- [ ] Failure classified as infrastructure flake or code regression with evidence recorded
- [ ] Fix landed so the real-Docker sandbox CI job passes
- [ ] 0.69 release gate requires green real-Docker sandbox CI before ship

## Audit ref
Secs 7-8, 33 + commit 995759f
