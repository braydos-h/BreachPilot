# P1: Flow A / Flow B duplication

## Problem
The audit finds Flow A (active engine) and Flow B (legacy path) coexisting with duplicated scope, auth, audit, and evidence policy. Two policy implementations must be kept in sync on every hardening or behavior change. At HEAD 995759f (v0.68.4) this duplication is flagged as a reliability risk for the 0.69 beta.

## Why it matters
Duplicate policy paths invite hardening skew: a fix applied to one flow can be missed in the other. This increases the chance of scope, authorization, audit, or evidence handling diverging silently.

## Recommended action
Freeze the legacy path and retire it on verified parity. No new behavior goes into Flow B; Flow A becomes the single maintained path once parity is demonstrated.

## Acceptance criteria
- [ ] Legacy Flow B path is declared frozen with no new behavior accepted
- [ ] Parity checklist for scope, auth, audit, and evidence behavior is defined
- [ ] Parity of the active flow against the checklist is verified and recorded
- [ ] Legacy path is retired or gated behind an explicit opt-in once parity passes
- [ ] Regression check confirms no duplicated policy decision remains on the default path

## Audit ref
Secs 18, 33 + commit 995759f (v0.68.4, reliability-focused 0.69 beta)
