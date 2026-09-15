# P1 Credential vault can fall back to plaintext

## Problem
The credential vault can fall back to plaintext storage when secure storage is unavailable. The fallback currently proceeds with warning-only handling. This leaves stored secrets unencrypted on disk in exactly the failure case where protection matters most.

## Why it matters
Warning-only handling is weak for harvested secrets. Plaintext persistence exposes credentials to any reader of the operator box and undermines the audit trail for sensitive material.

## Recommended action
Fail closed on vault secure-storage failure unless `BREACHPILOT_ALLOW_PLAINTEXT_VAULT=1` is explicitly set.

## Acceptance criteria
- [ ] Vault refuses plaintext fallback by default and returns an error instead of writing
- [ ] Plaintext fallback occurs only when `BREACHPILOT_ALLOW_PLAINTEXT_VAULT=1` is set
- [ ] Every fallback or refusal emits a clear warning or error identifying the cause
- [ ] No silent downgrade path remains in the default configuration
- [ ] Regression test covers default fail-closed behavior and explicit opt-in override

## Audit ref
Secs 12, 33 + commit 995759f
