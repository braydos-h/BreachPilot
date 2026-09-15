# P0 Plugin safety is trust/documentation based

## Problem
Third-party plugin code runs as trusted host Python with the same privileges as the core engine. Per the audit, plugin safety currently rests on trust and documentation rather than enforced isolation or capability boundaries. A malicious or compromised plugin can therefore bypass the built-in safety guarantees.

## Why it matters
Third-party code runs as trusted host Python and bypasses built-in guarantees. One untrusted plugin is sufficient to undermine scope, safety, and audit controls for the whole run.

## Recommended action
Adopt an explicit trusted-only plugin posture until plugins are isolated, centrally capability-gated, and have recorded provenance. Do not treat untrusted third-party plugins as safe based on documentation alone.

## Acceptance criteria
- [ ] Plugin use is documented and enforced as trusted-only until isolation exists
- [ ] Untrusted third-party plugins are refused or require explicit operator trust decision
- [ ] Plugin capabilities are gated through a central enforcement point, not self-declared
- [ ] Provenance (source/version/trust decision) is recorded for every loaded plugin
- [ ] A plugin bypass attempt or untrusted load is denied and auditable

## Audit ref
Secs 10, 33 + commit 995759f (version 0.68.4, reliability-focused 0.69 beta)
