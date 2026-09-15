# P0: MCP decorator invariant weaker than target-authorization need

## Problem
The current MCP tool registration invariant checks decorator presence but does not guarantee target authorization. A future target-touching tool could satisfy the invariant with audit-only decoration while missing allowlist enforcement. Audit Secs 5 and 33 flag this gap as weaker than what target authorization requires.

## Why it matters
Audit-only coverage records execution without preventing off-target execution. One future tool added with the weaker decoration would create an authorization bypass by omission. The property must therefore hold by check, not by reviewer memory.

## Recommended action
Cross-check target params plus the tool manifest against required allowlist enforcement in CI and at runtime. Deny registration or execution when a target-capable tool lacks the required allowlist enforcement, without introducing new architecture beyond the audit recommendation.

## Acceptance criteria
- [ ] Every existing target-touching tool is inventoried and confirmed to require allowlist enforcement, not audit-only
- [ ] CI fails when a tool declaring target params or manifest target capability lacks required allowlist enforcement
- [ ] Runtime denies a target-touching call that lacks allowlist authorization
- [ ] Manifest-declared target capability is cross-checked against enforced allowlist requirement

## Audit ref
Secs 5, 33 + commit 995759f (v0.68.4, reliability-focused 0.69 beta)
