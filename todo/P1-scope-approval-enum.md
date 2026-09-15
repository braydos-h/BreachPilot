# P1 Scope approval encoded as allowed+requires_approval

## Problem
Scope decisions are currently expressed as an allowed flag paired with a separate requires-approval flag. This two-bool shape lets a caller check the first value and drop the second, silently converting approval-gated work into allowed work. The audit found this exact misuse in AttackModuleExecutor, which ignores the second bool.

## Why it matters
The pair is a dangerous API shape because the unsafe default is invisible: any caller that forgets or skips the second check proceeds as if approved. In a reliability-focused 0.69 beta built on an authorized-testing engine, an approval bypass can turn a gated action into an executed one without an explicit operator decision.

## Recommended action
Replace the allowed + requires_approval pair with a single DENY / ALLOW / REQUIRES_APPROVAL enum so every call site must handle all three outcomes. Add a LabAutoApprovalPolicy adapter to preserve the current lab posture by explicitly mapping REQUIRES_APPROVAL to an auditable auto-approval decision at one chokepoint.

## Acceptance criteria
- [ ] Scope check returns a single three-state verdict (DENY / ALLOW / REQUIRES_APPROVAL) with no separate approval boolean
- [ ] All existing callers handle the REQUIRES_APPROVAL state explicitly with no silent fallthrough to allow
- [ ] LabAutoApprovalPolicy adapter centralizes the lab auto-approval mapping and records each auto-approved decision
- [ ] Regression test proves the AttackModuleExecutor path requests approval instead of proceeding silently
- [ ] Existing scope-gate tests pass unchanged in intent under the new enum shape

## Audit ref
Secs 4, 33 + commit 995759f
