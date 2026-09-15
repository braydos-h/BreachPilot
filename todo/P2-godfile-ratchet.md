# P2 Grandfathered god files can keep growing

## Problem
The audit finds grandfathered god files are tracked by a baseline that warns on growth but does not fail. As a result, already-oversized files can keep growing without blocking CI. This leaves the reliability-focused 0.69 beta without an enforceable ceiling on file growth.

## Why it matters
A warn-only baseline normalizes growth in the largest, hardest-to-maintain files. Without a failing check, debt ratchets upward and review burden, defect risk, and refactoring cost concentrate where change is already riskiest.

## Recommended action
Fail on growth above budget, and ratchet the baseline only downward: any baseline update must lower or hold the ceiling, never raise it.

## Acceptance criteria
- [ ] Growth beyond the budgeted size fails the check instead of warning only
- [ ] Baseline updates are allowed only when the new ceiling is equal to or lower than the prior ceiling
- [ ] A baseline increase attempt is rejected with a clear error message
- [ ] Reductions in file size can ratchet the baseline downward without manual override
- [ ] The check runs in CI on the relevant change path

## Audit ref
Secs 16, 33 + commit 995759f
