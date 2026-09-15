# P0: Live autonomous reliability not empirically demonstrated

## Problem
At HEAD 995759f (version 0.68.4), reliability improvements for the 0.69 beta are not backed by repeated hermetic live trials. The audit finds no live matrix demonstrating stable autonomous behavior across repeated runs. The core reliability claim therefore remains asserted rather than empirically demonstrated.

## Why it matters
Core product claim is unproven. Without a repeated hermetic live matrix, regressions, flakiness, and environment-dependent failures can ship undetected into the reliability-focused 0.69 beta.

## Recommended action
Run repeated hermetic trials, publish the results matrix, and make the pass/stability thresholds release-blocking for 0.69.

## Acceptance criteria
- [ ] Repeated hermetic live trials of autonomous runs are executed and recorded
- [ ] Results matrix is published showing per-trial outcome and failure causes
- [ ] Minimum pass/stability thresholds are defined for the 0.69 beta
- [ ] Thresholds are enforced as release-blocking, with a documented go/no-go decision
- [ ] Trial failures are triaged into fixes or explicitly accepted known issues

## Audit ref
Secs 13-15, 33 + commit 995759f
