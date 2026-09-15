# P2: UI exposes internal architecture over assessment workflow

## Problem
The WebUI surfaces internal subsystems and architecture concepts as top-level navigation instead of leading with the assessment workflow. Operators must translate between system internals and their actual task of running an assessment and reviewing findings. Audit Secs 27 and 33 flag this as an information-architecture mismatch with the operator's mental model.

## Why it matters
It raises cognitive load for every run, forcing operators to learn architecture before they can assess a target. It reduces product cohesion by presenting a toolkit of subsystems rather than a coherent assessment flow.

## Recommended action
Redesign WebUI information architecture around assessment/findings-first flow, with internal subsystems moved to advanced views.

## Acceptance criteria
- [ ] Default WebUI entry point presents assessment workflow and findings first, not subsystem views
- [ ] Internal subsystems are reachable only via clearly labeled advanced views
- [ ] Operator can complete start-assessment to review-findings flow without passing through subsystem-level screens
- [ ] Navigation labels reflect operator tasks rather than internal architecture names
- [ ] Redesign is verified against audit Secs 27 and 33 with no unresolved IA findings

## Audit ref
Secs 27, 33 + commit 995759f (version 0.68.4, reliability-focused 0.69 beta)
