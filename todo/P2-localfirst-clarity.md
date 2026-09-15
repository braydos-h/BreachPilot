# P2 "Local-first" implies stronger data locality than hosted inference

## Problem
BreachPilot is positioned as local-first, but default inference paths use hosted providers (opencode_go / Ollama Cloud). Assessment prompts, findings context, and target-derived material sent for inference therefore leave the operator box despite the local-first framing.

## Why it matters
Operators handling sensitive assessment data may assume it never leaves the box. Undisclosed inference egress creates mishandling, contractual, and authorization risk for bug-bounty and enterprise assessment work.

## Recommended action
Position BreachPilot as local control/execution with pluggable inference, not full data locality. Explicitly surface inference egress: where prompts go, when hosted inference is active, and how to stay local-only.

## Acceptance criteria
- [ ] User-facing copy no longer claims assessment data stays on-box when hosted inference is configured
- [ ] Docs state which inference paths send data off-box and which keep it local
- [ ] Active inference destination/egress is surfaced to the operator before or during a run
- [ ] Operator has a documented local-only inference option or explicit hosted-inference acknowledgment
- [ ] Release notes for the reliability-focused 0.69 beta reflect the clarified positioning

## Audit ref
Secs 28, 33 + commit 995759f (version 0.68.4)
