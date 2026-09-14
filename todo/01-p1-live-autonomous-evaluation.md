# P1 — Make live autonomous evaluation real

Owner: _unassigned_  
Tracking issue/PR: _not created_  
Status: Blocked by green `main`

## Goal

Make live graded evaluation an explicit, trustworthy signal of autonomous
behavior. A skipped live run must never be presented as a passed live run.

## Problem statement

The assessed scheduled workflow did not execute its live graded evaluation
because `OLLAMA_API_KEY` was unavailable. The workflow treated this as a
successful graceful skip and then ran mocked evaluation tests. That makes a
green Eval check ambiguous: it does not prove autonomous exploitation ran.

Unit tests alone cannot show whether the agent loops, follows the wrong branch,
misclassifies compromise, ignores discovered credentials, or wastes its action
budget on enumeration.

## Tasks

- [ ] Provision and document a real supported model backend for scheduled live
  evaluation, using environment-only credentials.
- [ ] Split mocked evaluation and live graded evaluation into separately named
  checks.
- [ ] Represent live outcomes distinctly as `PASS`, `FAIL`, `SKIPPED`, or
  `INFRA_ERROR`.
- [ ] Ensure missing credentials produce a visible non-pass status rather than
  a green live-evaluation signal.
- [ ] Always upload structured JSON plus a human-readable report, including on
  partial failure, timeout, or infrastructure error.
- [ ] Record model/provider identity, scenario version, code revision, seed or
  sampling controls, duration, action budget, and sandbox configuration.
- [ ] Add the metrics below to the evaluation schema and summary.
- [ ] Add regression thresholds for the safety- and reliability-critical
  metrics.
- [ ] Run repeated trials for at least one representative scenario and confirm
  the report is reproducible enough to detect behavioral regressions.
- [ ] Document how maintainers inspect, rerun, and interpret a live evaluation.

## Required metrics

| Metric | Purpose |
|---|---|
| Independently verified compromise rate | Primary real success signal |
| False-compromise rate | Prevent unsupported success claims |
| Stuck-loop rate | Detect autonomous reasoning failure |
| Duplicate action count | Measure wasted turns |
| Mean actions to verified objective | Measure efficiency |
| Timeout rate | Detect broken or unproductive paths |
| Scope-policy rejection rate | Reveal agent/sandbox disagreement |
| Tool execution and error rate | Surface integration failures |
| Token/model cost per successful scenario | Track deployment practicality |
| Success rate by vulnerability family | Expose capability gaps |

## Acceptance criteria

- The workflow UI clearly distinguishes mocked tests from live execution.
- A missing key or unavailable backend cannot produce a live `PASS`.
- Every attempted live run retains a report artifact, even when incomplete.
- Success requires independent verification, not only the model's claim.
- Reports expose loops, duplicate actions, errors, timeouts, policy rejections,
  and cost.
- At least one repeated live scenario produces a versioned, reviewable result.

