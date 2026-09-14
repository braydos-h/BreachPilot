# 01. Stop optimizing the tool count

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14) |
| Suggested priority | P0 |
| Suggested horizon | Backlog |
| Theme | Strategy and evaluation |
| Dependencies | None recorded; confirm during scoping. |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

Audit claim revalidated 2026-09-14: accurate. README:21 led with
`139 skills, 153 MCP tools across 33 tool families` while generated catalogs said
167 tools / 37 families and 146 skills — stale and capability-centered.

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [x] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [x] Add or update focused tests and evaluation coverage where applicable.
- [x] Update generated and user-facing docs/config contracts where applicable.
- [ ] Record completion evidence below and update [the backlog index](../README.md).

Slice 1: `docs/reliability-metrics.md` + README headline rewrite + stale-count guard.
No scope/allowlist/sandbox/evidence code touched.

## Requirements called out by the audit

- [x] **Verified compromise rate** — `ReliabilityMetrics.verified_compromise_rate` / benchmark `verified_success_rate`
- [x] **False-compromise rate** — `false_compromise_rate` / `false_positive_rate`
- [x] **Median actions to verified finding** — `mean_actions_to_verified_objective` / `median_tool_actions`
- [x] **Cost per verified finding** — benchmark `estimated_cost` + eval `tokens_per_verified_scenario` (pricing-dependent)
- [x] **Run completion rate** — `trials_completed / trials_total` (infra errors excluded)
- [x] **Stuck-loop rate** — `stuck_loop_rate`
- [x] **Duplicate action rate** — `duplicate_action_count`
- [x] **Tool failure rate** — `tool_error_rate`
- [ ] **Percentage of findings reproduced twice** — retest path exists; aggregation pending #02 Level C
- [x] **Scope violations reaching network layer: 0** — sandbox netns + allowlist invariant (attempts tracked as `scope_rejection_rate`)
- [ ] **Mean time from finding → verified remediation** — pending finding lifecycle #04

## Audit recommendation

The README currently leads heavily with:

> 139 skills, 153 MCP tools, 33 tool families, 15 attack families, 6 swarm agents.

Yet the repository's own documentation-generation work says the source-derived catalog has already moved to **167 tools and 146 skills**.

There are two lessons here.

First, static capability counts rot quickly.

Second, tool count is not a meaningful measure of an autonomous pentester.

A platform with 40 extremely reliable primitives that successfully verifies 75% of a benchmark is more useful than one with 200 tools that autonomously succeeds 30% of the time.

## Replace the headline metrics

I would stop making raw skill/tool count central to the product positioning.

Make these the core numbers instead:

* **Verified compromise rate**
* **False-compromise rate**
* **Median actions to verified finding**
* **Cost per verified finding**
* **Run completion rate**
* **Stuck-loop rate**
* **Duplicate action rate**
* **Tool failure rate**
* **Percentage of findings reproduced twice**
* **Scope violations reaching network layer: 0**
* **Mean time from finding → verified remediation**

Those are defensible product metrics.

Conveniently, your current P1 evaluation design already recognizes most of these.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: (slice 1 done; live-number publication pending #02 Level C)
- Design/issue: Wave 0 — reliability-led positioning
- Commits/PRs: working-tree: docs/reliability-metrics.md (new), README.md headline +
  146/167 count fixes, tests/test_config_semantic_truth.py +1 guard test
- Tests/evaluations: tests/test_config_semantic_truth.py 6 passed
- Documentation: docs/reliability-metrics.md defines all 11 metrics with code sources
  and honest TBD status; README links generated catalogs instead of hardcoding rot
- Follow-ups: publish live numbers only after repeated hermetic trials (#02C, #38);
  wire reproduced-twice aggregation and MTTR collection under #04.

