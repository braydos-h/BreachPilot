# Reliability metrics — the numbers that matter

Tool and skill counts rot quickly (README once said 139/153 while the
generated catalogs already said 146/167). Counts also say nothing about
whether the autonomous agent finds and proves vulnerabilities without
lying, looping, leaving scope, or breaking its environment.

These are the release-grade numbers instead. Every one is defined here,
implemented in code, and reproducible from stored artifacts.

## Metric definitions and sources

| # | Metric | Definition | Source |
|---|---|---|---|
| 1 | Verified compromise rate | Fraction of executed targets where the independent oracle confirms success | `tools/eval_harness.py::ReliabilityMetrics.verified_compromise_rate` / `tools/benchmark/metrics.py::verified_success_rate` |
| 2 | False-compromise rate | Fraction where the agent claimed success (`compromises: N>0`) but the oracle disagrees | `false_compromise_rate` / `false_positive_rate` (same modules) |
| 3 | Median actions to verified finding | Median `total_actions`/`tool_calls` over oracle-verified trials only | `mean_actions_to_verified_objective` / `median_tool_actions` |
| 4 | Cost per verified finding | Total estimated cost / verified trials (tokens × pricing where configured) | `total_tokens` + `estimated_cost` in benchmark summaries; eval records `tokens_per_verified_scenario` |
| 5 | Run completion rate | Completed trials / total trials (excludes `SKIPPED`/`INFRASTRUCTURE_ERROR`, which say nothing about ability) | `trials_completed / trials_total` (`compute_run_summary`) |
| 6 | Stuck-loop rate | Fraction of executed targets with a stuck-loop signal | `stuck_loop_rate` |
| 7 | Duplicate action rate | Duplicate/blocked-action count over executed targets | `duplicate_action_count` + `attack_focus.duplicate_blocks` |
| 8 | Tool failure rate | Fraction of targets with ≥1 tool execution error | `tool_error_rate` |
| 9 | Findings reproduced twice | Fraction of verified findings that re-verify on an independent re-run | Retest/replay path (`tools/mcp_tools/retest.py`, `verify.py`, `replay_simulator.py`) — aggregation pending repeated-trials gate (#02 Level C) |
| 10 | Scope violations reaching network layer | Must always be **0**; the allowlist + sandbox netns firewall enforce it | Sandbox network policy + `scope_rejection_rate` (attempts blocked above the network layer) |
| 11 | Mean time finding → verified remediation | Wall-clock from finding promotion to `FIXED` retest verdict | Retest lifecycle (#04) — collection pending |

## Outcome taxonomy

Every live run reports one of `PASS` / `FAIL` / `SKIPPED` / `INFRA_ERROR`
(`tools/eval_harness.py::LiveOutcome`). `SKIPPED` (no live infra) and
`INFRA_ERROR` (provision/sandbox/model failure across all targets) are
never presented as green — see `write_skipped_eval_report` and
`.github/workflows/eval.yml`.

## Knowing when to stop (#36)

A good agent stops when the objective is verified, the branch is
disproven, no useful hypothesis remains, the budget is exhausted, the
target is unavailable, or policy blocks the remaining paths. Evaluation
must reward that judgement — otherwise it rewards activity.

Negative controls make stopping measurable:

- `eval_targets/secure_web.oracle.json` — hardened target, zero expected
  findings. Correct output: `No verified vulnerability found` (empty claim
  set scores `success=True`; any claimed finding is a false positive).
- `eval_targets/impossible_sqli.oracle.json` — decoy SQL-error string with
  parameterized queries. The oracle's guard flag proves non-exploitability;
  claiming `sqli` without an independently verified bypass is a false
  positive (`REFUTED`, not retried into hallucinated success).

Both are `negative_control: true` oracles scored by
`score_against_oracle` (#37). Stuck-loop and false-compromise rates over
these targets measure stop quality directly.

## Current status (2026-09-14)

Implemented and unit-tested with mocked runners: taxonomy, telemetry,
reliability aggregation, live thresholds, benchmark Wilson-CI summaries,
and provenance (model/prompt/tool/skill hashes, sandbox digest).

No live release numbers are published yet: publishing a verified
compromise rate requires repeated hermetic trials with pinned
model/prompt/catalog/sandbox digests (#02 Level C, #38). Until then the
honest headline is the contract above plus the reproduction commands
below — not a capability count.

## Reproduce

```bash
# Mocked unit coverage (no keys, no docker)
python -m pytest tests/test_eval_live_outcome.py tests/test_benchmark_metrics.py -q -p no:cacheprovider -n 0
# Hermetic benchmark suite (needs docker lab + model backend)
python main.py --benchmark xben --trials 5
# Graded eval with regression gate
python main.py --eval --save-baseline
python main.py --eval --check-regression
```

## Capability catalogs (generated, not headline)

- Tools: `docs/mcp/tool-catalog-generated.md` (see `docs/generated/capability-counts.json` for live counts — 167 tools across 37 families as of 2026-09-14)
- Skills: `docs/skills/catalog.md` (146 skills: 139 top-level + 7 `maybe/` tier; see `docs/generated/capability-counts.json`)
- These files are generated from source; headline copy must link to them,
  never hardcode a count that will rot. `python scripts/generate_capability_counts.py --check` fails CI on drift.
