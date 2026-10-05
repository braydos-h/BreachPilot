# Reliability metrics — the numbers that matter

Tool and skill counts rot quickly (README once said 139/153 while the
generated catalogs already said 146/167). Counts also say nothing about
whether the autonomous agent finds and proves vulnerabilities without
lying, looping, leaving scope, or breaking its environment.

These are the release-grade numbers instead. Every one is defined here, with
collection status called out below; a defined metric is not claimed as
measured evidence until its producer is wired and the report records it.

## Metric definitions and sources

| # | Metric | Definition | Source |
|---|---|---|---|
| 1 | Verified compromise rate | Fraction of executed targets where the independent oracle confirms success | `tools/eval_harness.py::ReliabilityMetrics.verified_compromise_rate` / `tools/benchmark/metrics.py::verified_success_rate` |
| 2 | False-compromise rate | Fraction where the agent claimed success (`compromises: N>0`) but the oracle disagrees | `false_compromise_rate` / `false_positive_rate` (same modules) |
| 3 | Actions to verified finding | Mean `total_actions` across verified eval targets; median tool actions across verified benchmark trials | `mean_actions_to_verified_objective` / `median_tool_actions` |
| 4 | Cost per verified finding | Total estimated cost / verified trials (tokens × pricing where configured) | `total_tokens` + `estimated_cost` in benchmark summaries; eval records `tokens_per_verified_scenario` |
| 5 | Run completion rate | Completed trials / total trials (excludes `SKIPPED`/`INFRASTRUCTURE_ERROR`, which say nothing about ability) | `trials_completed / trials_total` (`compute_run_summary`) |
| 6 | Stuck-loop rate | Fraction of executed targets with a stuck-loop signal | `stuck_loop_rate` |
| 7 | Duplicate action rate | Duplicate/blocked-action count over executed targets | `duplicate_action_count` + `attack_focus.duplicate_blocks` |
| 8 | Tool failure rate | Fraction of targets with ≥1 tool execution error | `tool_error_rate` |
| 9 | Findings reproduced twice | Fraction of verified findings that re-verify on an independent re-run | `tools/mcp_tools/verify.py::is_reproduced_twice` / `count_reproduced_twice` (proof-capsule runs ≥2, or ≥2 VERIFIED verdicts) → `tools/eval_harness.py::aggregate_finding_lifecycle` → `ReliabilityMetrics.findings_reproduced_twice_rate`; benchmark run level: `ScenarioSummary.reproduced_twice` (verified ≥2 across ≥2 trials via `meets_repeated_trials_gate`) → `RunSummary.reproduced_twice_rate` (null when no scenario has a verified trial) |
| 10 | Scope violations reaching network layer | Must always be **0**; the allowlist + sandbox netns firewall enforce it | `scope_rejection_rate` records attempts blocked before the network layer. The `scope_violation_count` consumer and gates exist, but the runtime producer that observes violations past containment is not wired yet; reports preserve this as unavailable and release/baseline gates fail closed. |
| 11 | Mean time finding → verified remediation | Wall-clock from finding promotion to `FIXED` retest verdict | `tools/mcp_tools/retest.py::aggregate_retest_lifecycle` (last `FIXED` − first `VERIFIED` over parseable timestamps; unparseable excluded, never fabricated) → `ReliabilityMetrics.mean_time_to_remediation_seconds` / `remediated_count` |

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

Negative-control scoring rules define how stopping should be measured, but the
two checked-in controls below are currently skipped in live eval because the
compose suite does not provision their services. Unit tests for their scorer
semantics are not live reliability evidence:

- `eval_targets/secure_web.oracle.json` — unsupported until a local hardened
  service and an independent safe-state check exist.
- `eval_targets/impossible_sqli.oracle.json` — unsupported until a local
  service and its non-exploitability check are provisioned.

Both remain `negative_control: true` scoring fixtures for
`score_against_oracle` (#37). Stuck-loop and false-compromise rates over these
targets are unavailable until live verification is supported.

## Current status (2026-09-21)

Implemented and unit-tested with mocked runners: taxonomy, telemetry,
reliability aggregation, live thresholds, benchmark Wilson-CI summaries,
and provenance (model/prompt/tool/skill hashes, sandbox digest).

Aggregation for the two pending metrics is wired (no live numbers yet):

- **Findings reproduced twice (#9)** — verify proof capsules aggregate via
  `tools/mcp_tools/verify.py::count_reproduced_twice` (repeated-trials gate:
  ≥2 independent proof runs) into `ReliabilityMetrics`, and per-scenario via
  `ScenarioSummary.reproduced_twice` (verified ≥2 across ≥2 trials) into
  `RunSummary.reproduced_twice_rate`. When the rate's denominator contains no
  verified scenarios, the run summary stores `null` and the UI renders
  unavailable instead of reporting a measured 0%. Plan-level repeatability (pre-commit
  critique agreement) is separate: `tools/replay_simulator.py::simulate_repeated`.
- **Mean time finding → verified remediation (#11)** — `FIXED` lifecycle
  aggregates via `tools/mcp_tools/retest.py::aggregate_retest_lifecycle`
  into `ReliabilityMetrics.mean_time_to_remediation_seconds`.
- **Regression gates fail on stopping-judgement drift**, not just score
  drift: `tools/eval_harness.py::check_regression` fails HARD on
  false-compromise rise, any scope violation reaching the network layer
  (>0), and stuck-loop rise; `tools/benchmark/regression.py::compare_to_baseline`
  fails HARD on false-positive rise, scope-violation count >0, and
  stuck-loop rise beyond `benchmark.regression.stuck_loop_tolerance`.
  Both surface in the WebUI (Benchmarks "Stopping judgement" section, Stats
  "Evaluation reliability" section).

No live release numbers are published yet: publishing a verified
compromise rate requires repeated hermetic trials with pinned
model/prompt/catalog/sandbox digests (#02 Level C, #38). Until then the
honest headline is the contract above plus the reproduction commands
below — not a capability count.

### How the next docker-lab run fills the table (no reformatting needed)

The shipped XBEN targets use `reset_strategy: none`; run one trial per
benchmark invocation. Independent repeated-trial evidence for eval requires
five passing full-suite runs with identical executed-target coverage and
identical required provenance pins, including code revision. This release
evidence rule is stricter than the regression baseline, which allows source
revision changes while requiring the runtime and configuration pins to match.

```bash
# 1. Start the pinned eval-target suite
docker compose -f eval_targets/docker-compose.yml up -d
# 2. One XBEN benchmark trial; these targets cannot be reset automatically
python main.py --benchmark xben --trials 1
# 3. Graded eval + regression gate (currently unavailable)
# The live runner currently has no scope-violation producer, so these commands
# intentionally fail closed and cannot initialize or pass a baseline yet.
python main.py --eval --save-baseline
python main.py --eval --check-regression
# 4. Stop the suite
docker compose -f eval_targets/docker-compose.yml down
```

Required digests (no release numbers without pinned provenance):

- Eval reports record model, prompt/catalog, configuration, and sandbox
  provenance from `tools/eval_harness.py::build_run_provenance`. Benchmark
  replay manifests record their documented environment and run-shape pins;
  fields unavailable in a local environment remain unknown and do not establish
  reproducibility.
- Target-set digest: the oracle files actually executed
  (`eval_targets/*.oracle.json`), likewise content-hashed into
  `provenance.scenario_version`.
- Minimum five independent full-suite eval runs with identical executed
  target coverage for repeated evidence. Benchmark targets without reset
  support remain single-trial. `SKIPPED`/`INFRA_ERROR` outcomes are stored via
  `write_skipped_eval_report` and never presented as green.

Negative-control scorer fixtures (not currently included in live runs):

- `eval_targets/secure_web.oracle.json` and
  `eval_targets/impossible_sqli.oracle.json` remain marked
  `verification_supported: false` because the checked-in compose suite does
  not provision their services and independent live verifiers are unavailable.
  They are skipped in live reports; their scorer unit tests do not count as
  reliability evidence.

Outcome handling: every live run reports `PASS` / `FAIL` / `SKIPPED` /
`INFRA_ERROR` (`tools/eval_harness.py::LiveOutcome`). `SKIPPED` (no live
infra) and `INFRA_ERROR` (provision/sandbox/model failure across all
targets) are written via `write_skipped_eval_report` and never presented
as green — see `.github/workflows/eval.yml` (mocked unit job on every
push/PR; live nightly job on schedule/dispatch only). Stored artifacts:
`reports/eval/<run_id>/` JSON/MD + provenance hashes.

### Live results (UNPOPULATED — awaiting docker-lab run)

No live model backend is available in this environment, so no live numbers
are claimed here. The next hermetic run fills one row per metric; Wilson
95% CI comes from `tools/benchmark/metrics.py` summaries.

| # | Metric | n | Result (Wilson 95% CI) | Date | Digests (model/prompt/catalog/sandbox/targets) |
|---|---|---|---|---|---|
| 1 | Verified compromise rate | — | UNPOPULATED | — | — |
| 2 | False-compromise rate | — | UNPOPULATED | — | — |
| 3 | Actions to verified finding | — | UNPOPULATED | — | — |
| 4 | Cost per verified finding | — | UNPOPULATED | — | — |
| 5 | Run completion rate | — | UNPOPULATED | — | — |
| 6 | Stuck-loop rate | — | UNPOPULATED | — | — |
| 7 | Duplicate action rate | — | UNPOPULATED | — | — |
| 8 | Tool failure rate | — | UNPOPULATED | — | — |
| 9 | Findings reproduced twice | — | UNPOPULATED (aggregation wired: `count_reproduced_twice` + `reproduced_twice_rate`) | — | — |
| 10 | Scope violations reaching network layer | — | unavailable until a producer is wired; release gates fail closed | — | — |
| 11 | Mean time finding → verified remediation | — | UNPOPULATED (collection wired: `aggregate_retest_lifecycle`) | — | — |

## Reproduce

```bash
# Mocked unit coverage (no keys, no docker)
python -m pytest tests/test_eval_live_outcome.py tests/test_benchmark_metrics.py tests/test_reliability_metrics.py -q -p no:cacheprovider -n 0
# XBEN targets currently use reset_strategy=none; run one trial per lab reset
python main.py --benchmark xben --trials 1
# Initialize once from trusted PASS evidence; saving requires measured scope
# telemetry equal to zero. On later runs, check and refresh atomically:
python main.py --eval --save-baseline --check-regression
```

## Capability catalogs (generated, not headline)

- Tools: `docs/mcp/tool-catalog-generated.md` (see `docs/generated/capability-counts.json` for current live counts)
- Skills: `docs/skills/catalog.md` (146 skills: 139 top-level + 7 `maybe/` tier; see `docs/generated/capability-counts.json`)
- These files are generated from source; headline copy must link to them,
  never hardcode a count that will rot. `python scripts/generate_capability_counts.py --check` fails CI on drift.
