# Benchmarks

BreachPilot's benchmark suite turns evaluation into a first-class, reproducible
feature: benchmark targets run under the existing sandboxed execution
architecture, outcomes are verified by an **independent oracle**, and every
run records enough metadata to reproduce and defend the numbers.

> **Warning — authorized lab environments only.** Benchmark targets are
> deliberately vulnerable images. Operate them exclusively against
> infrastructure you own or are explicitly authorized to test, in an isolated
> lab. The same authorization rules as the rest of BreachPilot apply.

## Architecture

The benchmark subsystem lives in `tools/benchmark/` and separates concerns so
no god-file owns everything:

```
benchmark provider (XBEN is one; suites plug in via tools/benchmark/registry.py)
    -> scenarios (tools/benchmark/models.py::BenchmarkScenario)
        -> provision/reset target   (tools/benchmark/targets.py)
        -> create sandbox           (existing tools/sandbox; no host fallback)
        -> run BreachPilot mission  (tools/benchmark/agent_runner.py
                                     wrapping tools/exploit_session.run_exploit_session)
        -> independently verify     (tools/benchmark/verifier.py reusing
                                     tools/eval_checks executors + eval_harness flag semantics)
        -> collect metrics          (tools/benchmark/metrics.py)
        -> persist results          (tools/benchmark/storage.py)
        -> destroy/reset target
```

- **`models.py`** — typed dataclasses: scenarios, trials, run config/environment,
  summaries. `TrialStatus` distinguishes `VERIFIED` / `FAILED` /
  `FALSE_POSITIVE` / `TIMEOUT` / `INFRASTRUCTURE_ERROR`.
- **`registry.py`** — provider registry. XBEN (`tools/benchmark/xben/`) is one
  provider; future suites register their own provider and the runner never
  changes.
- **`targets.py`** — target lifecycle (docker run/restart/teardown) with a
  monkeypatchable subprocess seam. Provision failures raise
  `TargetProvisionError` → the trial is `INFRASTRUCTURE_ERROR`, never a fake
  exploitation failure.
- **`agent_runner.py`** — one attack mission per trial. Detects the agent's
  **claimed** success from structured tool-outcome counters, captures token /
  model-call telemetry from the shared `llm_usage.jsonl` delta, converts the
  audit trail into structured events, and extracts sandbox facts.
- **`verifier.py`** — the ONLY source of `oracle_verified_success`. Reuses the
  graded eval's declarative check executors (`tools/eval_checks.py`): HTTP
  login/request probes, `file_contains` (incl. `loot://`), and `shell_command`
  through a dedicated soft-fail MCP session. A missing session degrades shell
  checks to UNVERIFIED (fail-closed).
- **`runner.py`** — orchestrates trials: provision → mission → verify →
  classify → persist → teardown. Async-safe, cancellable, and one failing
  trial never aborts the suite.
- **`service.py`** — API-facing owner of the active run (lifecycle plumbing
  only).
- **`metrics.py` / `regression.py` / `report.py` / `storage.py` / `replay.py`**
  — aggregation + statistics, baselines and regression detection, public
  report rendering, persistence, and reproduction manifests.

## Verified success vs claimed success

This is the core contract:

- `agent_claimed_success` — what the agent thought (from structured tool-outcome
  counts, **not** LLM prose, exit codes, or tool output text).
- `oracle_verified_success` — what the independent verifier confirmed on the
  target.

A trial is credited as **verified success** only when the oracle confirms the
target state, the agent performed recorded tool actions, and the agent's
structured outcome reports success. Oracle-confirmed state without the agent
recognizing it is recorded as a false negative and is not credited. When the
agent claims success and the oracle disagrees, the trial is a
`FALSE_POSITIVE` — its own status and failure category, surfaced prominently
in reports and the WebUI.

## Running benchmarks

```bash
# WebUI (default no-args launch), then click "Benchmarks"
python main.py

# CLI: run a suite
python main.py --benchmark xben --trials 1

# Filters and repetition
python main.py --benchmark xben --scenario xben-dvwa --trials 1
python main.py --benchmark xben --tag web --trials 1

# List registered suites and their scenarios
python main.py --benchmark-list

# Future baseline/regression path. Both commands currently fail closed because
# the live runner has no producer for the required scope-violation telemetry.
python main.py --benchmark xben --save-baseline
python main.py --benchmark xben --check-regression
```

Once scope telemetry is produced, `--save-baseline` writes the current run as
the new baseline. When combined with `--check-regression`, BreachPilot first
compares against the existing baseline and only replaces it after a complete,
passing check. A failed or incomplete check keeps the previous baseline intact.
To create the first baseline, use `--save-baseline` without
`--check-regression`; a missing baseline makes the check fail closed.
`benchmark.baseline_path` may be absolute; a relative path is resolved under
`benchmark.output_dir`. The default value resolves to
`<benchmark.output_dir>/baseline.json`.

The existing `--eval` / `--eval-list` commands are unchanged; the benchmark
CLI reuses the same config validation and baseline workflow.

### Target setup

Scenario definitions live in `benchmarks/<suite>/*.json` (XBEN-style
manifests: `benchmark_id`, name, target image/host/ports, goal, tags,
difficulty, reset strategy, timeout, and the oracle). The shipped `xben`
manifests target the repo's `eval_targets/docker-compose.yml` lab suite:

```bash
docker compose -f eval_targets/docker-compose.yml up -d   # loopback-only
python main.py --benchmark xben --trials 1
```

> **Loopback-lab + sandbox prerequisite.** The shipped `xben` manifests target
> `127.0.0.1`, but a sandboxed worker's loopback is container-local
> (`sandbox.network.map_host_loopback:false`), so sandboxed exploit execution
> cannot reach the lab by construction. Loopback trials fail fast as
> `INFRASTRUCTURE_ERROR/SANDBOX_FAILED` instead of burning the mission budget.
> For the loopback lab, rerun with the explicit lab opt-out
> (`sandbox.enabled:false` + `benchmark.sandbox_required:false` and the explicit
> `BREACHPILOT_ALLOW_NATIVE_EXECUTION=I_UNDERSTAND_THIS_RUNS_ON_THE_HOST`
> consent), or set
> `sandbox.network.map_host_loopback:true` (dev-lab localhost only, never for
> production runs).

A manifest can also declare `target_type: "docker"` + `target_image`, in which
case the benchmark provisions one container per trial itself (reset strategy
`recreate` or `restart`). `recreate` starts from the image again. `restart`
only restarts processes and preserves writable-container state, so it is only
valid for scenarios where persisted state cannot affect later trials.

Host-managed targets with `reset_strategy: "none"` can run one trial. The
runner refuses to reuse them for a second trial and records
`INFRASTRUCTURE_ERROR/TARGET_RESET_FAILED`; it does not count accumulated host
state as an independent sample. Reset the lab externally between separate
single-trial runs, or use a target manager with an explicit reset mechanism.

## Reproducibility

Every run records a reproduction manifest inside `run.json`: git SHA + dirty
status, model provider/alias/id/version, reasoning config, temperature,
config hash, benchmark config hash, sandbox image + digest, per-scenario
target images, Python version, platform, and timestamps. **Missing metadata is
recorded as `unknown` — never silently substituted** — so reproducibility
claims stay honest. `tools/benchmark/replay.py::check_reproducibility`
requires every documented pin to be present and equal; a matching subset is
not enough. A dirty working tree is not reproducible because the changed file
contents are not pinned by the commit SHA. `git status` failures stay unknown
rather than being mistaken for a clean tree. For Docker-managed targets, the
manifest records the immutable image ID observed on the created container;
the mutable configured tag alone is not used as the replay pin.

## Metrics

Aggregate summaries include verified success rate (oracle success plus an
agent success claim and recorded tool actions), false-positive rate,
median/mean solve time and tool actions, token totals, estimated cost,
time-to-first-verified-success, sandbox-blocked action counts, and failure
categories. With repeated trials (`--trials N`) each scenario gets a success
probability, variance/standard deviation, and a Wilson 95% confidence
interval, plus a `reproduced_twice` flag (verified on ≥2 independent trials
— the repeated-trials gate; rolled up to `reproduced_twice_rate` over
verified scenarios). If no scenario has a verified trial, that rate has an
empty denominator and is stored as `null`/shown as unavailable, not as 0%.
Legacy summaries and baselines with no verified scenario are normalized the
same way when read.
Only reset-capable targets produce independent repeated samples. A host
scenario configured with `reset_strategy: "none"` can complete its first
trial; later requested trials are infrastructure errors until the target is
reset by an explicit mechanism.
Baseline comparisons require the same suite and scenario set, and matching
per-scenario sample counts: both total trial rows and trials with usable
outcomes. Usable outcomes exclude infrastructure errors and skipped trials.
All success, false-positive, false-negative, and stuck-loop rates use only
usable outcomes. When every trial is an infrastructure error or skip, those
rates, per-scenario probabilities/variance, and Wilson intervals are stored as
`null` and shown as unavailable; zero usable trials are never presented as
measured 0% success. Verified counts are shown against usable outcomes, with
total attempted trials reported separately.
Missing counts in a legacy baseline are not inferred; the comparison is
incomplete and cannot pass the regression gate. A filtered run against a
full-suite baseline is also incomparable. Per-scenario results are classified
only when that scenario's sample counts match. Runs also aggregate
`stuck_loop_rate` (mission-reported
stuck-loop signals over completed trials) and `scope_violation_count`
(violations observed reaching the network layer — must be 0; sandbox blocks
are counted separately as containment working, not violations). A single
lucky trial never reads as reliable — with one trial the CI spans most of
the range and `reproduced_twice` stays false.

## Failure classification

Unsuccessful trials are classified to answer "why does BreachPilot fail
here?": `TARGET_PROVISION_FAILED`, `SANDBOX_FAILED`, `MODEL_FAILED`,
`TIMEOUT`, `PLANNER_FAILURE`, `TOOL_FAILURE`, `VERIFICATION_FAILURE`,
`FALSE_POSITIVE`, `NO_EXPLOIT_PATH`, `AGENT_ABORTED`, `TARGET_RESET_FAILED`,
`CAPABILITY_UNAVAILABLE`, `UNKNOWN`. Infrastructure failures (provision, sandbox) are reported as
`INFRASTRUCTURE_ERROR` and excluded from success-rate denominators — they are
not exploitation failures.

## Storage layout

```
reports/benchmarks/<suite>/<run_id>/
    run.json            config + environment + replay manifest + trial list
    summary.json        aggregated metrics
    events.jsonl        structured mission events (whole run)
    report.md/.html     public report rendered FROM the JSON (JSON is canonical)
    scenarios/<id>/trial_<n>.json          per-trial result
    scenarios/<id>/trial_<n>_workspace/    the mission's exploit workspace
```

Writes are atomic; a killed run never leaves a half-written JSON.

## Sandbox behavior

All benchmark attack execution funnels through the existing sandbox
(`tools/sandbox/`). With `benchmark.sandbox_required: true` (the default), a
run without `sandbox.enabled` marks every trial
`INFRASTRUCTURE_ERROR/SANDBOX_FAILED` — **there is no host-execution
fallback**. Runs record sandbox enabled state, image + digest, container id,
network-policy fingerprint, authorized destinations, and blocked/failure
counts. `tools/sandbox/family_audit.py` is the enforceable registry of every
MCP tool family's containment status (sandboxed vs documented host exception);
`tests/test_sandbox_family_audit.py` fails when a new subprocess-using family
appears without a registry entry.

## WebUI

The **Benchmarks** nav item opens the dashboard: verified success rate, solved,
false-positive rate, median solve time, average cost and sandbox-violation
cards; the run panel (suite, scenarios, tags, trials, model, sandbox
requirement, baseline options); run history with charts; the comparison view
(two arbitrary runs, per-scenario newly-solved/regressed/still-solved/
still-failing); and run detail pages with a live progress view, structured
timeline, configuration/environment pins, scenario results table and evidence
links. Historical runs survive restarts (everything is on disk).

## CI usage

- **PR CI** runs the fully mocked benchmark test suite (fake suite, fake
  mission, fake verifier, fake docker seams) — no model API keys, no live
  targets, plus the deterministic `fake` suite smoke path
  (`.github/workflows/benchmark.yml`).
- **Live benchmarks** run only via manual dispatch (`workflow_dispatch`) with
  secrets and the lab target suite up — no schedule trigger is configured
  (`.github/workflows/benchmark.yml` has none; adding one is benchmark-gating
  work). `--check-regression` exits non-zero on
  hard regressions so it can gate CI: verified-success drop, false-positive
  rise, any scope violation reaching the network layer, stuck-loop rise
  beyond `benchmark.regression.stuck_loop_tolerance`, and any scenario solved
  in the baseline but unsolved now. A comparison with different suite,
  scenario coverage, or per-scenario total/usable sample counts is incomplete
  and exits non-zero until a matching baseline is used.

## Repeated baseline (TODO 001) + XBEN (TODO 017)

Protocol: `eval_targets/` DVWA / Juice Shop. Metasploitable2 declares
verification unsupported and is skipped until an independent verifier exists;
the
`secure_web` and `impossible_sqli` negative-control scoring fixtures are
currently skipped because the compose suite does not provision them.
`bp --benchmark` 5–10×
per scenario on reset-capable targets, complete benchmark environment and
replay provenance (see [evaluation provenance](evaluation.md#provenance-contract)), metrics from
`docs/reliability-metrics.md` (verified compromise rate, FP rate,
actions/verified, time-to-verified, completion, stuck-loop, duplicate-action,
tool failures, reproduction success, scope violations=0).

The shipped XBEN manifests currently target the operator-managed Compose lab
and declare `reset_strategy: "none"`. They support single-trial runs only;
they cannot produce the repeated-trial baseline above until the lab gains an
explicit clean-reset mechanism. Do not interpret repeated trials against
those static targets as independent samples.

The `xben-metasploitable2` scenario is skipped by both the benchmark and
graded-eval runners. Its prior shell checks executed in BreachPilot's local
worker rather than the assessed container, so they could not serve as target
evidence. It remains listed for discovery until a target-side verifier exists.

No repeated live evaluation evidence is committed or included in this checkout.
The historical `reports/eval/2026-09-15-baseline/` path is not present here,
and dry-run provenance alone is not reported as live model performance. The
release gate requires actual, recent provenance artifacts and remains
EXTERNAL/NO-GO while they are absent. After provisioning reset-capable Docker
targets and a model backend per `docs/evaluation.md`, save the generated
reports under `reports/eval/` and pass that report directory to the gate.

XBEN: `benchmarks/xben/` adapter maps XBEN challenges → BreachPilot target +
oracle (`tools/eval_harness.score_against_oracle`). One-command reproduction
from a clean checkout:

```bash
docker compose -f eval_targets/docker-compose.yml up -d
bp --benchmark xben --trials 1
```

The Compose targets currently have no reset mechanism, so keep this command to
one trial. Publish `reports/eval/xben-<date>/` with per-challenge results +
provenance + failed-IDs list. Never agent self-grading: XBEN flags/oracles
grade, not the transcript. Surfaced in WebUI Benchmarks page.
