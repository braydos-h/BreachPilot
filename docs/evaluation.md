# Evaluation & Benchmarking Guide

## Overview

Two evaluation layers exist for the Flow A exploit engine:

1. **`--eval` legacy harness** (`tools/eval_harness.py`) — a single-run smoke
   report. Runs one attack-mode exploit session against `--target`, derives
   `EvalMetrics` from the `run_exploit_agent` final-result dict, and writes
   JSON / Markdown / HTML under `reports/eval/<run_id>/`.
2. **Oracle-backed paired benchmark** (`tools/eval_benchmark.py`) — a
   baseline-vs-treatment comparison where a caller-supplied **target-side
   oracle** independently confirms each success. The agent's own claims are
   never trusted; they are only used to compute a false-positive rate.

The legacy harness self-scores the system's own regex-derived
`outcome_summary`, does not enable the smart features it claims to evaluate
(adaptive exploits, Flow A outcome judgment, skills, long-session), has no
baseline/treatment comparison, and its `success_rate` is
compromise-events-per-action, not run-success probability
(`eval_benchmark.py:1-8`). The benchmark exists to fix exactly those gaps.

Both are lab-only builds: the operator runs them against infrastructure they
own or are explicitly authorized to test. The attack path is target-locked at
the MCP tool layer (the allowlist unions the runtime `--target` via
`EXPLOIT_TARGET`); neither harness adds any further gate
(`eval_harness.py:15-18`).

## Run Commands

| Command | What it does |
| --- | --- |
| `python main.py --eval --target <ip>` | Run the legacy eval harness against `<ip>`; writes `reports/eval/<run_id>/eval_report.{json,md,html}` (`main.py:403-404`, dispatched at `main.py:867-870`) |
| `python main.py --eval` | Run the graded eval suite (oracle v2) across ALL `eval_targets/*.oracle.json` targets and print the report |
| `python main.py --eval dvwa juice_shop` | Grade only the named oracle targets |
| `python main.py --eval-list` | Print oracle target ids + flag counts, exit 0 (no docker, no agent) |
| `make eval` | Makefile mirror of `--eval` (Linux/macOS) (`Makefile:28-29`) |
| `python -m pytest tests/test_eval_harness.py -v` | Hermetic harness tests (mocked MCP session + exploit session; no network) |
| `python -m pytest tests/test_eval_benchmark.py -v` | Oracle-backed benchmark tests (mock oracle + mock run_session) |
| `python -m pytest tests/test_eval_cli.py tests/test_eval_config.py -v` | `--eval` flag parsing/dispatch and `eval:` config-block schema tests |
| `python main.py --eval --save-baseline` | Graded loop across all oracle targets, then persist `eval.baseline_path` (see *Graded Eval Loop* below) |
| `python main.py --eval --check-regression` | Graded loop, then fail with a non-zero exit when any target regresses beyond `eval.regression_tolerance` |

Bare `--eval` (no `--target`) runs the graded suite; `--save-baseline` /
`--check-regression` require `--eval` and exit 2 without it. The legacy
single-target path requires `--target`; it returns exit code 2 without one, 1 on
config/MCP failure, 0 on success (`eval_harness.py:362-367, 452-467, 522-524`).

The nightly `.github/workflows/eval.yml` runs the mocked eval unit tests on
push/PR (no API key needed) and the live graded suite on schedule/manual
dispatch — skipped gracefully when `OLLAMA_API_KEY` is not configured.

The `eval:` block in `config.yaml` (lines 305-310) gates the harness defaults:
`enabled`, `output_dir` (default `reports/eval`), `max_rounds` (default 30,
becomes `attack_max_rounds`), `write_markdown`, `write_html`, plus the graded
loop's `regression_tolerance` (default `0.05`) and `baseline_path` (default
`reports/eval/baseline.json`). The `--eval`
flag still works when `enabled` is false — the block only gates defaults
(`eval_harness.py:376-380`).

## Legacy Harness (`tools/eval_harness.py`)

### Flow

1. Load validated config, build the Ollama model router, probe the MCP
   exploit server with `open_exploit_mcp_session(soft_fail=True)` so an
   unreachable server degrades to an error report instead of raising
   (`eval_harness.py:369-467`).
2. Run `run_exploit_session` in attack mode with
   `ExploitPermission.FULL_ACCESS`, the `initial_access` goal at
   `high_authorized_testing` risk, and the eval workspace under
   `reports/eval/<run_id>/exploit_workspace` (`eval_harness.py:416-484`).
3. Compute metrics from the final-result dict and write the report
   (`eval_harness.py:511-520`).

Every MCP-wrapping call uses `_EXC_GROUP_CATCH` from `tools.exceptions` so an
anyio `BaseExceptionGroup` (subprocess death) is not silently swallowed
(`eval_harness.py:11-13, 445-448, 485-488`).

### Metrics (`EvalMetrics`, `eval_harness.py:101-123`)

| Metric | Derivation |
| --- | --- |
| `compromise_count` / `cred_dump_count` / `partial_count` | Regex-parsed from the `_ToolOutcomeTracker` summary string (`eval_harness.py:64-78`) |
| `failure_count` | Audit records whose `status` is exactly `failed`/`blocked`/`error` or contains `fail`/`error`/`block` (`eval_harness.py:81-94`) |
| `success_rate` | `(compromise_count + cred_dump_count) / total_actions`, clamped to [0, 1] (`eval_harness.py:168-175`) — events-per-action, not run-success |
| `verdict` | Priority: `compromised` > `cred_dump` > `partial` > `no_access` > `error` (`eval_harness.py:177-186`) |
| `evidence_refs` | Copied from `evidence` / `evidence_refs` keys of the final result (`eval_harness.py:161-166`) |
| `duration_seconds` | Wall-clock of the exploit session (`eval_harness.py:509, 515`) |

### Output

`write_eval_report` writes `eval_report.json` (always) plus `eval_report.md`
and `eval_report.html` (config-gated) under `reports/eval/<run_id>/`
(`eval_harness.py:328-355`). The Markdown report contains a metrics table,
audit path, evidence refs, and the raw outcome summary
(`eval_harness.py:216-256`); the HTML report is self-contained with no
external dependencies (`eval_harness.py:259-321`).

### Pass/fail interpretation

- `verdict=compromised` — at least one compromise recorded; strongest signal.
- `verdict=cred_dump` / `partial` — partial access; weaker than compromise.
- `verdict=no_access` — actions ran but nothing landed.
- `verdict=error` — zero actions (MCP server unavailable, session crashed, or
  empty result); the run is invalid, not merely unsuccessful
  (`eval_harness.py:452-467`).

Because the harness self-scores, treat any non-`error` verdict as a smoke
signal only — use the oracle-backed benchmark for defensible numbers.

## Oracle-Backed Benchmark (`tools/eval_benchmark.py`)

### Design

- **Oracle** — a callable `Oracle(target_ip, scenario) -> bool` that confirms
  the objective independently on the target (e.g. "did a known proof file get
  read?", "did a callback reach the verifier?", "do the seeded credentials
  match?"). A success counts **only** when the oracle confirms
  (`eval_benchmark.py:10-30, 336-340`).
- **Paired conditions** — baseline (smart features OFF) vs treatment (smart
  features ON: `adaptive_exploits`, `outcome_judgment.flow_a`, `skills`,
  `long_session`, `reasoning`, `multi_model`, `memory`)
  (`eval_benchmark.py:157-177`).
- **Per-trial metadata** — model ID, config hash (sha256 of the condition
  config, `eval_benchmark.py:183-186`), target snapshot ID, actions, duration,
  time-to-first-verified-success (`eval_benchmark.py:90-104`).
- **Target reset** — optional `reset_target_between_trials` callback invoked
  before every trial; a reset failure is best-effort and does not abort the
  trial (`eval_benchmark.py:322-326`).
- **Injection point** — `run_session` is injectable so the benchmark is
  testable without a live MCP server; when `None`, the real
  `run_exploit_session` is used (`eval_benchmark.py:152, 236-274`).

### Metrics (`BenchmarkReport`, `eval_benchmark.py:106-133`)

| Metric | Definition |
| --- | --- |
| `verified_success_rate[condition]` | `mean(Y)` where `Y` = oracle-confirmed trials (`eval_benchmark.py:359-364`) |
| `false_positive_rate[condition]` | Trials where the agent claimed success (`compromises: N` with N>0 in `outcome_summary`) but the oracle did not confirm (`eval_benchmark.py:276-277, 360-365`) |
| `risk_ratio` | `mean(Y_treatment) / mean(Y_baseline)`; `None` when baseline rate is 0 (`eval_benchmark.py:379-383`) |
| `risk_ratio_ci_low/high` | 1000-sample cluster bootstrap (resamples scenarios with replacement, seed 42) 95% CI (`eval_benchmark.py:384-405`) |
| `actions_per_verified_success[condition]` | Mean actions over verified trials (`eval_benchmark.py:366-369`) |
| `time_to_first_verified_success[condition]` | Mean duration of verified trials (`eval_benchmark.py:370-373`) |

### Output

Persists `reports/eval_benchmark/benchmark_<timestamp>.json` containing the
full report dict (`eval_benchmark.py:420-423`).

### Pass/fail interpretation

- `risk_ratio > 1` with a CI that excludes 1.0 — treatment measurably beats
  baseline (the "4x claim" the benchmark exists to test).
- `risk_ratio ≈ 1` or CI bracketing 1.0 — no measurable effect.
- `risk_ratio = None` — baseline verified rate was 0; RR is undefined.
- High `false_positive_rate` on either condition — the agent claims success it
  cannot prove; treat its self-reported verdicts as unreliable.

### Usage

```python
from tools.eval_benchmark import BenchmarkConfig, Scenario, run_benchmark

def my_oracle(target_ip: str, scenario: Scenario) -> bool:
    # Independently confirm the objective on the target.
    ...

cfg = BenchmarkConfig(
    scenarios=[Scenario(scenario_id="s1", target_ip="10.0.0.5",
                        goal_name="initial_access", target_snapshot_id="snap-1")],
    oracle=my_oracle,
    conditions=["baseline", "treatment"],
    trials_per_scenario=4,
    reset_target_between_trials=reset_snapshot,
)
report = await run_benchmark(cfg)
```

## Scenarios and Oracles

A `Scenario` is one resettable lab target: `scenario_id`, `target_ip`,
`goal_name` (e.g. `initial_access`, `backdoor`), `description`,
`target_snapshot_id` (identifies the target image for reset),
`expected_duration_seconds`, and free-form `metadata`
(`eval_benchmark.py:76-86`). The goal is resolved through `GoalEngine` at
`high_authorized_testing` risk (`eval_benchmark.py:233`).

The oracle is the contract between the benchmark and the lab: it must check
state on the target, never the agent's text. The agent's own exit code and
`OutcomeJudge` verdict are explicitly NOT sufficient — that is the whole point
(`eval_benchmark.py:24-29`).

## Graded Eval Loop (flag oracle schema v2)

The graded loop (`tools/eval_harness.py::run_graded_eval`) is the flag-based
scoring layer over the Docker target suite. It extends the per-target oracle
JSONs (`eval_targets/*.oracle.json`) with a declarative `flags` list and a
`host_owned_when` condition, runs the agent against each target, and grades it
on **independently verified evidence** — the check executor is the truth
source; the agent's claimed findings never decide a flag.

### Oracle schema v2

Every oracle keeps its v1 keys (`target_id`, `host`, `ports`,
`expected_findings`, `scoring`) and adds:

```json
"flags": [
  {
    "id": "dvwa_admin_login",
    "description": "Admin credentials grant dashboard access",
    "check": {"type": "http_login", "url": "http://127.0.0.1:8081/login.php",
              "user": "admin", "password": "password", "expect_status": 200}
  }
],
"host_owned_when": "any"
```

- `flags` — 2-4 declarative check specs per target, derived from the oracle's
  existing `weak_credentials` / `flag_path` data.
- `host_owned_when` — when the target counts as "owned": `"any"` (default — at
  least one flag captured), `"all"` (every flag captured), or an explicit list
  of flag ids meaning "all of these". An empty list falls back to `"any"`.

### Flag check types

Check specs are declarative and target-side; the executor is injected. All
four types are implemented in `tools/eval_checks.py` (re-exported through
`tools/eval_harness.py`):

| Type | Spec | Verdict rule |
| --- | --- | --- |
| `http_login` | `{type, url, user, password, expect_status?}` | POSTs the credential pair (JSON then urlencoded form, both judged) plus a Basic auth header; passes when a response status equals `expect_status` (default 200) |
| `http_request` | `{type, url, expect_status?, expect_body_contains?}` | Anonymous GET; passes when status matches and (when set) the body contains the substring |
| `file_contains` | `{type, path, pattern}` | `path` may be `loot://<relative>` (resolved against the run's loot/exploit workspace) or an absolute operator-box path; passes when the pattern appears in the file |
| `shell_command` | `{type, exec, expect_stdout}` | Executed through the injected MCP session (`run_exploit_terminal` in production); passes when `expect_stdout` appears in the output, or — with an empty `expect_stdout` — when any output was produced |

Shared semantics: HTTP checks are **loopback-only** (any non-loopback URL is
refused before a socket is opened — the compose suite binds everything to
`127.0.0.1`); `shell_command` is **nonzero-exit-tolerant** (stdout content
decides; a missing flag file cats nothing and fails an any-output expect); a
`shell_command` with no session available degrades to `UNVERIFIED` (False),
never a pass. Flags stay achievable-by-design: cred-login flags for
dvwa/juice-shop, shell/flag-file flags for metasploitable2/vulnerable-k8s
(a `msfadmin`-level `id` is explicitly *not* a flag — a flag is root or the
flag file), plus one `http_request` misconfiguration flag per web target.

### Scoring (`TargetScore`)

`score` is a 0.0-1.0 composite — the unweighted mean of:

1. **Flag ratio** — `flags_captured / flags_total` (1.0 when the target
   declares no flags);
2. **Host-owned ratio** — `hosts_owned / hosts_total` (1 when the
   `host_owned_when` condition is met);
3. **Findings F1** — harmonic mean of precision (`tp / (tp + fp)`) and recall
   (`tp / expected_total`) from the existing `score_against_oracle`
   paper-scoring of the agent's claimed findings.

`success` for a target is the `host_owned_when` condition being met. The
aggregate `EvalReport` folds totals across targets and writes
`reports/eval/<run_id>/report.json` (+ `.md` / `.html` when
`eval.write_markdown` / `eval.write_html`).

### Baseline & regression

- `save_baseline(report, baseline_path)` writes
  `{"run_id", "timestamp", "targets": {target_id: {score, flags_captured,
  flags_total, hosts_owned, hosts_total, findings_verified,
  findings_claimed}}}`.
- `check_regression(report, baseline_path, tolerance)` — a target **regresses**
  when `score < baseline_score - tolerance` (`tolerance` from
  `eval.regression_tolerance`, default `0.05`; path from `eval.baseline_path`,
  default `reports/eval/baseline.json`). Targets present in the report but not
  the baseline are new and skipped; targets in the baseline but not the report
  produce a warning line, **not** a failure. A missing or malformed baseline
  **fails closed** (`passed=False`).

## PoE Canary Verification (`tools/verification/poe_verifier.py`)

**Status: scaffolded primitive — not part of the live execution path.** No
production code calls it yet (only `tests/test_poe_verifier.py`); it exists so a
compromise oracle for the benchmark harness can be built on it. Given a
`tool_executor` wired to the target
(`(tool_name, args) -> result_text`, the same shape as
`SwarmMcpBridge.dispatch`), it:

1. Writes a unique canary token (`PoE-<ip>-<uuid4 hex>`) to `/tmp/poe_*.txt`
   on the target and reads it back in one shell call
   (`poe_verifier.py:67-80, 172-196`).
2. Confirms the token echoed back — proving real write+read on the target,
   not a stub (`poe_verifier.py:199-211`).
3. Collects `id` / `whoami` / `hostname` probes and classifies privilege:
   `root` / `system` / `user` / `unknown` (`poe_verifier.py:134-153`).

Defensive by design: any executor failure (`BLOCKED:`,
`TOOL_EXECUTION_ERROR:`, exception, missing token echo, timeout) collapses to
`verified=False` with the reason captured in `evidence`; it never raises into
the caller (`poe_verifier.py:14-17, 240-327`). Async entry
`verify_compromise` offloads the blocking executor to a worker thread with a
30s asyncio shield; `verify_compromise_sync` is the non-async variant
(`poe_verifier.py:284-327`). Tests: `tests/test_poe_verifier.py`.

## Detection Coverage Scoring (`tools/detection_coverage.py`)

Read-only planning + audit-footprint helpers (pure stdlib, no network, no
execution at import time; `detection_coverage.py:1-18`):

- `detection_probe_plan(target_ip)` — a 4-item canary plan (auth / file /
  exec / network) the operator deploys against their OWN authorized target to
  validate that SIEM/IDS/FIM/EDR coverage fires on attacker-like behavior
  (`detection_coverage.py:86-124`). Each entry carries a `detection_hint`
  naming the surface it should trip. Nothing executes — it only produces plan
  dicts.
- `footprint_summary(audit_records)` — reduces an audit-record list (the shape
  `exploit_audit.jsonl` lines decode to) into counts: total/noisy actions,
  commands executed, unique targets/tools, egress endpoints, and up to 5 noisy
  command examples. A record is noisy when its `noisy` flag is set or its
  command matches `_NOISY_PATTERNS` (masscan, hydra, nuclei, crackmapexec,
  etc.; `detection_coverage.py:28-31, 127-179`). The audit trail is
  append-only/tamper-evident and is never mutated — read for reporting only.

## How Attack Modules Get Exercised in Eval

The harness does not call `find_modules` directly — modules are selected
inside the exploit session by the agent loop (`docs/attack-modules.md:235-255`).
The eval session runs in attack mode with `FULL_ACCESS` permission and the
`initial_access` goal; the agent loop picks applicable modules via
`AttackModule.applicability` scoring and drives them through the MCP
`attack_module` tool family. Module correctness is covered by unit tests
rather than the harness:

- `tests/test_weaponized_cloud_k8s_modules.py` — `WeaponizedExploit`,
  `CloudPrivesc`, `K8sPrivesc`: class attributes, `run()` returning
  `info`/`script_generated` results, applicability scoring, and the rule that
  `run()` must express intent only (`expected_shell_type`) and never set
  `shell_type`/`privilege_level` (confirmed-compromise signals).
- `tests/test_supply_chain_modules.py` — `ExposedVCS`, `CICDMisconfig`,
  `DependencyConfusion`, `ArtifactExposure`, `SupplyChainRecon`: class attrs,
  script generation (target-IP embedded), info-workflow framing that must stay
  detection/report-oriented (no "register a package" instructions), and
  applicability zero on non-matching services.
- `tests/test_version_aware_ranking.py` — the +25 version bonus in
  `AttackModule.applicability`: exactly +25 on a matching version, no bonus on
  non-match, backward-compatible default `target_versions={}`, capped at 100,
  once per module (not per pattern/service), case-insensitive substring match.
- `tests/test_tier4_correctness.py` — the defensive-server allowlist
  CIDR-subset fix (`_is_in_allowlist` accepts a /24 asset against a /16 entry,
  wildcard domains, exact IPs) and the `run_exploit_terminal` tool-layer
  target-IP lock: an out-of-scope scan is blocked with the allowlist reason
  ("not in the explicit allowlist"), and the removed destructive /
  interpreter-`-c` / `find -exec` gates must not supply the block reason.

## Adding a New Eval Scenario

1. **Define the scenario** — create a `Scenario` with a unique
   `scenario_id`, the lab `target_ip`, a `goal_name` the `GoalEngine`
   knows, and a `target_snapshot_id` for reset
   (`eval_benchmark.py:76-86`).
2. **Write the oracle** — a callable that independently confirms the
   objective on the target (e.g. seed a proof file, then check it was read;
   or wrap `verify_compromise` from `poe_verifier.py` to confirm a canary
   landed). It must never read the agent's text.
3. **Wire a reset** — supply `reset_target_between_trials` so each trial
   starts from a clean snapshot; without it, trials leak state.
4. **Add the scenario to `cfg.scenarios`** and run `run_benchmark(cfg)`.
   Results land in `reports/eval_benchmark/benchmark_<timestamp>.json`.

For the legacy harness, a new scenario is just a new `--target` — the harness
runs the same `initial_access` goal against whatever IP you point it at
(`eval_harness.py:416-429`).

## Tests

| File | Covers |
| --- | --- |
| `tests/test_eval_harness.py` | `compute_metrics` parsing/verdict matrix/clamping/robustness, report rendering, `write_eval_report` file creation + run-id minting, `run_eval` end-to-end with fully mocked MCP session + exploit session (hermetic); graded loop (`run_graded_eval` with fake runner/executor, `verify_flag_check` per check type, `host_owned_when` semantics, baseline save/regression, real oracle v2 loading) |
| `tests/test_eval_benchmark.py` | Oracle determines `verified_success` (not the agent's claim), risk-ratio computation, RR `None` when baseline is 0, report JSON persistence, reset-between-trials, default condition configs differ |
| `tests/test_eval_cli.py` | `--eval` flag parsing and `run_eval` importability |
| `tests/test_eval_config.py` | `eval:` block in `CONFIG_SCHEMA`, defaults, shipped `config.yaml`, validator acceptance |
| `tests/test_poe_verifier.py` | PoE canary verification (see testing-guide.md:72) |
