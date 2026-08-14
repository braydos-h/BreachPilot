# Outcome Judgment and Evidence Handling

Outcome judgment is the layer that decides, on evidence, whether an investigation
or exploit attempt actually succeeded. The repo's core rule: **evidential status is
kept separate from execution status** (docs/safety-model.md:173). A tool that ran
(`execution_outcome = succeeded`) is not evidence that a hypothesis is true; raw
output words like `success` are explicitly not a confirmation signal
(outcome_judge.py:1-7).

Two judgment stacks exist:

- **Flow B (legacy, SQLite-backed)**: `outcome_judge.py` + `finding_verifier.py` +
  `evidence.py` + `summarizer.py` + `report_generator.py` — the database-backed
  research loop (docs/runtime-flows.md:17-73).
- **Flow A (modern exploit engine)**: `tools/exploit_agent/outcome_classify.py`,
  `outcome_truth.py`, `outcome_adapter.py`, `tools/verification/poe_verifier.py`,
  `tools/enhanced_reporting.py`, `tools/eval_harness.py`, `tools/eval_benchmark.py`.

## Outcome Taxonomy

There are three distinct classification axes; conflating them is the historical
false-positive path the codebase defends against.

### 1. Execution outcome — did the call complete?

| Class | Meaning | Source |
|---|---|---|
| `succeeded` | Tool ran and returned a determinate result | `ExecutionOutcome` (outcome_judge.py:21-26) |
| `failed` | Tool ran but errored operationally | same |
| `blocked` | Rejected by scope/approval/target-lock before execution | same; detection at outcome_judge.py:622-632 |

Flow A's equivalent is `OperationalStatus` (outcome_truth.py:46-51):
`completed` / `failed` / `blocked` / `retryable` / `execution_unknown`. A transport
death is `execution_unknown`, never `failed`, so it does not trip policy
unavailability thresholds (outcome_truth.py:10-13).

### 2. Evidential status — did the evidence resolve the hypothesis?

`HypothesisStatus` (outcome_judge.py:29-36): `open` → `confirmed` | `refuted` |
`inconclusive` | `exhausted`. Terminal statuses are `confirmed`, `refuted`,
`exhausted` (outcome_judge.py:39-45). A terminal hypothesis blocks further
pending/replanned checks (outcome_judge.py:540-552); an `inconclusive` hypothesis
can continue only with a materially different check fingerprint
(outcome_judge.py:584-602, docs/runtime-flows.md:47-49).

### 3. Exploit outcome — did the action achieve compromise?

Flow A verdicts from the classifiers (outcome_classify.py:96-126,
outcome_truth.py:54-60, `ExploitOutcome`):

| Verdict | Required signal |
|---|---|
| `compromise` | Strong shell marker: `meterpreter session N`, `nt authority\system`, `command shell session N`, `uid=0(`, `whoami` → root, `root@host:~# ` + command (outcome_truth.py:91-104) |
| `cred_dump` | Explicit credential/hash/dump marker requiring a colon or `dumped` verb, e.g. `credentials:`, `ntlm: 0x…`, pwdump lines (outcome_truth.py:109-117) |
| `partial` | Access-denied / limited / not-authorized markers — a partial outcome is **not** a failure (outcome_classify.py:58-68) |
| `failure` | Explicit error or non-zero exit marker with no stronger signal (outcome_classify.py:72-86) |
| `unknown` | Nothing matched — caller falls back to exit code / structured signals (outcome_classify.py:121-122) |
| `none` | Not an exploit-validation action — recon/install tools can never read as access (outcome_truth.py:60, 66-81) |

### Finding lifecycle (Flow B)

`candidate → needs_validation → validated → report_ready` (finding_verifier.py:33-40),
with side transitions to `duplicate_suspected` and the terminal `rejected`.
Transitions are enforced by `VALID_STATUS_TRANSITIONS` (finding_verifier.py:33-40).

## Truth vs Model Claim

`outcome_truth.py` and `outcome_classify.py` both classify text, but they are not
the same layer:

- **`outcome_classify.py`** is the **legacy loose classifier** (`classify_exploit_result`,
  outcome_classify.py:96). It can still confirm on bare `meterpreter`, trailing
  prompt `$`/`#`/`>`, and bare `hashes`/`creds` (outcome_classify.py:27-43) — this is
  the historical false-compromise path (outcome_truth.py:5-8, docs/exploit-agent.md:297-306).
- **`outcome_truth.py`** is the **authoritative normalization**
  (`normalize_action_result` → `ActionResult`, outcome_truth.py:339). It:
  - splits `operational_status` from `exploit_outcome`;
  - defaults `exit_code` to `None` (unknown), never fabricates `0` (outcome_truth.py:161-180);
  - reads MCP structured `isError` (outcome_truth.py:307-326);
  - classifies only `_EXPLOIT_VALIDATION_TOOLS` (outcome_truth.py:66-81);
  - uses the tightened `_STRONG_SHELL_PATTERNS` (outcome_truth.py:91-104).

`ActionResult.verified_success` (outcome_truth.py:284-290) is the flag that gates
`access_achieved`, `compromised_hosts`, finding creation, and post-exploit phases —
**not** the judge alone and **not** `operational_success` (which is only
"completed and non-failing", outcome_truth.py:274-281). `judge_flow_a` threads the
same tightened `ActionResult` classification into the judge so it can never
re-classify via the loose legacy path (outcome_adapter.py:412-432).

## The Evidence Model

### What counts as evidence

Evidence is a persisted, hash-stamped, filesystem artifact with SQLite metadata
(evidence.py:1-14). Types and storage subdirectories (evidence.py:27-36,
202-213):

| Evidence type | Subdir | Extension | Examples |
|---|---|---|---|
| `raw_output` | `evidence/raw_output` | `.txt` | tool stdout/stderr |
| `http_response` / `http_request` | `evidence/http_responses` | `.txt` | curl sessions |
| `screenshot` | `evidence/screenshots` | `.png` | web UI proof |
| `note` / `diff` | `evidence/notes` | `.md` / `.diff` | analyst notes |
| `file` | `evidence/artifacts` | `.bin` | downloaded payloads |
| `structured_json` | `evidence/artifacts` | `.json` | promoted audit rows |

### Evidence fields (SQLite `evidence` table, evidence.py:108-124)

| Field | Meaning |
|---|---|
| `id` | Evidence ID, `E-00001-XXXX` (`_new_id`, evidence.py:78) |
| `mission_id` / `task_id` / `finding_id` | join keys to mission/tasks/findings |
| `type` | one of the types above |
| `path` | path relative to the mission workspace |
| `summary` | first ~300 chars, whitespace-collapsed (evidence.py:216-219) |
| `hash` | SHA256 of the content — integrity check for verification and comparison (evidence.py:82, 148-162) |
| `metadata_json` | structured metadata, plus `content_truncated` and `original_size`; content over 1 MB is truncated at write (evidence.py:84-90) |
| `created_at` | ISO timestamp |

`EvidenceStore.get` re-attaches content on read; binary types come back base64-encoded
(evidence.py:127-146). `compare` checks `same_hash` for two items (evidence.py:148-162).

### Flow A audit trail: `exploit_workspace/<target_ip>/exploit_audit.jsonl`

Every exploit MCP call and every `ExploitRecord` is appended to a shared
append-only JSONL (tools/mcp_shared.py:459-491, tools/exploit_agent/policy.py:128-131).
Two schemas coexist in one file (policy.py:213-218):

- **MCP-tool rows** (`_audit_log`): `tool_name`, `args`, `approved`, `status`,
  `command` (secret-masked), `attempt_id`, `code_sha256`, `duration_seconds`
  (tools/mcp_shared.py:474-488).
- **Flow A `ExploitRecord` rows** (`policy.record`): carry `action`, `full_args`,
  `detail`, and the **tamper-evidence hash chain** — each record's `hash` is the
  sha256 of its canonical JSON excluding the `hash` field, and the next record's
  `prev_hash` must equal it (policy.py:159-165, 191-201). `verify_audit_chain`
  (policy.py:205-265) recomputes the chain on startup; a broken chain is reported,
  never silently ignored. MCP rows lack `hash` and are skipped by the chain check
  (policy.py:245-246).

### Artifact storage map

| Artifact | Location |
|---|---|
| Flow B evidence | `<mission_workspace>/evidence/<subdir>/` (evidence.py:93) |
| Flow A audit log | `exploit_workspace/<target_ip>/exploit_audit.jsonl` |
| Exploit attempts | `exploit_workspace/<target_ip>/<attempt_id>/` |
| Per-run reports | `reports/<run_id>/` |
| Eval reports | `reports/eval/<run_id>/` (eval_harness.py:6, 343) |
| Benchmark reports | `reports/eval_benchmark/benchmark_<timestamp>.json` (eval_benchmark.py:144, 422) |
| Flow B finding reports | `<workspace>/reports/<finding_id>.md` (report_generator.py:254) |
| Enhanced reports | `<workspace>/enhanced/report_<mission>_<ts>.(json\|md\|html)` (enhanced_reporting.py:293-310) |

### Evidence bridge: audit JSONL → EvidenceStore

`evidence.promote_exploit_audit` (evidence.py:288-340) promotes Flow A audit rows
into the shared `EvidenceStore` as `structured_json` rows tagged with
`audit_hash`, `target_ip`, `row_attempt_id`, and the action label so report
generators can group by tool without re-parsing (evidence.py:343-378). It is
purely additive — it reads the JSONL and never mutates it (evidence.py:259-262).
`record_run_output` is the single-row convenience wrapper (evidence.py:381-421).

## How Outcomes Are Judged (outcome_judge.py)

`OutcomeJudge.judge` (outcome_judge.py:190-307) is a pure, deterministic function
over `(task, execution_result, observation, evidence_refs, prior_hypothesis)`.
It never mutates persistence — `HypothesisRepository.persist_assessment`
(outcome_judge.py:428-568) does that atomically.

Judgment order (outcome_judge.py:244-277):

1. If the hypothesis was already terminal → keep prior status (no new path justified).
2. `REFUTED` if ≥ `min_evidence_references` refs exist **and** refutation score ≥
   `refutation_threshold` (0.75 default, outcome_judge.py:169-188).
3. `CONFIRMED` if refs exist **and** support score ≥ `confirmation_threshold`.
4. `EXHAUSTED` after `max_inconclusive_attempts` (3 default) materially different
   checks.
5. Otherwise `INCONCLUSIVE` (attempted) or `OPEN` (blocked).

Evidence scoring:

- `_explicit_evidence_scores` (outcome_judge.py:789-815) reads `hypothesis_evidence`
  polarity entries (`supports`/`contradicts`) plus `facts` prefixed
  `confirms …`/`refutes …`.
- `_criterion_met` evaluates `success_criteria`/`stop_conditions` as structured
  `{field, operator, value}` or text clauses (outcome_judge.py:680-786). Generic
  operational words (`success`, `completed`) are **not** meaningful tokens for
  `contains` matching (outcome_judge.py:717-720, `_STOPWORDS` at 925-959).
- `_contradiction_score` (outcome_judge.py:818-862) detects polarity-opposite text
  sharing anchor tokens or numbers.
- An actual tool error zeroes support/refutation unless explicit structured
  evidence exists (outcome_judge.py:234-237). An execution error is never itself a
  refutation (outcome_judge.py:267, docs/runtime-flows.md:71-73).

Outputs: `OutcomeAssessment` (outcome_judge.py:102-152) with confidence
(0.7 + 0.3·score, clamped), `information_value` (0.35 usefulness + 0.25 structural +
0.2 evidence + 0.2 resolution; terminal judgments floor at 0.85, outcome_judge.py:865-895),
and `another_investigation_justified`. `evidential_outcome` maps
CONFIRMED→`success`, REFUTED→`failure` for the learning loop (outcome_judge.py:124-131).
Dedup: `build_check_fingerprint` hashes `(tool, tool_args)` or normalized method
text so retry-text changes do not count as new checks (outcome_judge.py:584-602);
`HypothesisRepository.prepare_task` rejects terminal-hypothesis and duplicate
checks (outcome_judge.py:374-399). Each judgment is logged to the mission audit
trail via `DatabaseManager.log_audit` (outcome_judge.py:553-564).

The judge **cannot** authorize tasks, change scope, approve risk, unlock targets,
or call tools — it only records evidence-linked assessments downstream of every
gate (docs/safety-model.md:156-161).

## Finding Verification (finding_verifier.py)

`FindingVerifier` manages the SQLite-backed finding lifecycle (finding_verifier.py:77-78).
`validate_finding` (finding_verifier.py:146-226) runs the checklist:

1. **In scope?** via `ScopeGate` (finding_verifier.py:166-174).
2. **Evidence?** at least one `evidence_ref`, and if an `EvidenceStore` is
   supplied, each ref must exist **on disk** (finding_verifier.py:176-192).
3. **Summary ≥ 20 chars**, impact defined, vulnerability class present,
   reproduction steps present (finding_verifier.py:194-214).

A finding cannot move to `validated` without attached evidence
(finding_verifier.py:139-144); `mark_report_ready` requires `validated`
(finding_verifier.py:238-246). `_score_impact` produces a 0-100 impact score from
vuln class + impact-text keywords (finding_verifier.py:306-329); `_severity_label`
maps it to Critical/High/Medium/Low/Informational (report_generator.py:39-48).
`generate_validation_tasks` (finding_verifier.py:340-377) creates the recon tasks
needed to fill missing evidence/reproduction steps.

## Proof-of-Execution Verification (tools/verification/poe_verifier.py)

A claimed compromise is only trusted after independent verification against the
live target (poe_verifier.py:1-5). `_verify_sync` (poe_verifier.py:172-237):

1. Writes a unique canary token (`PoE-<ip>-<uuid>`, poe_verifier.py:67-80) to a
   temp file on the target via `run_exploit_terminal`.
2. Reads it back in the same shell call — a missing echo means the write/read did
   not land on the target → `verified=False` (poe_verifier.py:200-211).
3. Collects `id` / `whoami` / `hostname` probes and classifies privilege via
   `classify_privilege` → `root`/`system`/`user`/`unknown` (poe_verifier.py:134-153).

Any executor failure (`BLOCKED:`, `TOOL_EXECUTION_ERROR:`, exception, timeout)
collapses to `verified=False` with the reason captured in `evidence` — the verifier
never raises into the campaign (poe_verifier.py:14-17, 262-281, 305-327). Async
entry `verify_compromise` offloads the blocking executor to a thread and shields
with an asyncio timeout (poe_verifier.py:284-327). The returned verdict dict is
`{verified, evidence, privilege, shell_type, token, target_ip}` (poe_verifier.py:230-237).

## Summarization and Report Generation

### Summarization (summarizer.py)

`summarize_tool_output` (summarizer.py:15-44) compresses raw tool output for LLM
context by tool type: nmap (open ports/OS), search (entry lists), HTTP (status +
key headers), msf (session/exploit lines), python, terminal (exit code, command,
tail), generic. Truncated output notes `[truncated, full output saved as evidence]`
(summarizer.py:161-164). `summarize_observation` (summarizer.py:167-182) builds the
one-liner observation summary (facts/signals/findings/dead ends).

### Reports

- **Flow B finding reports** — `ReportGenerator.generate_report` requires
  `report_ready` status and renders the 11-section template (summary, affected
  asset, vuln class, severity, preconditions, reproduction steps, expected/actual
  behavior, evidence refs, security impact, remediation, notes) to
  `<workspace>/reports/<finding_id>.md` (report_generator.py:53-135, 155-257).
  `export_report` returns the same content as JSON (report_generator.py:259-280);
  `generate_summary_report` aggregates all report-ready findings into
  `summary_report.md` (report_generator.py:282-335).
- **Enhanced red-team reports** — `EnhancedReportGenerator.generate_full_report`
  (enhanced_reporting.py:255-312) writes JSON + Markdown (+ optional HTML) under
  `<workspace>/enhanced/`, composed of: executive summary (per-target recon,
  critical exploits, privilege escalations, credentials, success rate —
  enhanced_reporting.py:314-408), attack timeline (enhanced_reporting.py:410-439),
  exploitation chains (enhanced_reporting.py:488-538), failure analysis with
  error categorization and mitigations (enhanced_reporting.py:441-486,
  1258-1293), and technical findings with CVSS 3.1 scoring (enhanced_reporting.py:51-128,
  540-584). When an `EvidenceStore` is passed, findings are back-filled with
  promoted audit evidence refs and derived reproduction steps
  (enhanced_reporting.py:762-830); when `outcome_assessments` (keyed by target IP)
  is passed, confidence comes from the verdict — CONFIRMED→0.95, REFUTED→0.2,
  INCONCLUSIVE→0.5 (enhanced_reporting.py:1322-1330).
- **Eval reports** — `write_eval_report` (eval_harness.py:328-355) writes
  `eval_report.json` / `.md` / `.html` under `reports/eval/<run_id>/`.

## Evaluation Harness Scoring

### `--eval` (tools/eval_harness.py) — legacy single-run smoke report

Runs one attack session against `--target` and derives `EvalMetrics`
(eval_harness.py:101-123) from the final-result dict:

- Counts parsed from the `_ToolOutcomeTracker` summary string: compromises,
  cred dumps, partials (eval_harness.py:64-78); failures counted from audit
  records whose `status` contains fail/error/block (eval_harness.py:81-94).
- `success_rate = (compromise_count + cred_dump_count) / total_actions`
  (eval_harness.py:171-175) — note this is events-per-action, not run-success.
- `verdict`: `compromised` > `cred_dump` > `partial` > `no_access` > `error`
  (eval_harness.py:177-186).
- Evidence refs are copied through from the final result (eval_harness.py:161-166).

The harness itself adds no gate — the MCP target-IP allowlist is the lock
(eval_harness.py:15-18).

### `tools/eval_benchmark.py` — oracle-backed paired benchmark

The benchmark fixes the legacy harness's self-scoring weakness: **a success counts
only when a caller-supplied target-side oracle confirms it**, independent of the
agent's text, exit code, or `OutcomeJudge` verdict (eval_benchmark.py:10-30,
336-340). Per trial it records both `verified_success` (oracle) and
`agent_claimed_success` (parsed from `outcome_summary`, eval_benchmark.py:276-277)
so it can compute a **false-positive rate** (agent claimed, oracle did not confirm;
eval_benchmark.py:360-365). Aggregates: verified success rate per condition,
paired risk ratio `RR = mean(Y_treatment)/mean(Y_baseline)` with a 1000-sample
bootstrap 95% CI (eval_benchmark.py:375-405), actions per verified success, and
time-to-first-verified-success. Baseline disables the smart features
(`outcome_judgment.flow_a` off, eval_benchmark.py:157-166); treatment enables them
(eval_benchmark.py:168-177). Results persist to
`reports/eval_benchmark/benchmark_<timestamp>.json` (eval_benchmark.py:421-423).

## Pipeline

```text
                 Flow A                                        Flow B
   MCP tool result ──────────────┐                     ExecutionResult
          │                      │                          │
   normalize_action_result        │                    structured Observation
   (outcome_truth.py:339)         │                   + task success_criteria
   -> ActionResult                │                   + evidence_refs
   (operational_status,           │                          │
    exploit_outcome,              │                          v
    verified_success)             │                  OutcomeJudge.judge
          │                      │                   (outcome_judge.py:190)
          v                       │                   -> OutcomeAssessment
   classify_exploit_outcome       │                   (status, confidence,
   (outcome_truth.py:187)         │                    information_value,
   -> compromise/cred_dump/       │                    check_fingerprint)
     partial/failure/unknown      │                          │
          │                      │                          v
          v                       │               HypothesisRepository
   build_observation        ┌─────┴──────────►   persist_assessment (SQLite)
   (outcome_adapter.py:72)  │                     + db.log_audit("outcome_judgment")
   -> task/observation/     │                            │
     execution_result       │                            v
          │                 │                     FindingVerifier
          v                 │                     (candidate -> validated ->
   judge_flow_a /           │                      report_ready, evidence checks)
   judge_outcome            │                            │
   (outcome_adapter.py)     │                            v
   -> (status, confidence)  │                     ReportGenerator
          │                 │                     <workspace>/reports/<id>.md
          v                 │
   ExploitRecord -> exploit_audit.jsonl
   (hash-chained, policy.py:468)
          │
          v
   poe_verifier.verify_compromise      (independent target-side canary check)
          │
          v
   evidence.promote_exploit_audit -> EvidenceStore (structured_json rows)
          │
          v
   EnhancedReportGenerator -> <workspace>/enhanced/report_*.{json,md,html}
   eval_harness / eval_benchmark -> reports/eval|eval_benchmark/
```

The truth flow: **attempt → evidence → classification → truth → judgment →
finding → report**. A terminal judge verdict (CONFIRMED/REFUTED) is what closes a
hypothesis; `verified_success` is what gates access-achieved and finding creation;
`FindingVerifier` is what makes a finding reportable; reports render only
`report_ready` findings with evidence references attached.

## Regression Coverage

- `tests/test_outcome_judge.py` — deterministic, no network/model: execution vs
  evidence separation, matching/contradictory structured evidence, repeated
  inconclusive attempts, duplicate-check rejection, terminal-state planning
  guards, restart persistence, v3 DB migration (docs/testing-guide.md:96-104).
- `tests/test_outcome_classify.py`, `tests/test_outcome_judge_flow_a.py`,
  `tests/test_cross_mission_wiring.py` — Flow A classification and judge bridge
  (docs/testing-guide.md:41, 62).
- Outcome judgment does not replace the safety gates; scope/approval/target-lock
  tests remain the safety regression suite (docs/testing-guide.md:102-104).
