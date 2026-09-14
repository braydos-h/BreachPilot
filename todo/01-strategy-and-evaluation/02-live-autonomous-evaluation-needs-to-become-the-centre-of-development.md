# 02. Live autonomous evaluation needs to become the centre of development

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14) |
| Suggested priority | P0 |
| Suggested horizon | 30-day |
| Theme | Strategy and evaluation |
| Dependencies | None recorded; confirm during scoping. |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

Audit claim revalidated 2026-09-14: accurate. Taxonomy (`PASS/FAIL/SKIPPED/INFRA_ERROR`),
`classify_live_outcome` precedence, telemetry, reliability metrics, and live thresholds
exist in `tools/eval_harness.py`; but `.github/workflows/eval.yml` graceful-skip did
`exit 0` with no artifact, and provenance lacked model/prompt/catalog hashes and
sandbox digest.

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [x] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [x] Add or update focused tests and evaluation coverage where applicable.
- [x] Update generated and user-facing docs/config contracts where applicable.
- [ ] Record completion evidence below and update [the backlog index](../README.md).

Slice 1 (2026-09-14, Muse Spark): provenance + SKIPPED-visibility. Affected:
`tools/eval_harness.py` (`RunProvenance` + `write_skipped_eval_report`),
`tests/test_eval_live_outcome.py`, `.github/workflows/eval.yml`. Remaining: Level B
hermetic lab per-PR trigger, Level C repeated-trials release gate, baseline-delta
publishing (see follow-ups).

## Requirements called out by the audit

- [ ] `PASS`
- [ ] `FAIL`
- [ ] `SKIPPED`
- [ ] `INFRA_ERROR`

## Audit recommendation

This is the most important item in the entire audit.

The latest commit adds an improved evaluation taxonomy:

* `PASS`
* `FAIL`
* `SKIPPED`
* `INFRA_ERROR`

and reliability metrics.

That is the right direction.

But the actual GitHub workflow still contains:

```text
Graceful skip without OLLAMA_API_KEY
...
exit 0
```

and only executes the live evaluation if the key exists.

So at the moment there is a disconnect:

**evaluation framework improved → CI wiring hasn't finished catching up.**

Your own backlog correctly identifies why this matters: mocked unit tests cannot tell you whether the agent loops, chooses the wrong attack path, falsely declares compromise, misses discovered credentials, or burns its budget on useless enumeration.

## What I would build

Create three levels.

### Level A — deterministic CI

Every PR:

```text
scope/property tests
sandbox tests
planner state-machine tests
tool parsing tests
finding verifier tests
mocked model traces
WebUI tests
type/lint
```

Fast, deterministic and mandatory.

### Level B — hermetic autonomous lab

Every PR that modifies:

```text
planner/
exploit_agent/
skills/
tool registry/
prompts/
model routing/
finding verification/
sandbox/
```

should run something like:

```text
BreachPilot
    ↓
Docker test network
    ├── web-basic
    ├── web-auth
    ├── API
    ├── Linux service
    ├── AD/synthetic network
    └── intentionally-secure target
```

The **secure target** is particularly important.

A pentesting agent needs negative controls. Otherwise it learns/tests only whether it can produce findings.

Measure:

```text
TP   real bug correctly verified
FP   claims bug where none exists
FN   missed known bug
Unsupported compromise claim
Loops
Repeated actions
Scope rejects
Tool errors
Actions
Tokens
Cost
Time
```

### Level C — stochastic release evaluation

Before a release, execute each representative scenario perhaps **5–10 times**, not once.

LLM agent performance is stochastic.

A single successful run proves very little.

Store:

```text
model
model version
provider
temperature/sampling
prompt hashes
skill catalog hash
tool catalog hash
scenario version
git SHA
sandbox image digest
seed if applicable
token usage
cost
runtime
complete action trace
verifier output
```

Then compare distributions against the previous release.

For example:

```text
v0.68.4
verified compromise:    61%
false compromise:       4.2%
median actions:         43

candidate v0.69
verified compromise:    74%
false compromise:       1.1%
median actions:         31
```

Now you can legitimately claim the product became better.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: (slice 1 done; Levels B/C still open — see follow-ups)
- Design/issue: Wave 0 — make missing live infra unable to appear green
- Commits/PRs: working-tree (uncommitted): tools/eval_harness.py (extended
  RunProvenance: model_id/version, temperature, config/prompt/tool/skill hashes,
  breachpilot_version, sandbox digest; new write_skipped_eval_report),
  tests/test_eval_live_outcome.py (+2 tests), .github/workflows/eval.yml
  (SKIPPED report + step summary + error-on-missing artifact)
- Tests/evaluations: tests/test_eval_live_outcome.py 17 passed; ruff clean
- Documentation: eval.yml header + step summary now say SKIPPED≠green
- Follow-ups: Level B hermetic lab on planner/exploit_agent/skills/registry/prompt/
  routing/verification/sandbox PRs; Level C 5–10x repeated trials with
  model/prompt/catalog/sandbox-digest pinning and baseline-delta table; protected-main
  eval gate (#41); provider comparison harness (#38).

