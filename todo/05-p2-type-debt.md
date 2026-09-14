# P2 — Reduce type debt

Owner: Muse Spark (AI)
Tracking issue/PR: _not created (human creates per packet-03 issue plan)_
Status: Batch 1 complete (278 → 276) — CI verification rides the packet-00 PR

## Goal

Keep the type-debt ratchet strictly downward and concentrate fixes in runtime-
critical paths where incorrect shapes and optional values create real failures.

## Starting point

Debt script re-run at assignment time: **278 errors (baseline 278)** — the
assessed 285 spike was already repaired in packet 00 (7 errors fixed at
source). `pyproject.toml` stale `301 errors in 65 files` comment confirmed
present; fixed below.

## Debt grouping (hermetic `scripts/mypy_debt.py` raw run, 2026-09-14)

By error code (top): `union-attr` 57, `attr-defined` 51, `arg-type` 39,
`name-defined` 36, `assignment` 28, `misc` 13, `var-annotated` 10,
`call-arg` 9, `operator` 8, `index` 6, `return-value`/`no-redef` 5 each —
Optional/shape handling dominates, matching the packet's risk thesis.

By subsystem (top): `exploit_agent` 47, `api` 45, `mcp_tools` 29,
`run_service` 27, `attack_ui.py` 24, `recon` 12, `reliability.py` /
`campaign` 10 each. Top files: `tools/api/run_manager.py` 35,
`tools/exploit_agent/runner/_impl.py` 31, `tools/attack_ui.py` 24,
`tools/run_service/execute.py` 18. Next batches should target
`run_manager.py` first (largest single holder; also packet-04 follow-on).

## Tasks

- [x] Fix any debt introduced after the committed baseline before starting
  opportunistic cleanup. (Done in packet 00: 285 → 278. Verified 278 at
  assignment; this packet starts clean.)
- [x] Update stale type-debt comments and documentation to derive from or match
  the actual baseline. (`pyproject.toml` 301/335 → non-numeric wording with
  baseline pointer; `AGENTS.md`, `CLAUDE.md` ×2, `CONTRIBUTING.md` ×2 file-count
  claims → non-numeric. `docs/type-checking.md` had no stale numbers.)
- [x] Group the current errors by subsystem and error code. (Tables above.)
- [x] Define typed state/result structures at the highest-risk dictionary and
  optional-value boundaries. (Batch 1: `ScopeGate | None` optional boundary
  in `tools/exploit_agent/policy.py` via `TYPE_CHECKING` import — explicit
  useful type, not a cast; runtime import-free so Flow A keeps no hard
  dependency on the frozen path.)
- [x] Remove errors in small, behavior-preserving pull requests with focused
  tests. (Batch 1: 2 errors, `test_exploit_scope_gate` 9 + 
  `test_exploit_permission` 7 passed — runtime behavior identical,
  annotations are strings.)
- [x] Coordinate with the exploit-runner refactor to avoid conflicting moves.
  (Batch 1 deliberately avoids `_impl.py`/runner internals — packet 04
  untouched. Recommended next: `run_manager.py`, coordinated with 04.)
- [x] Reject new broad ignores, unbounded `Any`, or baseline increases used only
  to silence the ratchet. (Diff adds zero ignores/`Any`; baseline moved only
  downward via `--update` after a verified batch.)
- [x] Lower the committed baseline after every verified cleanup batch.
  (`mypy-baseline.txt`: 278 → **276**; `policy.py` drops out of the file.)
- [x] Publish a short trend summary in CI so maintainers can see progress.
  (`scripts/mypy_debt.py --trend`: total + top-5 from the committed baseline,
  no mypy run; new `Mypy debt trend summary` step in the CI `types` job,
  informational, never fails. Current top-5 in the Evidence section.)

## Acceptance criteria

- [x] The baseline never moves upward. (278 → 276.)
- [x] Stale counts in configuration or documentation are corrected.
- [x] Runtime-critical interfaces gain explicit, useful types rather than cosmetic
  casts.
- [x] Each cleanup batch lowers the committed error count and passes focused tests.
- [x] The normal mypy job and the independent debt ratchet both pass.
  (`mypy --follow-imports=skip tools`: 337 files, no issues; strict hot
  files + strict subsystems: no issues; ratchet: 276 = baseline.)

## Evidence (local, 2026-09-14)

- `scripts/mypy_debt.py` → `passed: 276 errors (baseline 276, delta +0)`;
  `--trend` → `276 errors in 64 files`, top: `run_manager.py` 35,
  `_impl.py` 31, `attack_ui.py` 24, `run_service/execute.py` 18,
  `reliability.py` 10.
- Focused tests (one file at a time, `-n 0`): `test_exploit_scope_gate` 9
  passed, `test_exploit_permission` 7 passed.
- `ruff check` on changed Python files: pass; `ruff format --check .`: pass.
- No new ignores, no `Any`, no baseline increase; no behavior change; no
  allowlist/sandbox weakening; frozen Flow B files untouched (type-only
  reference to `scope_gate.py`, never imported at runtime).

## Notes / follow-ups (not in this batch)

- Unrelated working-tree change `tools/eval_harness.py` (`__all__` gains
  packet-01 names with no definitions yet) exists in this checkout and was
  **left untouched** (preserve-unrelated-work rule). Consequence: repo-wide
  `ruff check .` is currently red with 9 `F822` errors, all inside that
  file; every other file passes. Not caused by, and out of scope for, this
  packet — packet-01 work should define or drop those names.
- Test-file counts are stale in docs (`~250` in `AGENTS.md`/`CONTRIBUTING.md`,
  `~340` in `CLAUDE.md`; actual 353 test files). Out of scope for task 2
  (type-debt counts) — suggested docs follow-up: same non-numeric treatment.

## Goal

Keep the type-debt ratchet strictly downward and concentrate fixes in runtime-
critical paths where incorrect shapes and optional values create real failures.

## Starting point

The assessed committed baseline was 278 errors, while the latest assessed
change increased it to 285. `pyproject.toml` also contained a stale comment
referring to roughly 301 errors.

Re-run the debt script before assigning work; counts may have changed.

## Priority areas

1. Exploit runner and its state/result objects.
2. Run manager and run-service execution layer.
3. MCP terminal and sandbox execution interfaces.
4. Evaluation result and reporting schemas.
5. API boundaries that deserialize or expose runtime state.

## Tasks

- [ ] Fix any debt introduced after the committed baseline before starting
  opportunistic cleanup.
- [ ] Update stale type-debt comments and documentation to derive from or match
  the actual baseline.
- [ ] Group the current errors by subsystem and error code.
- [ ] Define typed state/result structures at the highest-risk dictionary and
  optional-value boundaries.
- [ ] Remove errors in small, behavior-preserving pull requests with focused
  tests.
- [ ] Coordinate with the exploit-runner refactor to avoid conflicting moves.
- [ ] Reject new broad ignores, unbounded `Any`, or baseline increases used only
  to silence the ratchet.
- [ ] Lower the committed baseline after every verified cleanup batch.
- [ ] Publish a short trend summary in CI so maintainers can see progress.

## Acceptance criteria

- The baseline never moves upward.
- Stale counts in configuration or documentation are corrected.
- Runtime-critical interfaces gain explicit, useful types rather than cosmetic
  casts.
- Each cleanup batch lowers the committed error count and passes focused tests.
- The normal mypy job and the independent debt ratchet both pass.

