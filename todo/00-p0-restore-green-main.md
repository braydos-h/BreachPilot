# P0 — Restore green `main`

Owner: Muse Spark (AI)
Tracking issue/PR: _not created (no push/PR authorization — human must open the PR for CI verification)_
Status: Local fixes complete — blocked on PR/CI verification (see Evidence)

## Goal

Restore all required CI paths on the latest `main` without weakening the
allowlist, sandbox, test, or type-debt safeguards.

## Assessed failures — verification against current repo (2026-09-14)

| Failure | Verified current state | Fix applied |
|---|---|---|
| Ruff formatting | REPRODUCED: `ruff format --check .` failed on `.claude/hooks/guard-pytest.py` only | Formatted with Ruff; `ruff check .` + `ruff format --check .` pass |
| Python 3.11 installation | CONFIRMED: `numpy==2.5.3` metadata says `Requires-Python >=3.12`, repo supports `>=3.11`; only pin incompatible with 3.11 (all others allow 3.10/3.11) | Re-pinned to `numpy==2.4.6` (`>=3.11`, wheels for cp311/cp312/cp313 verified); constraints-vs-pyproject audit passes |
| Sandbox integration | REPRODUCED: `tests/test_sandbox_policy.py::TestBuildNetworkPolicy::test_fqdn_resolved_host_side_and_validated` FAILED (mocked stale seam, real DNS leaked); integration fixture `mgr.execute("true")` with enforced allowlist denied empty target (no local-computation distinction) | Added `is_pure_local_computation` classifier (`tools/sandbox/policy.py`), threaded `command` into `SandboxManager._enforce_scope` (empty allowed ONLY for provably-local work); integration `_run` now passes the authorized `target_ip` so the netns firewall (not the scope gate) decides |
| Mixed-scope DNS test | REPRODUCED: production `_resolve_authorized` uses `resolve_all_addresses`, test mocked `resolve_target_to_ip` (no effect) | Added injectable `resolver_fn` to `build_network_policy`/`_resolve_authorized` (threaded to `resolve_all_addresses`); rewrote tests to the production seam + added mixed IP+domain test |
| Browser worker image | CONFIRMED: `Dockerfile.browser` ran system-Python `pip install` (PEP 668 failure on Debian 12) | Image-local venv at `/opt/bp-browser-venv` (PATH + `PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright`, no bypass flag) |
| Type-debt gate | REPRODUCED: `scripts/mypy_debt.py` reported baseline 278 → current 285 (`_impl.py` 31→37, `terminal/execute.py` 0→1) | Fixed all 7 at source (typed tool-name helper, `_focus` None-narrowing, `ServiceBanner` typing, `Sequence[Mapping]` callee covariance, `TargetCorrection` list); debt back to 278, gate passes |
| (Unlisted) MCP bare-except guard | FOUND during verification: lint guard failed on 9 bare `except Exception` in `tools/mcp_tools` + `tools/exploit_agent` (custom `ponytail:` wording missing the required `bare except intentional` marker, incl. 7 from the attack-focus commit) | Annotated all 9 with the required `ponytail: bare except intentional` marker (no behavior change; none wrap MCP lifecycle) |

## Tasks

- [x] Reproduce each failing CI job from the assessed commit and record its
  current failure output in the tracking issue.
- [x] Run Ruff formatting on `.claude/hooks/guard-pytest.py` and verify the
  repository-wide format check.
- [ ] Generate or validate dependency constraints using Python 3.11, then
  confirm installation on Python 3.11, 3.12, and 3.13.
  (VALIDATED via Requires-Python + wheel availability; installation
  confirmation BLOCKED — no 3.11/3.12 interpreters or Docker locally, and no
  PR authorization. Human: open the PR and confirm the 3.11/3.12/3.13 matrix.)
- [x] Make the NumPy constraint compatible with every supported Python version.
- [x] Fix the sandbox command classifier so local computation such as plain
  `python -c` is distinguished from network-capable, target-touching execution.
- [x] Add focused tests for allowed local computation and blocked unscoped
  network/target operations.
- [x] Introduce or restore one injectable DNS resolver interface used by both
  production and tests.
- [x] Update the mixed-scope DNS test to mock that interface.
- [x] Create a virtual environment inside `Dockerfile.browser`, install
  Playwright into it, and put its binaries on `PATH`.
- [ ] Build the browser image and run its focused smoke test without using
  `--break-system-packages`.
  (BLOCKED — no Docker daemon locally. Human/CI: `docker build -t
  breachpilot-sandbox:latest docker/sandbox` then `docker build -t
  breachpilot-sandbox:browser -f docker/sandbox/Dockerfile.browser
  docker/sandbox`, then the browser CI job.)
- [x] Fix the seven newly introduced mypy errors in their source locations.
- [x] Run the type-debt ratchet and keep the committed baseline at or below 278.
- [ ] Verify all formerly red jobs on a pull request.
  (BLOCKED — no push/PR authorization. Human: open a PR from this commit and
  confirm tests/sandbox/browser/coverage/lint/types/package/webui/audit all green.)

## Constraints

- Do not weaken `_allowed_target_list`, `_target_lock_block`, or the default-on
  sandbox to make an integration test pass.
- Do not add a host `subprocess` fallback for sandbox failures.
- Do not update the mypy baseline upward.
- Do not run the complete test directory locally; follow the test-slice rules
  in `AGENTS.md` and `CLAUDE.md`.
- All honored: allowlist/lock untouched; sandbox stays default-on fail-closed
  (empty allowed ONLY for provably-local work); no host fallback added;
  `mypy-baseline.txt` untouched at 278; tests run one file at a time with
  `-n 0`.

## Acceptance criteria

- [ ] The Python 3.11–3.13 CI matrix installs and passes. (BLOCKED on PR/CI;
  local: constraints audit passes, numpy wheels verified for all three.)
- [x] Ruff check and format jobs are green. (Local: `ruff check .` 0 errors,
  `ruff format --check .` 0 diffs, MCP bare-except guard OK, god-file budget
  passes, config-schema sync OK, docs-truth guard OK.)
- [ ] Sandbox and browser-image integration jobs are green. (Local: sandbox
  unit files green — policy 40, manager 29, mcp_exec 11, network 21, models 8,
  backend 22, hotpath 10, tool-scope 13; integration skips cleanly without a
  daemon. Docker-backed confirmation BLOCKED on CI.)
- [x] The mixed-scope DNS behavior is tested through the production seam.
- [x] The type-debt job reports no increase from the committed 278 baseline.
- [ ] The aggregate required CI check on `main` is green. (BLOCKED on PR.)

## Evidence (local, 2026-09-14)

- `ruff check .` → All checks passed; `ruff format --check .` → 1359 files
  formatted; MCP bare-except guard → OK; `scripts/god_file_budget.py` →
  passed (grandfathered warnings only); config-schema sync → OK;
  docs-truth guard → OK.
- `scripts/mypy_debt.py` → `passed: 278 errors (baseline 278, delta +0)`;
  `mypy --follow-imports=skip tools` → no issues (337 files); strict hot
  files + strict subsystems → no issues.
- Tests (one file at a time, `-n 0`): `test_sandbox_policy` 40 passed,
  `test_sandbox_manager` 29 passed, `test_sandbox_mcp_exec` 11 passed,
  `test_sandbox_network` 21 passed, `test_sandbox_models` 8 passed,
  `test_sandbox_backend` 22 passed, `test_sandbox_hotpath` 10 passed,
  `test_mcp_tool_scope` 13 passed, `test_attack_focus` 25 passed,
  `test_attack_focus_loop` 4 passed, `test_exploit_scope_gate` 9 passed,
  `test_exploit_permission` 7 passed, `test_flow_a_enhanced_report` 5 passed,
  `test_sandbox_integration` 14 skipped (no Docker daemon).
- `numpy==2.4.6`: PyPI `Requires-Python >=3.11`; wheels present for
  cp311/cp312/cp313; `constraints-dev.txt` vs `pyproject.toml` audit → ok.
- No allowlist/sandbox weakening: `_allowed_target_list`,
  `_target_lock_block`, `require_explicit_allowlist` semantics untouched;
  `sandbox.enabled` default untouched; no host-execution fallback added
  (new `SANDBOX_*` paths all fail closed); frozen Flow B files untouched.

## Human actions required

1. Open a PR from this commit (no push/PR authorization in this session) and
   confirm the full CI matrix: tests (3.11/3.12/3.13), sandbox (real Docker),
   browser (image build + Playwright/Chromium), coverage, lint, types,
   package, webui, audit.
2. On CI: confirm `docker build` of both sandbox images succeeds without any
   bypass flag and the browser smoke/integration passes.
3. If CI is green, this packet can be marked complete; packets 01/02 unblock.

## Goal

Restore all required CI paths on the latest `main` without weakening the
allowlist, sandbox, test, or type-debt safeguards.

## Assessed failures

| Failure | Assessed cause | Intended correction |
|---|---|---|
| Ruff formatting | `.claude/hooks/guard-pytest.py` is not formatted | Format it with Ruff |
| Python 3.11 installation | `numpy==2.5.3` is pinned despite oldest-supported-Python guidance | Regenerate constraints on 3.11 or use compatible environment markers |
| Sandbox integration | Plain `python -c` is treated as target-less/network-capable | Correct command classification; do not weaken the gate globally |
| Mixed-scope DNS test | Test mocks a resolver seam production no longer uses | Centralize/inject resolution and test the production interface |
| Browser worker image | Debian PEP 668 rejects system-Python Playwright install | Install Playwright in an image-local virtual environment |
| Type-debt gate | Debt increased from 278 to 285 | Fix the seven new errors; do not raise the baseline |

## Tasks

- [ ] Reproduce each failing CI job from the assessed commit and record its
  current failure output in the tracking issue.
- [ ] Run Ruff formatting on `.claude/hooks/guard-pytest.py` and verify the
  repository-wide format check.
- [ ] Generate or validate dependency constraints using Python 3.11, then
  confirm installation on Python 3.11, 3.12, and 3.13.
- [ ] Make the NumPy constraint compatible with every supported Python version.
- [ ] Fix the sandbox command classifier so local computation such as plain
  `python -c` is distinguished from network-capable, target-touching execution.
- [ ] Add focused tests for allowed local computation and blocked unscoped
  network/target operations.
- [ ] Introduce or restore one injectable DNS resolver interface used by both
  production and tests.
- [ ] Update the mixed-scope DNS test to mock that interface.
- [ ] Create a virtual environment inside `Dockerfile.browser`, install
  Playwright into it, and put its binaries on `PATH`.
- [ ] Build the browser image and run its focused smoke test without using
  `--break-system-packages`.
- [ ] Fix the seven newly introduced mypy errors in their source locations.
- [ ] Run the type-debt ratchet and keep the committed baseline at or below 278.
- [ ] Verify all formerly red jobs on a pull request.

## Constraints

- Do not weaken `_allowed_target_list`, `_target_lock_block`, or the default-on
  sandbox to make an integration test pass.
- Do not add a host `subprocess` fallback for sandbox failures.
- Do not update the mypy baseline upward.
- Do not run the complete test directory locally; follow the test-slice rules
  in `AGENTS.md` and `CLAUDE.md`.

## Acceptance criteria

- The Python 3.11–3.13 CI matrix installs and passes.
- Ruff check and format jobs are green.
- Sandbox and browser-image integration jobs are green.
- The mixed-scope DNS behavior is tested through the production seam.
- The type-debt job reports no increase from the committed 278 baseline.
- The aggregate required CI check on `main` is green.

