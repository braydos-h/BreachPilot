# Backlog progress checkpoint (2026-09-14, Packet 00 local complete)

## Completed

- Packet 00 (P0 — Restore green `main`): all LOCAL tasks done on `main`.
  Blocked items (need human/CI): 3.11/3.12/3.13 install confirmation, browser
  image build + smoke (no Docker daemon locally), full PR/CI verification
  (no push/PR authorization in this session).
  - Ruff: formatted `.claude/hooks/guard-pytest.py`; `ruff check .` 0 errors,
    `ruff format --check .` 0 diffs. Also fixed the lint MCP bare-except
    guard (9 annotations; pre-existing failure found during verification).
  - Deps: `constraints-dev.txt` `numpy==2.5.3` → `==2.4.6` (Requires-Python
    `>=3.11`; cp311/cp312/cp313 wheels verified; constraints audit passes).
  - Sandbox: new `is_pure_local_computation` classifier
    (`tools/sandbox/policy.py`); `SandboxManager._enforce_scope` accepts
    `command` and allows empty target ONLY for provably-local work;
    `+ _scope_command_from_argv` for the argv path; integration `_run`
    passes the authorized `target_ip` (firewall decides). New tests:
    classifier cases (`test_sandbox_policy.py::TestPureLocalComputation`)
    + gate cases (manager: local-allowed ×2, network/script/unscoped
    blocked ×3).
  - DNS: injectable `resolver_fn` on `build_network_policy` /
    `_resolve_authorized` (threaded to `resolve_all_addresses`); rewrote the
    stale-mock test to the production seam + added mixed IP+domain test.
  - Browser: `Dockerfile.browser` now builds an image-local venv
    (`/opt/bp-browser-venv` on PATH, `PLAYWRIGHT_BROWSERS_PATH` shared,
    no bypass flag).
  - Types: fixed all 7 new errors at source (tool-name helper, `_focus`
    None-narrowing, `ServiceBanner` typing via `_common`, `Sequence`
    covariance in `branch.py`, `TargetCorrection` list); debt 285 → 278,
    ratchet passes, baseline untouched.
  - Packet file `todo/00-p0-restore-green-main.md` updated (owner, task
    checkboxes, verification table, evidence, human actions).

## Validation (local, one file at a time, `-n 0`)

- `ruff check .` pass; `ruff format --check .` pass; bare-except guard pass;
  god-file budget pass; config-schema sync pass; docs-truth guard pass.
- `scripts/mypy_debt.py` pass (278 = baseline); `mypy --follow-imports=skip
  tools` pass (337 files); strict hot files + strict subsystems pass.
- Tests passed: sandbox_policy 40, sandbox_manager 29, sandbox_mcp_exec 11,
  sandbox_network 21, sandbox_models 8, sandbox_backend 22, sandbox_hotpath
  10, mcp_tool_scope 13, attack_focus 25, attack_focus_loop 4,
  exploit_scope_gate 9, exploit_permission 7, flow_a_enhanced_report 5.
- `test_sandbox_integration` 14 skipped (no Docker daemon).
- Constraints-vs-pyproject audit pass. No allowlist/sandbox weakening; no
  host fallback; no frozen Flow B edits; no full-suite runs.

## Commits

- P0 local commit on `main` (this checkpoint included): message
  `P0: restore green main (local fixes; CI/PR verification blocked)`.
  (Hash: fill in after commit — see `git log --oneline -3`.)

## Blockers (human actions)

1. Open a PR from the P0 commit (no push/PR authorization here) and confirm
   full CI: tests matrix 3.11/3.12/3.13, sandbox (real Docker), browser
   (image builds + smoke), coverage, lint, types, package, webui, audit.
2. On CI: `docker build` both sandbox images with no bypass flag; browser
   smoke/integration.
3. If CI green → mark packet 00 complete; packets 01/02 unblock.

## Precise next action

- After committing P0: continue to packet 03 (repository governance,
  independent of green main) for local tasks (`SECURITY.md`, merge/
  emergency docs, label/issue plan — ruleset/labels/issues need GitHub
  admin, mark blocked), then packet 07 (documentation truth, independent),
  then packet 05 (type debt: stale comments, grouping, trend), keeping one
  commit per packet and never running banned pytest invocations.

---

## Packet 03 — repository governance (2026-09-14, local tasks complete)

- Verified read-only: NO rulesets (`[]`), `main` NOT branch-protected (404),
  only default labels, no packet tracking issues. Dependabot operates
  (weekly + open PRs); Dependency Review runs on `pull_request`; CodeQL runs
  on `push` + `pull_request` + weekly (py + js) — coverage supports required
  checks.
- Local deliverables: new `SECURITY.md` (0.68.x supported; private GitHub
  Security Advisory path, no invented email; lab-only scope notes);
  `CONTRIBUTING.md` §11b merge + emergency-fix process (PR + green checks +
  evidence, zero required approvals; direct pushes only to restore a broken
  PR flow with immediate follow-up PR).
- Packet file updated with owner, checkbox states, proposed ruleset spec
  (`CI success` + CodeQL py/js + dependency-review; 0 approvals; no bypass;
  block force push), proposed label spec (p0/p1/p2, evaluation, benchmark,
  ci, architecture, release, security; reuse `documentation`), and the nine
  issue titles.
- BLOCKED on human (external changes, no authorization): create the ruleset,
  create labels, create nine tracking issues + link numbers back, confirm
  private advisories enabled.
- Verification: no Python changed (no pytest needed); markdown-only.
- Precise next action: commit packet 03, then packet 07 (documentation
  truth, independent).

---

## Packet 07 — documentation truth (2026-09-14, local tasks complete)

- New guard `scripts/docs_truth_audit.py` (`links`: 163 files, GitHub slugs
  with code-span/underscore/dupe handling; `versions`: triple-source
  equality + stale `0.49.12`/`netcheck` scan) wired into the CI `lint` job
  (aggregate signal); new `tests/test_docs_truth_audit.py` (9 passed).
- Fixes: phase-audit refs (replace/remove), api.md ToC anchors ×7, deployment
  README anchor, stale versions ×3 → `0.68.4`, eval SKIPPED-not-pass wording,
  benchmark manual-only wording. Regenerated tool catalog (166→167) + config
  ref (439→444) from source; date-only churn elsewhere reverted.
- Claims spot-check: providers 3/3, flags 61/61, skills 146 unchanged.
  No behavior changes (workflows untouched for packets 01/02).
- Verification: audit green; `ruff check`/`format` green; docs-truth + no-args
  guards green; focused test file green.
- BLOCKED only on CI confirmation via the packet-00 PR (no separate
  authorization); GitHub-side release metadata itself is packet-08 scope.
- Precise next action: commit packet 07, then packet 05 (type debt).
