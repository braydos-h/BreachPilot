# P2 — Make documentation mechanically truthful

Owner: Muse Spark (AI)
Tracking issue/PR: _not created (human creates per packet-03 issue plan)_
Status: Local tasks complete — CI verification rides the packet-00 PR (no separate PR authorization)

## Goal

Use automated truth checks to keep the existing documentation aligned with the
code, release state, configuration, and available artifacts.

## Assessed drift — verification against current repo (2026-09-14)

- CONFIRMED: `docs/architecture.md:260` cited absent
  `docs/phase2-audit/architecture-debt.md` (with stale import counts);
  `docs/capability-upgrade-design.md:4` cited absent `docs/phase1-audit/`.
  Neither directory exists.
- CONFIRMED (stale versions): `docs/webui/overview.md:35`,
  `docs/webui/build.md:38`, `docs/components/root/main.md:48` claimed
  `0.49.12` (and a wrong `main.py` line); all three sources agree on
  `0.68.4` (`pyproject.toml:7`, `main.py:13`, `webui/package.json:4`).
- CONFIRMED (link rot): `docs/api.md` ToC had 7 wrong anchors (graph routes
  + WS stream, written as if `/` slugs to `-`; GitHub removes it),
  `docs/deployment.md:12` pointed at `README.md#-safety-model` (heading is
  `#safety-model`). No missing *files* besides the phase-audit refs.
- CONFIRMED (healthier-than-real): `docs/evaluation.md` described the keyless
  nightly skip as "graceful" without saying green means SKIPPED-not-pass;
  `docs/benchmarks.md` claimed "manual or scheduled" live jobs though
  `benchmark.yml` has no `schedule` trigger. Behavior fixes are packets
  01/02 (blocked); wording fixed here.
- NOT FOUND in product docs: `NetCheckAi` branding (only `todo/08`, excluded
  backlog scope) and type-debt-count staleness (the `278/285/301` grep hits
  are all `file:line` citations, not debt claims).
- Claims spot-check: providers 3/3 match (`ollama`, `opencode_go`,
  `chatgpt`); all 61 `main.py` flags present in `cli-generated.md`;
  generated tool catalog was stale (166, missing `run_exploit_terminals`) and
  config reference was stale (439 keys, missing 5 attack-focus keys) — both
  regenerated from source (167 tools / 444 keys). Skill catalog verified
  unchanged (146) and left alone; CLI reference verified unchanged (date-only
  diff reverted).

## Tasks

- [x] Run an internal-link audit across Markdown files and classify every dead
  link as restore, replace, or remove.
- [x] Correct references to missing phase-audit material.
- [x] Add a CI guard for internal Markdown links and anchors.
- [x] Add or extend guards for the advertised package/version value.
- [x] Verify documented provider, model, backend, CLI flag, MCP tool, and config
  key claims against their registries and parsers where possible.
- [x] Verify benchmark and evaluation documentation states when live work may be
  skipped and how that status is displayed.
- [x] Replace stale repository names and release links.
- [x] Prefer generated counts or deliberately non-numeric wording for values
  that change frequently, unless CI verifies the number.
- [x] Add documentation checks to the aggregate CI signal.

## Acceptance criteria

- [x] Internal documentation links and anchors pass an automated check.
  (`scripts/docs_truth_audit.py --check links`: 163 files green; wired into
  the CI `lint` job, hence the aggregate `CI success` signal.)
- [x] No current page points to missing phase-audit content.
- [x] User-facing versions, flags, config keys, providers, and backend claims match
  source-of-truth code/configuration.
- [x] Eval and benchmark docs do not equate a skipped live run with a pass.
- [x] Release and repository links use current BreachPilot metadata.
  (In-repo: yes. The GitHub-side prerelease trail itself is packet-08
  release scope, blocked.)

## Evidence (local, 2026-09-14)

- New `scripts/docs_truth_audit.py` (stdlib; `links`: fenced-code-aware,
  GitHub slugs incl. code-span headings/underscores/duplicate suffixes +
  explicit anchors; `versions`: triple-source equality + stale `0.49.12` /
  `netcheck` scan) + new `tests/test_docs_truth_audit.py` (9 passed).
- `docs_truth_audit.py` → `passed (all): 163 files checked`.
- `ruff check .` 0 errors; `ruff format --check .` 0 diffs.
- `test_docs_truth_audit` 9 passed; `test_validate_target` 24 passed
  (ran as a neighboring-docs sanity slice, one file at a time, `-n 0`).
- Regenerated from source: `docs/mcp/tool-catalog-generated.md` (166→167,
  picks up `run_exploit_terminals`), `docs/configuration/config-reference-
  generated.md` (439→444, picks up 5 attack-focus keys). Date-only churn in
  `cli-generated.md` / `skills/catalog.md` reverted.
- No behavior changes: eval/benchmark workflows untouched (packets 01/02);
  no new scanners/modules/agents/UI; no allowlist/sandbox weakening.

## Classification log (restore / replace / remove)

- `docs/phase2-audit/architecture-debt.md` cite → REPLACE with live
  `legacy/README.md` pointer; stale import counts dropped (remove).
- `docs/phase1-audit/` companion clause → REMOVE (design is self-contained).
- `docs/api.md` ToC graph/WS anchors (7) → REPLACE with true GitHub slugs.
- `docs/deployment.md` `README.md#-safety-model` → REPLACE with `#safety-model`.
- `0.49.12` version claims (3) → REPLACE with `0.68.4` (+ correct line ref).
- Eval "graceful skip" → REPLACE with explicit SKIPPED-not-pass wording.
- Benchmark "manual or scheduled" → REPLACE with manual-only truth.
- Nothing qualified for RESTORE (absent material has no live original).

## Goal

Use automated truth checks to keep the existing documentation aligned with the
code, release state, configuration, and available artifacts.

## Assessed drift

- Some architecture/design pages refer to absent `docs/phase1-audit` or
  `docs/phase2-audit` material.
- Version and type-debt counts have become stale in some locations.
- Public release metadata and repository branding trail the source.
- Eval and benchmark checks can appear healthier than the work they actually
  performed.

## Tasks

- [ ] Run an internal-link audit across Markdown files and classify every dead
  link as restore, replace, or remove.
- [ ] Correct references to missing phase-audit material.
- [ ] Add a CI guard for internal Markdown links and anchors.
- [ ] Add or extend guards for the advertised package/version value.
- [ ] Verify documented provider, model, backend, CLI flag, MCP tool, and config
  key claims against their registries and parsers where possible.
- [ ] Verify benchmark and evaluation documentation states when live work may be
  skipped and how that status is displayed.
- [ ] Replace stale repository names and release links.
- [ ] Prefer generated counts or deliberately non-numeric wording for values
  that change frequently, unless CI verifies the number.
- [ ] Add documentation checks to the aggregate CI signal.

## Acceptance criteria

- Internal documentation links and anchors pass an automated check.
- No current page points to missing phase-audit content.
- User-facing versions, flags, config keys, providers, and backend claims match
  source-of-truth code/configuration.
- Eval and benchmark docs do not equate a skipped live run with a pass.
- Release and repository links use current BreachPilot metadata.

