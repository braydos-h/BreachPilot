# P1 — Establish repository governance

Owner: Muse Spark (AI)
Tracking issue/PR: _not created (issue/PR creation touches GitHub externally — human must create; drafts below)_
Status: Local tasks complete — blocked on GitHub admin + issue creation (see Evidence)

## Goal

Add lightweight controls around `main` so the existing CI, security, and debt
checks consistently protect releases and day-to-day development.

## Current state (verified 2026-09-14, read-only — nothing changed externally)

- Rulesets: `gh api repos/braydos-h/BreachPilot/rulesets` → `[]` (none).
- Branch protection: `branches/main/protection` → 404 `Branch not protected`.
  Assessment ("`main` was unprotected") is current.
- Labels: only the GitHub defaults (`bug`, `dependencies`, `documentation`,
  `enhancement`, …) — none of the packet's working labels exist.
- Issues: no reliability-packet tracking issues exist (only Dependabot PRs).
- Dependabot: `.github/dependabot.yml` runs weekly (pip + actions + npm) and
  operates (open update PRs present). Dependency Review runs on
  `pull_request` (`.github/workflows/dependency-review.yml`). CodeQL runs on
  `push` + `pull_request` + weekly for Python + JavaScript
  (`.github/workflows/codeql.yml`) — event coverage supports required status
  checks on PRs.
- `SECURITY.md`: did not exist — created in this packet.

## Tasks

- [x] Re-check the current GitHub ruleset and branch-protection state.
- [ ] Protect `main` with a ruleset that requires the aggregate CI check before
  merge.
  (BLOCKED — changing GitHub settings needs explicit authorization. Human:
  create the ruleset per the spec below; verify a test PR is blocked while
  red and mergeable when green.)
- [ ] Require CodeQL and other already-established security checks where their
  event coverage supports required status checks.
  (BLOCKED — same ruleset change. Coverage verified above: CodeQL +
  Dependency Review both run on `pull_request`, so both can be required.
  Include them per the spec below.)
- [ ] Require work to flow through pull requests, including maintainer-authored
  changes, without introducing unnecessary approval bureaucracy.
  (BLOCKED — same ruleset change. Process documented in
  `CONTRIBUTING.md` §11b: PR + green checks + §10 evidence, no self-approval
  ceremony; direct pushes reserved for restoring a broken PR flow with an
  immediate follow-up PR.)
- [ ] Create tracked issues from each work packet in this folder and link them
  back into the packet.
  (BLOCKED — creating issues modifies GitHub externally. Human: `gh issue
  create` once per packet using the titles below, then paste the issue
  numbers into each packet's `Tracking issue/PR` line.)
- [ ] Add labels for priority, evaluation, CI, architecture, release, security,
  and documentation work.
  (BLOCKED — label changes are external. Human: create per the spec below.
  `documentation` already exists and is reused, not duplicated.)
- [x] Add `SECURITY.md` with supported versions, reporting instructions,
  disclosure expectations, and a private contact path.
- [x] Confirm Dependabot and Dependency Review operate in the pull-request flow.
- [x] Document the minimal merge and emergency-fix process.

## Acceptance criteria

- [ ] Direct unvalidated changes cannot land on `main` through the normal workflow.
  (Needs the ruleset — human action below.)
- [ ] The repository's aggregate CI check is required before merge.
  (Needs the ruleset — required check name: `CI success`.)
- [ ] Each reliability packet has an assignable tracking issue.
  (Needs human-created issues — titles below.)
- [x] Security researchers have a current private reporting path.
  (`SECURITY.md`: private GitHub Security Advisory preferred, no public
  issues. Human: confirm private advisories are enabled for the repo under
  `Settings` → `Code security and analysis`.)
- [x] The process remains usable for a solo maintainer and does not require
  self-approval merely for ceremony.
  (`CONTRIBUTING.md` §11b: PR + green checks + evidence, zero required
  approvals.)

## Proposed ruleset (local spec — human applies, nothing changed here)

- Target: branch `main`. Enforcement: active. Bypass: none (emergency path
  is procedural per `CONTRIBUTING.md` §11b, not a ruleset bypass).
- Pull requests required (including maintainer-authored changes).
- Required status checks (must all pass):
  - `CI success` (the aggregate gate in `.github/workflows/ci.yml`, which
    already requires tests + sandbox + browser + coverage + lint + types +
    package + webui + audit),
  - CodeQL `Analyze (python)` and `Analyze (javascript)`,
  - Dependency Review `dependency-review`.
- Required approvals: 0 (solo maintainer — evidence in the PR, not ceremony).
- Block force pushes and deletions on `main`.

## Proposed labels (local spec — human creates, nothing changed here)

| Label | Color | Description |
|---|---|---|
| `p0` | `b60205` | Highest priority — red `main` / release blockers |
| `p1` | `d93f0b` | High priority — evaluation / benchmark / release work |
| `p2` | `fbca04` | Medium priority — refactors, debt, retirement, docs |
| `evaluation` | `0e8a16` | Live eval / graded runs / oracles |
| `benchmark` | `0e8a16` | XBEN suites, baselines, regression gating |
| `ci` | `1d76db` | CI, workflows, test infrastructure |
| `architecture` | `5319e7` | Runtime structure, refactors, module splits |
| `release` | `e99695` | Beta/release process, packaging, notes |
| `security` | `b60205` | Scope, sandbox, allowlist, audit, disclosure |
| `documentation` | _(exists — reuse)_ | Docs truth, guides, README |

Apply with e.g. `gh label create <name> --color <hex> --description "<text>"`.

## Proposed tracking issues (local spec — human creates, then links back)

One issue per packet, titled exactly:

1. `P0 — Restore green main` (packet `00`)
2. `P1 — Make live autonomous evaluation real` (packet `01`)
3. `P1 — Repair benchmark regression gating` (packet `02`)
4. `P1 — Establish repository governance` (packet `03`)
5. `P2 — Split the exploit runner` (packet `04`)
6. `P2 — Reduce type debt` (packet `05`)
7. `P2 — Retire Flow B incrementally` (packet `06`)
8. `P2 — Make documentation mechanically truthful` (packet `07`)
9. `P1 — Ship the reliability-focused 0.69 beta` (packet `08`)

Suggested body per issue: link the packet file, paste its Goal + Tasks, and
apply labels (`p0`/`p1`/`p2` + topic). After creating, paste each issue
number into its packet's `Tracking issue/PR` line.

## Human actions required

1. Create the `main` ruleset per the spec above; verify with a test PR.
2. Create the labels per the spec above (skip `documentation` — exists).
3. Create the nine tracking issues per the titles above; link numbers back
   into each packet.
4. Confirm private vulnerability reporting is enabled for the repo and that
   `SECURITY.md` renders (no private contact email was invented — the path
   is GitHub private advisories).

