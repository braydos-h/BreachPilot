# Branch Protection: `main` Ruleset + Green-Main Policy

Spec: `ruleset-main.json` (this directory). Todo: `todo/12-governance-branch-protection-rulesets.md`.
Status: **spec authored, not yet applied** — the `rulesets` endpoint still
returns an empty set. Applying requires repo admin
(Settings > Rules > Rulesets, or `scripts/apply-ruleset-main.sh`).

## 1. Required checks (sourced from `.github/workflows/ci.yml`)

The ruleset requires these four check runs on every `main` push/PR
(`integration_id: 15342` = GitHub Actions). Names must match the job
`name:` fields exactly — renaming a job below breaks the ruleset.

| Required context | Workflow | What it transitively covers |
|---|---|---|
| `CI success` | `CI` (`.github/workflows/ci.yml:528`, aggregate gate) | All of: `tests` (Python 3.11/3.12/3.13 × shard 1/2, `ci.yml:16`), `sandbox` (Docker worker, `ci.yml:55`), `browser` (Playwright + Chromium, `ci.yml:93`), `coverage` (`fail-under=80`, `ci.yml:137`), `lint` (ruff + guards, `ci.yml:169`), `types` (mypy, `ci.yml:297`), `package` (build + twine + wheel smoke, `ci.yml:348`), `webui` (tsc + vite + vitest, `ci.yml:439`), `audit` (pip-audit + npm audit + pins sync, `ci.yml:460`) |
| `Analyze (python)` | `CodeQL` (`.github/workflows/codeql.yml`, matrix `language: python`) | CodeQL Python analysis |
| `Analyze (javascript)` | `CodeQL` (matrix `language: javascript`) | CodeQL JS/TS analysis (WebUI) |
| `dependency-review` | `Dependency Review` (`.github/workflows/dependency-review.yml`, PR-only) | Fails PRs introducing vulnerable dependencies |

`strict_required_status_checks_policy: true` = the PR branch must be up to
date with `main` before merge (no stale-green merges).

## 2. Review + push rules

- **1 approving review** required; stale reviews dismissed on push;
  unresolved threads block merge (`required_review_thread_resolution`).
- **No bypass actors** (`bypass_actors: []`) — admins included. Emergency
  pushes to `main` are reserved for restoring a broken PR flow itself (see
  `CONTRIBUTING.md` §11b) and must be followed by a re-verifying PR + note.
- **Force-push blocked** (`non_fast_forward`) and **deletion blocked**
  (`deletion`). History on `main` is append-only; changes land via
  squash-merge.
- Solo-maintainer note: GitHub does not count the author's own approval, so
  `required_approving_review_count: 1` needs a second reviewer to merge.
  Until one exists, either set the count to `0` at apply time (the §10
  checklist evidence posted on the PR **is** the review — see
  `CONTRIBUTING.md` §11b) or add a collaborator. Do not weaken the status
  checks to compensate.

## 3. Merge process

1. Branch from `main` → focused change → push → open PR against `main`.
2. Fill in the `CONTRIBUTING.md` §10 checklist with evidence (focused test
   output, `ruff`, `mypy`, debt gate, rollback notes).
3. Wait for all four required checks green + review approval.
4. **Squash-merge** → delete the branch. Never force-push `main`.

## 4. Green-main release blocker

No release (tag, prerelease, or published artifact) goes out while `main`
is red:

- The hardened-release acceptance gates in `docs/release-checklist.md`
  (mocked suite slices, ruff, mypy, coverage ≥ 80, docs truth, version
  truth) plus `python scripts/release_gate.py` printing `GO` must all pass
  on the release commit.
- `SECURITY.md` records the same blocker on the disclosure side: security
  fixes land on a green `main` so the advisory trail is verifiable.

## 5. Feature-freeze-until-green policy

While `main` is red (any required check failing on the `main` branch):

1. **No feature PRs merge** — reviews and new work pause except red-fixing
   PRs, which jump the queue.
2. Fix-forward on a branch + PR like any other change (no direct pushes
   unless the PR flow itself is broken — §11b emergency path).
3. If red for reasons outside the tree (e.g. upstream action outage),
   document it on the tracking issue; the freeze still holds until the
   branch is green again — a red baseline makes every later bisect a lie.

## 6. Apply + verify (admin)

```bash
# Inspect current state (read-only, empty set = unprotected):
gh api repos/braydos-h/BreachPilot/rulesets

# Apply the spec (admin token required):
./scripts/apply-ruleset-main.sh
# ...or import docs/governance/ruleset-main.json via
# Settings > Rules > Rulesets > New ruleset > Import a ruleset.
```

Expected after apply: non-empty ruleset list with the four required
status checks, the pull-request rule, and no bypass actors. Re-run the
`gh api` verify and record the ruleset ID here.
