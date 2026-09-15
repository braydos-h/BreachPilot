# Branch protection — `main` ruleset (#41)

Status: in-repo contract defined here; **application requires a repo admin**
and is tracked as EXTERNAL in `scripts/release_gate.py` until applied.

## Required ruleset for `main`

- No force pushes; no deletion.
- PR required before merging (required human approvals: 0 is acceptable solo —
  the rule that matters is *code doesn't land without automated verification*).
- Required status checks (must all be green):
  - `CI success` (the `ci` aggregator: tests, sandbox, browser, coverage,
    lint, types, package, webui, audit)
  - `Eval unit tests` (`eval-unit`)
  - CodeQL (`codeql`)
  - Dependency review (`dependency-review`)
- Dismiss stale approvals on new pushes (when approvals are required).

## Apply (maintainer, one time)

```bash
# Replace OWNER/REPO. Requires admin.
gh api repos/OWNER/REPO/rulesets -X POST -f - <<'JSON'
{
  "name": "main-protected",
  "enforcement": "active",
  "target": "branch",
  "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
  "rules": [
    {"type": "deletion"},
    {"type": "non_fast_forward"},
    {"type": "required_status_checks",
     "parameters": {"required_status_checks": [
       {"context": "CI success"},
       {"context": "Eval unit tests (mocked, no API key)"}
     ], "strict": true}},
    {"type": "pull_request", "parameters": {"required_approving_review_count": 0,
      "dismiss_stale_reviews_on_push": true, "require_code_owner_review": false}}
  ]
}
JSON
```

Verify: `gh api repos/OWNER/REPO/rulesets --jq '.[].name'`, then confirm the
release gate box `branch-rules-applied` flips from EXTERNAL to satisfied and
record the ruleset ID + date in `todo/04-runtime-governance-and-ci/41-*.md`.

## Satisfying the release gate (admin)

```bash
gh api repos/OWNER/REPO/rulesets > branch-rules.json
python scripts/release_gate.py --branch-rules-file branch-rules.json
```

The gate passes `branch-rules-applied` when the JSON names `main`, shows
active enforcement, and requires CI checks. Commit the file as a release
artifact (or pass it between `release.yml` jobs); missing file stays
EXTERNAL, malformed file FAILs. See `docs/release.md` for the full
artifact table.
