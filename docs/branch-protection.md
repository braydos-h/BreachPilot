# Branch protection — `main`

The canonical ruleset is [`docs/governance/ruleset-main.json`](governance/ruleset-main.json).
Its application is external and requires repository-admin access; until the
GitHub API reports the full active ruleset, `scripts/release_gate.py` keeps
`branch-rules-applied` as `EXTERNAL` or fails on an insufficient ruleset.

The release gate checks the actual ruleset against that contract: exact
`refs/heads/main` scope, active enforcement, no bypass actors, deletion and
force-push protection, the required pull-request review rules, strict required
status checks, and the four documented GitHub Actions contexts. The spec is
the source of truth for the required review and check values.

## Apply and verify

From the repository root, a maintainer with admin access can apply the spec:

```bash
./scripts/apply-ruleset-main.sh
```

Then verify the API response and feed it to the release gate:

```bash
gh api repos/braydos-h/BreachPilot/rulesets > branch-rules.json
python scripts/release_gate.py --branch-rules-file branch-rules.json
```

The gate accepts only a ruleset satisfying the full checked-in contract. A
ruleset requiring `CI success` alone is insufficient. See
[`docs/governance/branch-protection.md`](governance/branch-protection.md) for
the required contexts and merge policy.
