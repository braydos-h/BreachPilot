#!/usr/bin/env bash
# Apply docs/governance/ruleset-main.json to the GitHub repo via the
# repository rulesets API. Requires a token with repo admin scope.
# Read-only inspection works with any read access:
#   gh api repos/braydos-h/BreachPilot/rulesets
set -euo pipefail

OWNER="${OWNER:-braydos-h}"
REPO="${REPO:-BreachPilot}"
SPEC="${SPEC:-docs/governance/ruleset-main.json}"

if ! command -v gh >/dev/null 2>&1; then
  echo "ERROR: gh CLI not found (https://cli.github.com)." >&2
  exit 1
fi
if [ ! -f "$SPEC" ]; then
  echo "ERROR: spec file not found: $SPEC (run from repo root)." >&2
  exit 1
fi

echo "== current rulesets (empty set = unprotected main) =="
gh api "repos/${OWNER}/${REPO}/rulesets"

echo "== applying ${SPEC} =="
# POST creates; if a ruleset named main-protection already exists, PUT-update it.
EXISTING_ID="$(gh api "repos/${OWNER}/${REPO}/rulesets" --jq '.[] | select(.name=="main-protection") | .id' || true)"
if [ -n "${EXISTING_ID:-}" ]; then
  echo "ruleset 'main-protection' exists (id=${EXISTING_ID}); updating via PUT."
  gh api -X PUT "repos/${OWNER}/${REPO}/rulesets/${EXISTING_ID}" --input "$SPEC"
else
  gh api -X POST "repos/${OWNER}/${REPO}/rulesets" --input "$SPEC"
fi

echo "== verify =="
gh api "repos/${OWNER}/${REPO}/rulesets" --jq '.[] | {id, name, enforcement, target}'
echo "OK: ruleset applied. Confirm the 4 required status checks + PR rule in the UI: Settings > Rules > Rulesets."
