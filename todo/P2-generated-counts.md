# P2 Generated metrics/counts duplicated manually

## Problem
Capability and version counts are manually duplicated across docs instead of being computed from a single source. Audit Secs 31, 33 flags this duplication as drift-prone. When tools, skills, or versions change, the scattered manual copies fall out of sync.

## Why it matters
Tool/skill count drift across docs misleads operators and reviewers about actual capabilities. Manual syncing adds recurring maintenance burden and erodes trust in documentation accuracy.

## Recommended action
Generate all capability/version counts from manifests so every rendered count reflects the current manifest state.

## Acceptance criteria
- [ ] No manually maintained capability/version counts remain in docs
- [ ] All rendered counts are generated from manifests at build or render time
- [ ] Adding or removing a tool/skill updates every rendered count without extra doc edits
- [ ] A check fails if a hardcoded count is reintroduced
- [ ] Rendered docs show consistent counts across all locations

## Audit ref
Secs 31, 33 + commit 995759f
