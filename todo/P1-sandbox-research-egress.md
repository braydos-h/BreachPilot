# P1 Sandbox permits GitHub/GitLab research egress by default

## Problem
The sandbox firewall allows GitHub/GitLab research egress by default, so the worker is not restricted to target-only traffic out of the box. Audit Secs 7 and 33 flag this default as overly permissive for an attack worker. Research fetching and attack execution therefore share the same egress surface.

## Why it matters
Target-only wording is inaccurate while research hosts are reachable by default. Shared research plus attack egress widens exfiltration and misuse surface and undermines sandbox containment claims.

## Recommended action
Split research vs attack worker or default allow_research_hosts off, per audit recommendation.

## Acceptance criteria
- [ ] Default sandbox egress denies GitHub/GitLab research hosts unless explicitly enabled
- [ ] Operator-facing wording no longer claims target-only egress when research egress is enabled
- [ ] Research fetching and attack execution do not share the same default egress allowance
- [ ] Existing target-only traffic continues to work with research egress disabled
- [ ] Regression test covers default-deny research egress behavior

## Audit ref
Secs 7, 33 + commit 995759f
