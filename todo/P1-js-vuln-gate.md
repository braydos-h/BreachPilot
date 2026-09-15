# P1/P2 No explicit JS vulnerability gate

## Problem
Python dependencies are covered by pip-audit, but there is no stated equivalent vulnerability gate for WebUI build dependencies. Audit Secs 25 and 33 flag this asymmetry at HEAD 995759f (version 0.68.4, reliability-focused 0.69 beta). A vulnerable JS dependency could therefore reach the build without a defined check stopping it.

## Why it matters
Without parity with the Python gate, the release gate cannot claim full dependency coverage. WebUI build dependencies ship to every operator running the bundled UI, so an uncaught known-vulnerable package widens exposure silently.

## Recommended action
Add an npm/OSV scan to CI and the release gate, matching the existing pip-audit posture for Python dependencies.

## Acceptance criteria
- [ ] JS dependencies are scanned for known vulnerabilities via npm audit or OSV on every CI run
- [ ] High or critical findings fail the check or block the release gate
- [ ] Scan results are visible in CI output for triage
- [ ] Python pip-audit coverage remains unchanged and passing
- [ ] Release gate treats a missing or skipped JS scan as a failure, not a pass

## Audit ref
Secs 25, 33 + commit 995759f
