# P1 Audit chain covers policy records, not every MCP audit row

## Problem
The tamper-evident audit chain currently covers policy-layer records but not every MCP audit row emitted during a run. Audit sections 6 and 33 found MCP tool executions that produce audit rows outside the chained writer, so the chain cannot prove completeness of what actually ran. An operator verifying the chain sees a valid sequence that is missing events.

## Why it matters
The "tamper-evident audit" guarantee is incomplete while chained coverage is partial. Missing or unchained rows can be altered or dropped without breaking verification, which defeats forensic reconstruction and post-run review of authorized testing.

## Recommended action
Route all audit writes through one canonical chained event writer so every MCP audit row is hash-chained in order, and introduce a single AUDIT_INTEGRITY_FAILED state that the system enters when chain verification fails.

## Acceptance criteria
- [ ] Every MCP audit row is written through the canonical chained event writer with no unchained write path
- [ ] Chain verification replays all MCP audit rows in order and detects any missing, reordered, or modified row
- [ ] A failed verification transitions the run to AUDIT_INTEGRITY_FAILED and blocks further tool execution
- [ ] Existing valid chains still verify after the change with no format break for compliant readers
- [ ] Regression test covers chained MCP rows plus the integrity-failed transition on tamper

## Audit ref
Secs 6, 33 + commit 995759f
