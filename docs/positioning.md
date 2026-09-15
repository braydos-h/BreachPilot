# Positioning — auditable, evidence-driven security testing

BreachPilot is a **local-first platform that executes inside explicit scope,
independently verifies findings, and produces auditable evidence** (§55).
Differentiation is auditability, not "most agents/tools" (§38, §46).

## What we claim

- **Scope first:** target-IP allowlist + mission scope gate deny off-scope work with auditable rows.
- **Containment:** disposable Docker worker with default-DROP egress; fail-closed `SANDBOX_*` blocks.
- **Verification:** stored probes re-executed (`VERIFIED`/`HOLDING`/`INCONCLUSIVE`); execution success and evidential success tracked separately.
- **Provenance:** 16-field `RunProvenance` on every eval/benchmark artifact; reproducible runs.
- **Operator graph:** WebUI console with attack graph, evidence, and approvals — not chat logs.

## What we do not claim

- No tool/skill/agent-count headlines above the fold. Counts live in the generated appendix (`docs/generated/capability-counts.json`) and are never the lead.
- No unverifiable superlatives vs competitors (Strix multi-agent + PoC validation + XBEN; CAI broad framework). We link eval artifacts when published; until the repeated baseline lands (TODO 001) we state "baseline in progress — methodology here" (honest, §31).
- No softened trust boundary: `full_access` + throwaway-box honesty stays (§9).

## Metrics that matter

Verified finding rate, FP rate, reproducibility, scope violations (=0),
time-to-verified, containment guarantees — from `docs/reliability-metrics.md`
and `docs/benchmarks.md` once TODO 001/017 numbers exist.

## Links

- Methodology: `docs/evaluation.md`, `docs/reliability-metrics.md`
- Baseline: `docs/benchmarks.md` (repeated trials + XBEN with CI/FP/cost/provenance)
- Safety: `docs/safety-model.md`, `docs/sandbox.md`
