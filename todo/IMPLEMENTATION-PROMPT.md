# BreachPilot complete-backlog implementation prompt

## Goal

Build and verify all 80 tasks in `todo/README.md` and its 30/60/90-day roadmap.
Deliver a measurably reliable, contained, evidence-led BreachPilot release. Continue
until each task is verified complete or genuinely blocked by external input.

## Operating instructions

Start by reading `AGENTS.md`, all of `CLAUDE.md`, `todo/README.md`,
`todo/ROADMAP.md`, `todo/GUARDRAILS.md`, and the task file being worked. Treat
`config.yaml` and repository source as current truth; the audit is a point-in-time
backlog that must be revalidated before implementation.

Work in dependency order and small reviewable slices:

1. Finish P0 reliability and release gates: live autonomous evaluation, protected
   `main`, canonical finding/evidence/retest lifecycle, semantic config/docs truth,
   sandbox/native-execution posture, exploit-runner decomposition, and the 0.69
   release contract.
2. Complete the 30-day foundations: typed boundaries, declarative tools, observation
   schemas, CI pyramid, injection corpus, and workflow tests.
3. Complete the 60-day assessment workflow, authenticated testing, imports,
   authorization comparison, evidence, coverage, retesting, and report diffing.
4. Complete the 90-day source-assisted testing, integrations, and public benchmarks.
5. Finish remaining P1/P2 work. Keep explicitly deferred work deferred until its
   prerequisites are proven; do not add unrelated tools, agents, providers, attack
   families, hosted/team features, or self-modification.

## Non-negotiable constraints

- Work in modern Flow A. Touch frozen Flow B safety files only during an explicitly
  planned, parity-tested retirement or migration.
- The target allowlist is the attack-mode lock. Never weaken or bypass it.
- All agent-generated attack execution must use the disposable sandbox. Never add
  host execution or a native fallback; sandbox failure must fail closed.
- The LLM may propose hypotheses and actions, but cannot define authorization,
  verified facts, or finding truth. Only independent deterministic/oracle checks may
  promote a finding to `VERIFIED`.
- Treat target, web, repository, tool, MCP, model, and memory content as untrusted.
  Secrets must use scoped opaque references and must not enter prompts or logs.
- Preserve user changes. Document every public flag, tool, schema, endpoint, or key.

## Execution and verification loop

For each task: assign an owner; revalidate the audit claim; write acceptance criteria;
identify dependencies and affected contracts; implement the smallest safe slice; add
focused unit, property, integration, UI, security, or autonomous evaluation coverage;
run only permitted test slices (`-n 0` or `-n 2`, never bare `pytest tests/`); run
relevant lint, type, frontend, build, and docs checks; record commands, results,
commits, benchmark deltas, and follow-ups in the task file. Update its status
and the checkbox in `todo/README.md` in the same change.

Do not claim completion from mocked tests alone when live autonomous behaviour is the
requirement. Evaluation must distinguish `PASS`, `FAIL`, `SKIPPED`, and `INFRA_ERROR`;
missing infrastructure must never appear green. Use negative controls, repeated trials,
scope/safety regressions, target-state damage checks, exact model/prompt/catalog hashes,
and pinned sandbox image digests. Compare verified-compromise, false-compromise, loops,
duplicate actions, failures, cost, time, and stop quality against the baseline.

At each milestone, leave the repository reviewable and CI-ready. The final result must
have every non-deferred checkbox complete, all required checks green, documentation and
runtime semantics aligned, release artifacts reproducible and signed, and remaining
blocked/deferred work explicitly justified with evidence and prerequisites.

## Exact implementation order

Follow this order unless current code evidence reveals a dependency that requires two
adjacent tasks to swap. If that happens, record the reason in both task files. A wave is
complete only when its code, tests, evaluation coverage, documentation, migrations,
rollback path, and task records are complete.

### Wave 0 — Establish measurable truth

1. **#45** — preserve and document the current testing baseline.
2. **#02** — make live autonomous evaluation real and release-blocking.
3. **#01** — replace tool-count claims with verified reliability metrics.
4. **#46** — implement the CI pyramid.
5. **#08** — generate semantic config assertions and remove docs/config drift.
6. **#36** — benchmark correct stopping behavior.
7. **#37** — add impossible cases and secure negative controls.
8. **#38** — benchmark supported model providers using comparable repeated trials.

Do not continue on architectural assumptions until evaluation distinguishes `PASS`,
`FAIL`, `SKIPPED`, and `INFRA_ERROR`, records reproducibility metadata, and prevents
missing live infrastructure from appearing green.

### Wave 1 — Safety, governance, supply chain, and the release gate

1. **#07** — remove native execution from normal product UX.
2. **#47** — add property-based scope and target-normalization tests.
3. **#48** — implement the explicit safety red-team suite.
4. **#49** — measure unexpected target-side damage in lab runs.
5. **#41** — require protected-branch CI/security/evaluation checks.
6. **#43** — generate and scan Python, npm, OS, sandbox, and browser SBOMs.
7. **#42** — produce signed release artifacts and provenance.
8. **#44** — pin release and evaluation containers by digest.
9. **#55** — create the signed, digest-pinned prebuilt sandbox-image workflow.
10. **#80** — encode the 0.69 beta contract as an enforceable release gate.

If #41, #42, #55, #79, or another task requires repository-admin credentials or an
external service unavailable to the agent, complete every in-repo workflow and config
change, write the exact remaining external steps, mark only that external part
`BLOCKED`, and continue. Do not pretend that a proposed setting has been applied.

### Wave 2 — Typed runtime contracts and one canonical orchestrator

1. **#69** — introduce the canonical observation schema.
2. **#70** — separate facts, inferences, hypotheses, claims, and verified facts.
3. **#11** — type the security-critical domain objects and boundaries.
4. **#12** — introduce declarative, versioned tool/capability manifests.
5. **#17** — document and test MCP protocol compatibility.
6. **#40** — make agent messages typed data; keep authorization external.
7. **#33** — implement durable action states, checkpointing, and safe resume.
8. **#34** — enforce time, cost, token, request, action, retry, browser, and asset
   budgets.
9. **#35** — add information gain and measurable action utility to planning.
10. **#39** — simplify multi-agent use and preserve verifier independence.
11. **#09** — incrementally decompose the giant exploit runner behind golden and live
    traces.
12. **#10** — retire Flow B only after measured parity and migration coverage.

For #09, extract typed components in reviewable steps; do not replace the loop in one
large rewrite. For #10, retire callers and migration dependencies without editing the
frozen Flow B safety implementation. Deleting files protected by current `AGENTS.md`
requires explicit maintainer approval and an intentional instruction update.

### Wave 3 — Agent security, skills, memory, credentials, and retention

1. **#15** — add trust-labelled context and independent tool policy.
2. **#16** — build prompt/content/tool/MCP/memory injection regression corpora.
3. **#13** — version skills and record provenance and evaluation history.
4. **#14** — add repeatable skill A/B tests and objective-aware routing.
5. **#72** — distinguish persistent experience from verified truth.
6. **#73** — include memory provenance, age, support, and confidence in prompts.
7. **#74** — use opaque secret references resolved only by authorized executors.
8. **#75** — scope credentials by target, role, protocol, tool, and visibility.
9. **#76** — add run-level retention policies and verifiable purge behavior.
10. **#77** — preserve the safe local API and design any remote operation as a
    separate hardened deployment profile.

This wave is complete only when untrusted content cannot grant authority, experience
cannot silently become truth, and raw credentials cannot leak through model, audit,
report, peer-agent, or artifact surfaces.

### Wave 4 — Findings, evidence, retest, regression, and reports

1. **#04** — make the canonical finding/evidence/retest lifecycle the central model.
2. **#28** — capture complete evidence with stable identifiers.
3. **#29** — make evidence content-addressed and immutable.
4. **#27** — deduplicate and cluster finding manifestations by root cause.
5. **#71** — measure and calibrate finding confidence against verifier outcomes.
6. **#30** — export reproducible finding bundles.
7. **#66** — reduce autonomous traces to deterministic minimal reproductions.
8. **#05** — generate and execute safe vulnerability regression tests.
9. **#67** — generate Nuclei templates only from verified findings and test them
   against vulnerable and fixed controls.
10. **#60** — record explicit assessment gaps.
11. **#61** — calculate honest tested-surface coverage.
12. **#62** — generate executive and technical reports plus durable JSON and SARIF.
13. **#63** — diff findings, retest states, and coverage between assessments.

An LLM may propose or explain a finding, but only an independent oracle/verifier may
promote it to `VERIFIED`. Preserve that invariant in storage, APIs, UI, reports, and
integrations.

### Wave 5 — Authenticated web/API testing and integrations

1. **#23** — add secure session acquisition and multi-identity credential profiles.
2. **#24** — import OpenAPI, Postman, HAR, and Burp data into an operation graph.
3. **#25** — implement independently verified differential authorization testing.
4. **#26** — use source context to form hypotheses and prove them dynamically.
5. **#68** — normalize mature scanner output through adapters into observations.
6. **#32** — stabilize the versioned public API, errors, pagination, idempotency,
   webhooks, and deprecation policy.
7. **#31** — connect verified finding/retest states to remediation integrations.
8. **#65** — add preview-environment Git/CI assessment integration that fails only
   on new, independently verified findings at the configured severity.

### Wave 6 — Assessment-centered WebUI

1. **#50** — decompose oversized routes into tested feature slices.
2. **#18** — reorganize navigation around assessments, assets, findings,
   regressions, integrations, benchmarks, and system state.
3. **#19** — build the target/context/scope/profile/safety/launch wizard.
4. **#20** — expose Recon, Guided, and Autonomous modes with effect-based approvals.
5. **#21** — render the structured plan and branch state.
6. **#22** — show reason codes, evidence, alternatives, risk, and information gain
   without exposing private chain-of-thought.
7. **#52** — expose doctor/readiness checks with actionable fixes.
8. **#53** — standardize stable remediation codes across backend and UI.
9. **#51** — add Playwright journeys for complete workflows and failure modes.

The finished interface must let a new operator configure, preview, launch,
understand, verify, report, and retest an assessment without needing to understand
the repository's internal module layout.

### Wave 7 — Product evidence, installation, ecosystem, and later features

1. **#06** — attach containment identity, policy hashes, and image digest to runs.
2. **#03** — generate the capability matrix from benchmark truth.
3. **#58** — generate a public benchmark dashboard from immutable evaluation data.
4. **#59** — add independent benchmark corpora where licensing permits.
5. **#54** — provide Core, Web, Network, and Full installation profiles.
6. **#56** — narrow product positioning around contained, verified, reproducible,
   local-first autonomous testing.
7. **#57** — rewrite the README first screen using measured claims only.
8. **#79** — correct repository metadata and prepare appropriate community settings.
9. **#64** — add scheduling only after reliability, checkpointing, and
   reproducibility gates are green.
10. **#78** — build team/RBAC/remote-worker support last, with a real remote
    deployment security model.

Tasks #64 and #78 are intentionally last, not permanently ignored. Do not start them
until their prerequisites are demonstrated by the earlier waves.

## Required final verification

After the last implementation wave:

1. Re-read all 80 numbered task files. Every task must have a truthful `DONE` or
   `BLOCKED` state, owner, dates, affected design/issue, commits or changes, exact
   test/evaluation evidence, documentation record, and follow-ups.
2. Synchronize all 80 checkboxes in `todo/README.md`. Resolve stale `IN PROGRESS`
   states, broken local links, unchecked acceptance criteria, generated-file drift,
   and documentation/config/API contradictions.
3. Run the smallest relevant regression tests throughout the work. At the end run,
   in order and when supported by the environment:
   - focused Python test files for every changed subsystem;
   - WebUI unit tests, production build, and Playwright workflow tests;
   - `ruff check .`;
   - `ruff format --check .`;
   - `mypy --follow-imports=skip tools`;
   - package build/install checks through the supported Python CI matrix;
   - `bp --doctor` and `bp --self-test`;
   - sandbox and browser image build/smoke checks;
   - the safety red-team suite;
   - hermetic autonomous benchmarks with negative controls;
   - repeated release evaluation against the stored baseline.
4. Never run bare `pytest tests/` locally. Use one file at a time, no more than about
   30 files in a planned slice, `-n 0` or at most `-n 2`, no concurrent pytest suites,
   and do not override the configured test-marker policy. Full-suite verification is
   CI's responsibility.
5. Inspect full CI when access exists. Do not describe targeted local tests as a
   complete suite, and do not describe `SKIPPED` or `INFRA_ERROR` evaluation as green.
6. Verify generated config, CLI, MCP tool, capability, and API references against the
   candidate code. Verify SBOMs, container digests, signatures, and provenance refer
   to the exact candidate artifacts.
7. Confirm that unauthorized packets reaching the network layer remain zero, native
   fallback is impossible in normal operation, false-compromise and stuck-loop rates
   are recorded, and every reported verified finding has oracle-backed evidence.
8. Create `todo/COMPLETION-REPORT.md` with:
   - work completed in each wave;
   - tasks already satisfied before this effort and the evidence proving it;
   - exact tests, builds, CI runs, safety results, and benchmark deltas;
   - schema/config migrations and rollback instructions;
   - public contract and documentation changes;
   - external actions performed;
   - external actions still required, with exact commands or settings;
   - residual risks and justified blockers;
   - a final `GO` or `NO-GO` recommendation against task #80.
9. Finish with a concise handoff describing the release candidate and anything the
   maintainer must still do. Do not claim completion while a task lacks evidence, a
   required gate was skipped, or an external blocker remains.

The required final product is a verified release candidate and an honest completion
report, not merely a large code diff.
