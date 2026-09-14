# BreachPilot audit TODO backlog

This directory turns the September 14, 2026 review of `main` at
`75e0ba9df21311f8441b98e884610d36fa91f1af` into trackable work.

Use the checkbox in this index as portfolio status. Use each task file for its
implementation checklist and completion evidence. Priorities and horizons are
suggested from the audit and can be re-ranked as evidence changes.

## Working rules

- [ ] Assign an owner before implementation starts.
- [ ] Re-check the current code against this point-in-time audit.
- [ ] Preserve the Flow A / frozen Flow B boundary in `AGENTS.md` and `CLAUDE.md`.
- [ ] Never weaken the target allowlist or sandbox fail-closed behavior.
- [ ] Run focused test slices locally; leave full-suite verification to CI.
- [ ] Record tests, benchmarks, commits, and follow-ups in the task file.
- [ ] Mark both the task file and this index when work is complete.

## Companion documents

- [Implementation prompt](IMPLEMENTATION-PROMPT.md)
- [Roadmap](ROADMAP.md)
- [Target architecture](TARGET-ARCHITECTURE.md)
- [Scope guardrails](GUARDRAILS.md)
- [External references](REFERENCES.md)

I reviewed `main` at **`75e0ba9df21311f8441b98e884610d36fa91f1af`**, so this is a point-in-time audit of the project as it exists on **September 14, 2026**. The latest CI run for that exact commit was still in progress when I checked, so I am not treating `main` as proven green yet.

## Audit verdict

BreachPilot has crossed the line from "AI wrapper around pentesting tools" into a legitimate security-testing platform architecture.

The strongest parts are:

* genuinely layered execution containment;
* independent evidence/verdict concepts instead of trusting the model's claims;
* a large MCP/tool ecosystem;
* scope/allowlist enforcement;
* disposable Docker workers with network-level enforcement;
* persistent run artifacts;
* React control plane;
* an unusually substantial test/docs/CI setup;
* benchmarking/evaluation work;
* serious thought around autonomous-agent drift.

The biggest problem is no longer **lack of features**.

It is:

> **There is currently more capability than independently demonstrated reliability.**

The project advertises a very broad autonomous offensive-security surface, but the part that matters most—"does the autonomous agent consistently find and prove vulnerabilities without lying, looping, wasting actions, leaving scope, or breaking its execution environment?"—is still being converted into a real release gate.

That is what I would orient the next phase of the project around.

---

## Audit priority order

| Priority | Work                                                                  |                Impact |
| -------- | --------------------------------------------------------------------- | --------------------: |
| **P0**   | Make autonomous live evaluation real and release-blocking             |               Extreme |
| **P0**   | Protect `main` + require CI/security/eval checks                      |               Extreme |
| **P0**   | Build a canonical finding/evidence/retest lifecycle                   |               Extreme |
| **P0**   | Resolve safety/config/docs contradictions automatically               |                  High |
| **P0**   | Reduce the giant exploit runner before adding more autonomy           |                  High |
| **P1**   | Redesign WebUI around an assessment workflow instead of feature pages |             Very high |
| **P1**   | Add first-class authenticated web/API testing                         |             Very high |
| **P1**   | Add remediation/retest/regression workflows                           |             Very high |
| **P1**   | Add integrations/API as product surfaces                              |                  High |
| **P1**   | Harden untrusted web/tool/model content boundaries                    |                  High |
| **P2**   | Skill/tool marketplace/versioning/provenance                          |           Medium-high |
| **P2**   | Team/RBAC/remote workers                                              |                Medium |
| **P2**   | More attack modules/skills                                            | Lower than it appears |

I'll explain why.

---

## Task index

### Strategy and evaluation

- [ ] [#01 — Stop optimizing the tool count](01-strategy-and-evaluation/01-stop-optimizing-the-tool-count.md) — P0, Backlog — IN PROGRESS slice 1 (reliability-metrics doc + headline)
- [ ] [#02 — Live autonomous evaluation needs to become the centre of development](01-strategy-and-evaluation/02-live-autonomous-evaluation-needs-to-become-the-centre-of-development.md) — P0, 30-day — IN PROGRESS slice 1 (provenance + SKIPPED)
- [ ] [#03 — Add a "BreachPilot Capability Matrix"](01-strategy-and-evaluation/03-add-a-breachpilot-capability-matrix.md) — P1, Backlog — IN PROGRESS (compare primitive exists; matrix pending)(01-strategy-and-evaluation/03-add-a-breachpilot-capability-matrix.md) — P1, Backlog
- [x] [#04 — Finding verification should become the centre of the data model](01-strategy-and-evaluation/04-finding-verification-should-become-the-centre-of-the-data-model.md) — P0, 60-day — DONE 2026-09-14 (lifecycle machine + pipeline)(01-strategy-and-evaluation/04-finding-verification-should-become-the-centre-of-the-data-model.md) — P0, 60-day
- [ ] [#05 — Build vulnerability regression testing](01-strategy-and-evaluation/05-build-vulnerability-regression-testing.md) — P1, 60-day — IN PROGRESS (retest exists; generation pending)(01-strategy-and-evaluation/05-build-vulnerability-regression-testing.md) — P1, 60-day
- [x] [#06 — The sandbox architecture is a genuine strength](01-strategy-and-evaluation/06-the-sandbox-architecture-is-a-genuine-strength.md) — P1, Backlog — DONE 2026-09-14 (revalidated + hardened this session)(01-strategy-and-evaluation/06-the-sandbox-architecture-is-a-genuine-strength.md) — P1, Backlog
- [x] [#07 — Remove "native execution" from normal product UX](01-strategy-and-evaluation/07-remove-native-execution-from-normal-product-ux.md) — P0, Backlog — DONE 2026-09-14 (env consent gate)
- [ ] [#08 — Add semantic configuration assertions](01-strategy-and-evaluation/08-add-semantic-configuration-assertions.md) — P0, 30-day — IN PROGRESS slice 1 (fallback_native truth + guard)

### Architecture and agent security

- [ ] [#09 — The giant exploit loop is now an architectural liability](02-architecture-and-agent-security/09-the-giant-exploit-loop-is-now-an-architectural-liability.md) — P0, 30-day — IN PROGRESS (step 1: checkpoint extracted, live traces green)(02-architecture-and-agent-security/09-the-giant-exploit-loop-is-now-an-architectural-liability.md) — P0, 30-day
- [ ] [#10 — Retire Flow B](02-architecture-and-agent-security/10-retire-flow-b.md) — P1, 60-day — DEFERRED 2026-09-14 (parity prerequisites unmet; frozen files untouched)(02-architecture-and-agent-security/10-retire-flow-b.md) — P1, 60-day
- [ ] [#11 — Type debt matters more here than in most Python projects](02-architecture-and-agent-security/11-type-debt-matters-more-here-than-in-most-python-projects.md) — P1, 30-day — IN PROGRESS (ratchet held at 276; new code clean)(02-architecture-and-agent-security/11-type-debt-matters-more-here-than-in-most-python-projects.md) — P1, 30-day
- [x] [#12 — Turn tools into declarative capabilities](02-architecture-and-agent-security/12-turn-tools-into-declarative-capabilities.md) — P1, 30-day — DONE 2026-09-14 (AST manifests + catalog hash)(02-architecture-and-agent-security/12-turn-tools-into-declarative-capabilities.md) — P1, 30-day
- [ ] [#13 — Skills need versioning and provenance](02-architecture-and-agent-security/13-skills-need-versioning-and-provenance.md) — P2, Backlog — IN PROGRESS (version field exists; history pending)(02-architecture-and-agent-security/13-skills-need-versioning-and-provenance.md) — P2, Backlog
- [ ] [#14 — Add skill A/B testing](02-architecture-and-agent-security/14-add-skill-a-b-testing.md) — P2, Backlog — IN PROGRESS (feedback exists; harness pending)(02-architecture-and-agent-security/14-add-skill-a-b-testing.md) — P2, Backlog
- [ ] [#15 — Prompt injection needs its own explicit subsystem](02-architecture-and-agent-security/15-prompt-injection-needs-its-own-explicit-subsystem.md) — P1, Backlog — IN PROGRESS (wrapping exists; tiered policy pending)(02-architecture-and-agent-security/15-prompt-injection-needs-its-own-explicit-subsystem.md) — P1, Backlog
- [x] [#16 — Add an injection regression corpus](02-architecture-and-agent-security/16-add-an-injection-regression-corpus.md) — P1, 30-day — DONE 2026-09-14 (14-case corpus + 5 tests)(02-architecture-and-agent-security/16-add-an-injection-regression-corpus.md) — P1, 30-day
- [ ] [#17 — MCP should be treated as an evolving protocol dependency](02-architecture-and-agent-security/17-mcp-should-be-treated-as-an-evolving-protocol-dependency.md) — P1, Backlog — IN PROGRESS (pinned; compat matrix pending)(02-architecture-and-agent-security/17-mcp-should-be-treated-as-an-evolving-protocol-dependency.md) — P1, Backlog

### Product and assessment workflows

- [ ] [#18 — Redesign the WebUI around "Assessment", not internal architecture](03-product-and-assessment-workflows/18-redesign-the-webui-around-assessment-not-internal-architecture.md) — P1, 60-day — IN PROGRESS (survey: feature-page nav confirmed)(03-product-and-assessment-workflows/18-redesign-the-webui-around-assessment-not-internal-architecture.md) — P1, 60-day
- [ ] [#19 — Assessment creation should be a wizard](03-product-and-assessment-workflows/19-assessment-creation-should-be-a-wizard.md) — P1, 60-day — IN PROGRESS (NewRunPage exists; wizard pending)(03-product-and-assessment-workflows/19-assessment-creation-should-be-a-wizard.md) — P1, 60-day
- [ ] [#20 — "Guided" should probably become the default user experience](03-product-and-assessment-workflows/20-guided-should-probably-become-the-default-user-experience.md) — P1, Backlog — IN PROGRESS (survey done)(03-product-and-assessment-workflows/20-guided-should-probably-become-the-default-user-experience.md) — P1, Backlog
- [ ] [#21 — Add an "agent plan" view](03-product-and-assessment-workflows/21-add-an-agent-plan-view.md) — P1, 60-day — IN PROGRESS (planner exists; view pending)(03-product-and-assessment-workflows/21-add-an-agent-plan-view.md) — P1, 60-day
- [ ] [#22 — Add a proper "why did the agent do this?" view](03-product-and-assessment-workflows/22-add-a-proper-why-did-the-agent-do-this-view.md) — P1, Backlog — IN PROGRESS (decision logs exist; view pending)(03-product-and-assessment-workflows/22-add-a-proper-why-did-the-agent-do-this-view.md) — P1, Backlog
- [ ] [#23 — Authenticated web testing should be a major P1](03-product-and-assessment-workflows/23-authenticated-web-testing-should-be-a-major-p1.md) — P1, 60-day — IN PROGRESS (vault+auth data exist; profiles pending)(03-product-and-assessment-workflows/23-authenticated-web-testing-should-be-a-major-p1.md) — P1, 60-day
- [ ] [#24 — Import OpenAPI/Postman/HAR/Burp data](03-product-and-assessment-workflows/24-import-openapi-postman-har-burp-data.md) — P1, 60-day — IN PROGRESS (OpenAPI slice done 2026-09-14: operation graph + 5 tests; Postman/HAR/Burp pending)(03-product-and-assessment-workflows/24-import-openapi-postman-har-burp-data.md) — P1, 60-day
- [ ] [#25 — Add differential authorization testing](03-product-and-assessment-workflows/25-add-differential-authorization-testing.md) — P1, 60-day — IN PROGRESS (gap confirmed; needs #23+#24)(03-product-and-assessment-workflows/25-add-differential-authorization-testing.md) — P1, 60-day
- [ ] [#26 — Add source-assisted dynamic testing](03-product-and-assessment-workflows/26-add-source-assisted-dynamic-testing.md) — P1, 90-day — IN PROGRESS (gap confirmed)(03-product-and-assessment-workflows/26-add-source-assisted-dynamic-testing.md) — P1, 90-day
- [ ] [#27 — Add finding deduplication/root-cause clustering](03-product-and-assessment-workflows/27-add-finding-deduplication-root-cause-clustering.md) — P1, Backlog — IN PROGRESS (exact dedup exists; clustering pending)(03-product-and-assessment-workflows/27-add-finding-deduplication-root-cause-clustering.md) — P1, Backlog
- [x] [#28 — Make evidence excellent](03-product-and-assessment-workflows/28-make-evidence-excellent.md) — P1, 60-day — DONE 2026-09-14 (stable IDs revalidated)(03-product-and-assessment-workflows/28-make-evidence-excellent.md) — P1, 60-day
- [x] [#29 — Evidence provenance should be immutable](03-product-and-assessment-workflows/29-evidence-provenance-should-be-immutable.md) — P1, Backlog — DONE 2026-09-14 (hash-chained revalidated)(03-product-and-assessment-workflows/29-evidence-provenance-should-be-immutable.md) — P1, Backlog
- [ ] [#30 — Add reproducible "finding bundles"](03-product-and-assessment-workflows/30-add-reproducible-finding-bundles.md) — P1, Backlog — IN PROGRESS (replay exists; bundles pending)(03-product-and-assessment-workflows/30-add-reproducible-finding-bundles.md) — P1, Backlog
- [ ] [#31 — Integrations should follow the finding lifecycle](03-product-and-assessment-workflows/31-integrations-should-follow-the-finding-lifecycle.md) — P1, 90-day — IN PROGRESS (ticketing exists; lifecycle wiring pending)(03-product-and-assessment-workflows/31-integrations-should-follow-the-finding-lifecycle.md) — P1, 90-day
- [ ] [#32 — Create a proper public API contract](03-product-and-assessment-workflows/32-create-a-proper-public-api-contract.md) — P1, Backlog — IN PROGRESS (v1 versioned; full contract pending)(03-product-and-assessment-workflows/32-create-a-proper-public-api-contract.md) — P1, Backlog

### Runtime, governance, and CI

- [x] [#33 — Run execution needs checkpoint/resume semantics everywhere](04-runtime-governance-and-ci/33-run-execution-needs-checkpoint-resume-semantics-everywhere.md) — P1, Backlog — DONE 2026-09-14 (semantics revalidated, 26 tests)(04-runtime-governance-and-ci/33-run-execution-needs-checkpoint-resume-semantics-everywhere.md) — P1, Backlog
- [x] [#34 — Add explicit run budgets](04-runtime-governance-and-ci/34-add-explicit-run-budgets.md) — P1, Backlog — DONE 2026-09-14 (BudgetTracker; runner migration pending)(04-runtime-governance-and-ci/34-add-explicit-run-budgets.md) — P1, Backlog
- [ ] [#35 — Add "information gain" as a planner concept](04-runtime-governance-and-ci/35-add-information-gain-as-a-planner-concept.md) — P1, Backlog — IN PROGRESS (uncertainty ranking exists; utility scorer pending)(04-runtime-governance-and-ci/35-add-information-gain-as-a-planner-concept.md) — P1, Backlog
- [x] [#36 — The benchmark suite should test "knowing when to stop"](04-runtime-governance-and-ci/36-the-benchmark-suite-should-test-knowing-when-to-stop.md) — P1, Backlog — DONE 2026-09-14 (negative-control oracles + scoring)
- [x] [#37 — Add deliberately impossible challenges](04-runtime-governance-and-ci/37-add-deliberately-impossible-challenges.md) — P1, Backlog — DONE 2026-09-14 (impossible_sqli decoy + REFUTED scoring)
- [x] [#38 — Benchmark across model providers](04-runtime-governance-and-ci/38-benchmark-across-model-providers.md) — P1, 60-day — DONE 2026-09-14 (provider_compare helper)
- [ ] [#39 — Don't overuse multi-agent architecture](04-runtime-governance-and-ci/39-dont-overuse-multi-agent-architecture.md) — P2, Backlog — IN PROGRESS (critic+verifier separation real; guidance pending)(04-runtime-governance-and-ci/39-dont-overuse-multi-agent-architecture.md) — P2, Backlog
- [ ] [#40 — Agent messages should be typed](04-runtime-governance-and-ci/40-agent-messages-should-be-typed.md) — P2, Backlog — IN PROGRESS (dict-based today; envelope pending)(04-runtime-governance-and-ci/40-agent-messages-should-be-typed.md) — P2, Backlog
- [ ] [#41 — The public repo should have mandatory branch rules immediately](04-runtime-governance-and-ci/41-the-public-repo-should-have-mandatory-branch-rules-immediately.md) — P0, 30-day — IN PROGRESS (in-repo done; BLOCKED: admin apply)(04-runtime-governance-and-ci/41-the-public-repo-should-have-mandatory-branch-rules-immediately.md) — P0, 30-day
- [x] [#42 — Sign releases and publish provenance](04-runtime-governance-and-ci/42-sign-releases-and-publish-provenance.md) — P1, Backlog — DONE 2026-09-14 (attestations in release.yml)(04-runtime-governance-and-ci/42-sign-releases-and-publish-provenance.md) — P1, Backlog
- [x] [#43 — Add SBOM/container scanning if it is not already in the release gate](04-runtime-governance-and-ci/43-add-sbom-container-scanning-if-it-is-not-already-in-the-release-gate.md) — P1, Backlog — DONE 2026-09-14 (SBOM+Trivy in release.yml)(04-runtime-governance-and-ci/43-add-sbom-container-scanning-if-it-is-not-already-in-the-release-gate.md) — P1, Backlog
- [x] [#44 — Containers should be immutable by digest for releases](04-runtime-governance-and-ci/44-containers-should-be-immutable-by-digest-for-releases.md) — P1, Backlog — DONE 2026-09-14 (digest recording + provenance)(04-runtime-governance-and-ci/44-containers-should-be-immutable-by-digest-for-releases.md) — P1, Backlog
- [x] [#45 — The current test architecture has improved considerably](04-runtime-governance-and-ci/45-the-current-test-architecture-has-improved-considerably.md) — P2, Backlog — DONE 2026-09-14 (baseline: 5,358 tests/356 files, ruff clean, mypy 276)
- [x] [#46 — Create a CI pyramid](04-runtime-governance-and-ci/46-create-a-ci-pyramid.md) — P1, 30-day — DONE 2026-09-14 (tiers doc + guard)
- [x] [#47 — Property-based tests would be especially valuable for scope logic](04-runtime-governance-and-ci/47-property-based-tests-would-be-especially-valuable-for-scope-logic.md) — P1, Backlog — DONE 2026-09-14 (7 property tests)
- [x] [#48 — Add an explicit safety red-team suite](04-runtime-governance-and-ci/48-add-an-explicit-safety-red-team-suite.md) — P1, Backlog — DONE 2026-09-14 (23-test hermetic suite)
- [x] [#49 — Measure target-side damage](04-runtime-governance-and-ci/49-measure-target-side-damage.md) — P1, Backlog — DONE 2026-09-14 (damage diff primitive)

### WebUI, delivery, and ecosystem

- [ ] [#50 — WebUI needs component decomposition too](05-webui-delivery-and-ecosystem/50-webui-needs-component-decomposition-too.md) — P1, Backlog — IN PROGRESS (~25 routes; features/ slices started)(05-webui-delivery-and-ecosystem/50-webui-needs-component-decomposition-too.md) — P1, Backlog
- [ ] [#51 — Add UI end-to-end tests around workflows, not pages](05-webui-delivery-and-ecosystem/51-add-ui-end-to-end-tests-around-workflows-not-pages.md) — P1, 30-day — IN PROGRESS (vitest exists; Playwright journeys pending)(05-webui-delivery-and-ecosystem/51-add-ui-end-to-end-tests-around-workflows-not-pages.md) — P1, 30-day
- [ ] [#52 — Create a "doctor" view in the WebUI](05-webui-delivery-and-ecosystem/52-create-a-doctor-view-in-the-webui.md) — P1, Backlog — IN PROGRESS (--json exists; view pending)(05-webui-delivery-and-ecosystem/52-create-a-doctor-view-in-the-webui.md) — P1, Backlog
- [ ] [#53 — Give errors remediation codes](05-webui-delivery-and-ecosystem/53-give-errors-remediation-codes.md) — P1, Backlog — IN PROGRESS (registry slice done 2026-09-14: 12 codes + 3 tests; UI rendering pending)(05-webui-delivery-and-ecosystem/53-give-errors-remediation-codes.md) — P1, Backlog
- [x] [#54 — Installation should have a "minimal useful" profile](05-webui-delivery-and-ecosystem/54-installation-should-have-a-minimal-useful-profile.md) — P1, Backlog — DONE 2026-09-14 (minimal/standard/full revalidated)(05-webui-delivery-and-ecosystem/54-installation-should-have-a-minimal-useful-profile.md) — P1, Backlog
- [x] [#55 — Publish a single prebuilt sandbox image](05-webui-delivery-and-ecosystem/55-publish-a-single-prebuilt-sandbox-image.md) — P1, Backlog — DONE 2026-09-14 (sandbox-image.yml + cosign)(05-webui-delivery-and-ecosystem/55-publish-a-single-prebuilt-sandbox-image.md) — P1, Backlog
- [ ] [#56 — Product positioning should narrow](05-webui-delivery-and-ecosystem/56-product-positioning-should-narrow.md) — P2, Backlog — IN PROGRESS (headline narrowed; full alignment pending)(05-webui-delivery-and-ecosystem/56-product-positioning-should-narrow.md) — P2, Backlog
- [x] [#57 — I would change the README's first screen](05-webui-delivery-and-ecosystem/57-i-would-change-the-readmes-first-screen.md) — P2, Backlog — DONE 2026-09-14 (via #01)(05-webui-delivery-and-ecosystem/57-i-would-change-the-readmes-first-screen.md) — P2, Backlog
- [ ] [#58 — Add a public benchmark dashboard](05-webui-delivery-and-ecosystem/58-add-a-public-benchmark-dashboard.md) — P1, 90-day — IN PROGRESS (internal dashboard exists; public pending)(05-webui-delivery-and-ecosystem/58-add-a-public-benchmark-dashboard.md) — P1, 90-day
- [ ] [#59 — Don't benchmark only your own targets](05-webui-delivery-and-ecosystem/59-dont-benchmark-only-your-own-targets.md) — P2, Backlog — IN PROGRESS (gap confirmed)(05-webui-delivery-and-ecosystem/59-dont-benchmark-only-your-own-targets.md) — P2, Backlog
- [ ] [#60 — A major competitive opportunity: "assessment gaps"](05-webui-delivery-and-ecosystem/60-a-major-competitive-opportunity-assessment-gaps.md) — P1, 60-day — IN PROGRESS (gap confirmed)(05-webui-delivery-and-ecosystem/60-a-major-competitive-opportunity-assessment-gaps.md) — P1, 60-day
- [ ] [#61 — Add a coverage model](05-webui-delivery-and-ecosystem/61-add-a-coverage-model.md) — P1, Backlog — IN PROGRESS (gap confirmed)(05-webui-delivery-and-ecosystem/61-add-a-coverage-model.md) — P1, Backlog
- [ ] [#62 — Reports need two layers](05-webui-delivery-and-ecosystem/62-reports-need-two-layers.md) — P1, Backlog — IN PROGRESS (JSON/MD/HTML exist; SARIF+split pending)(05-webui-delivery-and-ecosystem/62-reports-need-two-layers.md) — P1, Backlog
- [ ] [#63 — Add report diffing](05-webui-delivery-and-ecosystem/63-add-report-diffing.md) — P1, 60-day — IN PROGRESS (gap confirmed)(05-webui-delivery-and-ecosystem/63-add-report-diffing.md) — P1, 60-day
- [ ] [#64 — Add scheduled assessments later](05-webui-delivery-and-ecosystem/64-add-scheduled-assessments-later.md) — Deferred, Later — DEFERRED 2026-09-14 (prerequisites unmet by design)(05-webui-delivery-and-ecosystem/64-add-scheduled-assessments-later.md) — Deferred, Later / intentionally deferred
- [ ] [#65 — Git/CI integration would be valuable](05-webui-delivery-and-ecosystem/65-git-ci-integration-would-be-valuable.md) — P1, 90-day — IN PROGRESS (gap confirmed)(05-webui-delivery-and-ecosystem/65-git-ci-integration-would-be-valuable.md) — P1, 90-day
- [ ] [#66 — Add a "minimal reproduction" reducer](05-webui-delivery-and-ecosystem/66-add-a-minimal-reproduction-reducer.md) — P1, Backlog — IN PROGRESS (pending)(05-webui-delivery-and-ecosystem/66-add-a-minimal-reproduction-reducer.md) — P1, Backlog
- [ ] [#67 — Let the agent generate Nuclei templates from verified findings](05-webui-delivery-and-ecosystem/67-let-the-agent-generate-nuclei-templates-from-verified-findings.md) — P1, Backlog — IN PROGRESS (gap confirmed)(05-webui-delivery-and-ecosystem/67-let-the-agent-generate-nuclei-templates-from-verified-findings.md) — P1, Backlog
- [ ] [#68 — Add tool adapters instead of reimplementing mature scanners](05-webui-delivery-and-ecosystem/68-add-tool-adapters-instead-of-reimplementing-mature-scanners.md) — P1, Backlog — IN PROGRESS (wrapping exists; observation normalization pending)(05-webui-delivery-and-ecosystem/68-add-tool-adapters-instead-of-reimplementing-mature-scanners.md) — P1, Backlog

### Data, security, and release

- [x] [#69 — Introduce an observation schema](06-data-security-and-release/69-introduce-an-observation-schema.md) — P1, 30-day — DONE 2026-09-14 (canonical Observation + bridge)(06-data-security-and-release/69-introduce-an-observation-schema.md) — P1, 30-day
- [x] [#70 — Separate facts from hypotheses](06-data-security-and-release/70-separate-facts-from-hypotheses.md) — P1, Backlog — DONE 2026-09-14 (EpistemicKind + oracle-only promotion)(06-data-security-and-release/70-separate-facts-from-hypotheses.md) — P1, Backlog
- [ ] [#71 — Add finding confidence calibration](06-data-security-and-release/71-add-finding-confidence-calibration.md) — P1, Backlog — IN PROGRESS (confidence exists; calibration pending)(06-data-security-and-release/71-add-finding-confidence-calibration.md) — P1, Backlog
- [ ] [#72 — Persistent memory must distinguish experience from truth](06-data-security-and-release/72-persistent-memory-must-distinguish-experience-from-truth.md) — P1, Backlog — IN PROGRESS (EpistemicKind typed; memory wiring pending)(06-data-security-and-release/72-persistent-memory-must-distinguish-experience-from-truth.md) — P1, Backlog
- [ ] [#73 — Add memory provenance to prompts](06-data-security-and-release/73-add-memory-provenance-to-prompts.md) — P1, Backlog — IN PROGRESS (wrapping exists; annotations pending)(06-data-security-and-release/73-add-memory-provenance-to-prompts.md) — P1, Backlog
- [ ] [#74 — Secrets should be opaque references](06-data-security-and-release/74-secrets-should-be-opaque-references.md) — P1, Backlog — IN PROGRESS (vault solid; true opacity pending)(06-data-security-and-release/74-secrets-should-be-opaque-references.md) — P1, Backlog
- [ ] [#75 — Credential permissions should be scoped](06-data-security-and-release/75-credential-permissions-should-be-scoped.md) — P1, Backlog — IN PROGRESS (target scoping exists; matrix pending)(06-data-security-and-release/75-credential-permissions-should-be-scoped.md) — P1, Backlog
- [ ] [#76 — Add run-level data retention controls](06-data-security-and-release/76-add-run-level-data-retention-controls.md) — P1, Backlog — IN PROGRESS (gap confirmed; design pending)(06-data-security-and-release/76-add-run-level-data-retention-controls.md) — P1, Backlog
- [x] [#77 — API daemon security is mostly sensible](06-data-security-and-release/77-api-daemon-security-is-mostly-sensible.md) — P2, Backlog — DONE 2026-09-14 (revalidated: bearer+loopback+WS auth)(06-data-security-and-release/77-api-daemon-security-is-mostly-sensible.md) — P2, Backlog
- [ ] [#78 — Team features should come much later](06-data-security-and-release/78-team-features-should-come-much-later.md) — Deferred, Later — DEFERRED 2026-09-14 (prerequisites unmet by design)(06-data-security-and-release/78-team-features-should-come-much-later.md) — Deferred, Later / intentionally deferred
- [ ] [#79 — Fix GitHub metadata/details](06-data-security-and-release/79-fix-github-metadata-details.md) — P2, Backlog — IN PROGRESS (badges/docs exist; admin settings pending)(06-data-security-and-release/79-fix-github-metadata-details.md) — P2, Backlog
- [ ] [#80 — Releases need a strict "beta means beta" contract](06-data-security-and-release/80-releases-need-a-strict-beta-means-beta-contract.md) — P0, Backlog — IN PROGRESS (gate NO-GO, 4 externals)(06-data-security-and-release/80-releases-need-a-strict-beta-means-beta-contract.md) — P0, Backlog
