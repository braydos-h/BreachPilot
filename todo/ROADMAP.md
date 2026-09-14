# Roadmap task map

The roadmap below is preserved from the audit. The links connect its phases to
the individually trackable files.

## 30-day focus

- [#02 — Live autonomous evaluation needs to become the centre of development](01-strategy-and-evaluation/02-live-autonomous-evaluation-needs-to-become-the-centre-of-development.md)
- [#08 — Add semantic configuration assertions](01-strategy-and-evaluation/08-add-semantic-configuration-assertions.md)
- [#09 — The giant exploit loop is now an architectural liability](02-architecture-and-agent-security/09-the-giant-exploit-loop-is-now-an-architectural-liability.md)
- [#11 — Type debt matters more here than in most Python projects](02-architecture-and-agent-security/11-type-debt-matters-more-here-than-in-most-python-projects.md)
- [#12 — Turn tools into declarative capabilities](02-architecture-and-agent-security/12-turn-tools-into-declarative-capabilities.md)
- [#16 — Add an injection regression corpus](02-architecture-and-agent-security/16-add-an-injection-regression-corpus.md)
- [#41 — The public repo should have mandatory branch rules immediately](04-runtime-governance-and-ci/41-the-public-repo-should-have-mandatory-branch-rules-immediately.md)
- [#46 — Create a CI pyramid](04-runtime-governance-and-ci/46-create-a-ci-pyramid.md)
- [#51 — Add UI end-to-end tests around workflows, not pages](05-webui-delivery-and-ecosystem/51-add-ui-end-to-end-tests-around-workflows-not-pages.md)
- [#69 — Introduce an observation schema](06-data-security-and-release/69-introduce-an-observation-schema.md)

## 60-day focus

- [#04 — Finding verification should become the centre of the data model](01-strategy-and-evaluation/04-finding-verification-should-become-the-centre-of-the-data-model.md)
- [#05 — Build vulnerability regression testing](01-strategy-and-evaluation/05-build-vulnerability-regression-testing.md)
- [#10 — Retire Flow B](02-architecture-and-agent-security/10-retire-flow-b.md)
- [#18 — Redesign the WebUI around "Assessment", not internal architecture](03-product-and-assessment-workflows/18-redesign-the-webui-around-assessment-not-internal-architecture.md)
- [#19 — Assessment creation should be a wizard](03-product-and-assessment-workflows/19-assessment-creation-should-be-a-wizard.md)
- [#21 — Add an "agent plan" view](03-product-and-assessment-workflows/21-add-an-agent-plan-view.md)
- [#23 — Authenticated web testing should be a major P1](03-product-and-assessment-workflows/23-authenticated-web-testing-should-be-a-major-p1.md)
- [#24 — Import OpenAPI/Postman/HAR/Burp data](03-product-and-assessment-workflows/24-import-openapi-postman-har-burp-data.md)
- [#25 — Add differential authorization testing](03-product-and-assessment-workflows/25-add-differential-authorization-testing.md)
- [#28 — Make evidence excellent](03-product-and-assessment-workflows/28-make-evidence-excellent.md)
- [#38 — Benchmark across model providers](04-runtime-governance-and-ci/38-benchmark-across-model-providers.md)
- [#60 — A major competitive opportunity: "assessment gaps"](05-webui-delivery-and-ecosystem/60-a-major-competitive-opportunity-assessment-gaps.md)
- [#63 — Add report diffing](05-webui-delivery-and-ecosystem/63-add-report-diffing.md)

## 90-day focus

- [#26 — Add source-assisted dynamic testing](03-product-and-assessment-workflows/26-add-source-assisted-dynamic-testing.md)
- [#31 — Integrations should follow the finding lifecycle](03-product-and-assessment-workflows/31-integrations-should-follow-the-finding-lifecycle.md)
- [#58 — Add a public benchmark dashboard](05-webui-delivery-and-ecosystem/58-add-a-public-benchmark-dashboard.md)
- [#65 — Git/CI integration would be valuable](05-webui-delivery-and-ecosystem/65-git-ci-integration-would-be-valuable.md)

---

# 30-day roadmap

## Weeks 1–2 — prove the engine

1. Wire the new live evaluation result taxonomy into `eval.yml`.
2. Provision one real model backend for scheduled evaluation.
3. Run repeated trials.
4. Establish baseline metrics.
5. Make missing live-eval infrastructure visibly `SKIPPED/INFRA_ERROR`, never green "success".
6. Enable `main` ruleset.
7. Complete current Docker/browser CI validation.
8. Resolve documentation/config contradictions.

Do **no major new features**.

## Weeks 3–4 — reduce architectural risk

1. Begin exploit-runner extraction under golden/live traces.
2. Finish typing `run_manager`/orchestration boundaries.
3. Define typed `Observation`, `ToolInvocation`, `Evidence`, `Finding`.
4. Create declarative tool metadata.
5. Start Flow B migration/parity tests.
6. Add safety-agent injection benchmark corpus.

---

# 60-day roadmap

## Product quality

Build:

* assessment creation wizard;
* improved plan DAG;
* finding lifecycle;
* evidence browser;
* assessment coverage/gaps;
* finding diff/retest;
* regression-test generation.

## Web/API depth

Add:

* OpenAPI import;
* Postman import;
* HAR import;
* session/credential profiles;
* multiple identities;
* differential authorization testing.

## Engineering

Finish:

* Flow B retirement;
* exploit runner decomposition;
* tool manifest registry;
* model/provider comparative benchmark.

---

# 90-day roadmap

Then go after differentiation:

### Source-assisted testing

```text
repo + deployed target → hypotheses → dynamic proof
```

### Continuous validation

```text
verified vulnerability → regression test → CI → retest
```

### Integrations

```text
GitHub
Jira
Linear
SARIF
webhooks
```

### Public evidence

Publish versioned benchmark results with reproducible configuration.

At that point BreachPilot starts looking less like an ambitious autonomous hacking framework and more like a real AppSec/security testing product.

---

# The five things I would implement first

If you want the condensed answer after all of that:

1. **Finish the live autonomous evaluation pipeline.** Your new harness is useful, but `.github/workflows/eval.yml` still green-skips without credentials. Fix this first.
2. **Require green checks on protected `main`.** It is currently unprotected.
3. **Make verified findings/retest/regression the core product object.** This is the strongest potential differentiation against generic "AI pentest agents."
4. **Freeze capability expansion while decomposing the ~2,700-line autonomous runner and retiring Flow B.**
5. **Redesign the WebUI around Assessments → Findings → Evidence → Retest, with first-class authenticated API/web testing.**

The underlying architecture is already broad enough. The next leap in quality will come from making BreachPilot **measurably trustworthy, easier to operate, and excellent at turning autonomous exploration into reproducible verified findings**, rather than making it capable of even more kinds of actions.

I also compared the direction against current agent-security guidance: OWASP's current guidance emphasizes prompt/context attacks, tool misuse, excessive agency, memory poisoning and structured adversarial agent testing, while MCP's July 2026 specification has materially evolved around stateless operation and authorization. Those should inform the next threat-model/evaluation iteration. ([OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html?utm_source=chatgpt.com))

