# 59. Don't benchmark only your own targets

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14 — gap confirmed) |
| Suggested priority | P2 |
| Suggested horizon | Backlog |
| Theme | WebUI, delivery, and ecosystem |
| Dependencies | None recorded; confirm during scoping. |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [ ] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [ ] Add or update focused tests and evaluation coverage where applicable.
- [ ] Update generated and user-facing docs/config contracts where applicable.
- [ ] Record completion evidence below and update [the backlog index](../README.md).

## Requirements called out by the audit

- [ ] purpose-built BreachPilot scenarios;
- [ ] OWASP Juice Shop-style scenarios;
- [ ] WebGoat-like environments;
- [ ] Nuclei template labs;
- [ ] public benchmark corpora;
- [ ] maintained CTF-like vulnerable services;
- [ ] XBOW-style benchmark compatibility where licensing permits.

## Audit recommendation

Eventually test against multiple independent corpora.

Possible classes:

* purpose-built BreachPilot scenarios;
* OWASP Juice Shop-style scenarios;
* WebGoat-like environments;
* Nuclei template labs;
* public benchmark corpora;
* maintained CTF-like vulnerable services;
* XBOW-style benchmark compatibility where licensing permits.

PentestGPT's current architecture explicitly retains an XBOW benchmark reference corpus, showing how important comparative evaluation has become in this space. ([GitHub](https://github.com/GreyDGL/PentestGPT/blob/main/docs/architecture.md?utm_source=chatgpt.com))

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: revalidation slice (no code change yet)
- Design/issue: Wave 7 — independent corpora where licensing permits
- Commits/PRs: none yet; revalidation: eval_targets + XBEN manifests are
  first-party; no third-party corpus wired
- Tests/evaluations: n/a
- Documentation: n/a
- Follow-ups: adopt permitted external corpora as registry providers.

