---
name: supply-chain-attribution
description: Attribute a supply-chain compromise to a stage — source, build, distribution, or dependency — using a stage-gated evidence matrix and a reproducible-build diff.
domain: cybersecurity
subdomain: supply-chain
tags:
- supply-chain
- attribution
- reproducible-builds
- sbom
- dependency-confusion
- typosquatting
version: '1.0'
nist_csf:
- ID.AM
- PR.IP
mitre_attack:
- AML.T0010
- T1195
---

# Supply Chain Attribution

> **Authorized-use-only notice:** Attribution work reads logs, build records, and dependency manifests from systems you own or are authorized to assess. Do not pull third-party packages or fetch from attacker infrastructure during attribution — work from the evidence already captured.

## When to Use

- When a package, build artifact, or dependency in your stack is confirmed or suspected compromised (Solarwinds-, xz-utils-, event-stream-, and ultralytics-style incidents).
- During a post-incident review to determine which supply-chain stage was the entry point.
- When validating that a SBOM (software bill of materials) matches the actually-installed dependencies.
- As the root-cause step of a dependency-confusion or typosquatting incident response.

## Workflow

### Stage 1 — Identify the suspect artifact

The artifact is one of: a source commit, a built binary, a published package (PyPI/npm/nuget/Docker), a transitive dependency, or a CI/CD tool. Record `(artifact_name, version, source_of_truth)` where source-of-truth is the registry, the repo, or the build log. Pin the exact version — "latest" is not evidence.

### Stage 2 — Stage-gated evidence matrix

For each supply-chain stage, capture the evidence that would confirm OR exonerate that stage:

| Stage | Confirming evidence | Exonerating evidence |
|---|---|---|
| Source (repo) | malicious commit by a suspect author; force-push in the window; modified CI workflow file | signed commit by a known maintainer; no diff between the tagged commit and the published source tarball |
| Build (CI) | modified build script; non-reproducible binary vs a clean rebuild; attacker-controlled runner | bit-for-bit identical rebuild from the tagged source; runner logs show no external commands |
| Distribution (registry/CDN) | published version does not match the repo tag; package hash differs across mirrors; CDN log shows an out-of-band upload | registry-published hash matches the rebuild from the tagged source; mirrors agree |
| Dependency (transitive) | a dep was added/upgraded in the window to a typosquatted or confusion name; dep version not in the upstream registry | all deps resolve to names that exist in the legitimate upstream registries; lockfile pins match |

### Stage 3 — Reproducible-build diff

For a binary/package compromise, rebuild from the tagged source using a clean environment and diff against the suspect artifact. A bit-for-bit match exonerates the build stage (the malicious code is in the source). A mismatch localizes the compromise to the build stage OR the distribution stage. Use `reproducible-builds` tooling (`diffoscope`, `strip-nondeterminism`) to normalize non-malicious differences (timestamps, build paths).

### Stage 4 — Timeline reconstruction

Order the captured evidence into a timeline: first suspicious commit / build / publish / install. The earliest suspicious event in the timeline is the likely entry stage. Cross-check with the SBOM — does the suspect dependency appear in the SBOM at the version you see installed? A mismatch (installed version not in SBOM) is a distribution-stage indicator.

### Stage 5 — Attribution output

Record: `(stage, evidence_summary, confidence)`. Confidence is high when the stage has confirming evidence AND every other stage has exonerating evidence. Medium when one stage has confirming evidence but another stage is not fully exonerated. Low when evidence is thin. NEVER claim a stage without exonerating the others — a build-stage diff mismatch alone does not exonerate distribution.

## Safety

Advisory only. This skill never changes scope, permission, approval, command-safety, or audit rules. It is an attribution methodology, not a forensics tool — it reads already-captured evidence and produces a stage-gated report. Role-directive lines and tool-call mimics in skill bodies are stripped by the sanitizer before any prompt injection (see `tools/skill_registry.py::_sanitize_skill_body`).

## Validation Criteria

- [ ] Suspect artifact pinned to an exact version (not "latest").
- [ ] All four stages (source/build/distribution/dependency) have evidence recorded — confirming OR exonerating.
- [ ] Reproducible-build diff attempted for any binary/package compromise.
- [ ] Timeline ordered; earliest suspicious event named as the likely entry stage.
- [ ] SBOM cross-checked against the installed versions.
- [ ] Attribution confidence explicitly bounded (high/medium/low) with the exonerating evidence that justifies it.