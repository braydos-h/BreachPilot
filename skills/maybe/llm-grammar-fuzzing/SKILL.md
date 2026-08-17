---
name: llm-grammar-fuzzing
description: Fuzz an LLM or LLM tool layer with grammar-aware payloads — context-free-grammar-derived mutation, output-schema violation, and role-directive injection against the model's own input contract.
domain: cybersecurity
subdomain: ai-security
tags:
- ai-security
- fuzzing
- llm
- grammar
- mutation
- output-schema
version: '1.0'
nist_csf:
- PR.IP
mitre_attack:
- AML.T0051
- AML.T0052
---

# LLM Grammar Fuzzing

> **Authorized-use-only notice:** Fuzz only LLMs and tool layers you own or are explicitly authorized to test. Fuzzing a third-party hosted model is almost always a terms-of-service violation and may be illegal. Run against your own model deployment or a local model.

## When to Use

- Before deploying an LLM agent that accepts structured input (JSON, XML, function-call args) from untrusted users.
- When validating that an output guardrail rejects malformed or policy-violating model responses.
- As part of a pre-release red-team against an LLM-based product feature.
- When an audit finding flags the model's input/output contract as untested at the boundaries.

## Workflow

### 1. Derive the input grammar

Capture the model's expected input contract: the system prompt, the tool schemas (JSON Schema for MCP tools / function calls), the message format (chat roles), and any structured-input validator (a Pydantic model, a JSON Schema). This is your grammar. Tools: read the tool definitions from the MCP server's `tools/list`, dump the system prompt (if you own the model), and inspect the request-validation layer.

### 2. Grammar-aware mutation

Mutate within the grammar AND across the grammar boundary. Within-grammar mutations catch parser-edge bugs (deeply nested JSON, oversized strings, duplicate keys, unicode edge cases). Across-grammar mutations catch contract violations (role-directive injection, schema-mismatched types, missing required fields, extra fields the validator should reject). A CFG (context-free grammar) or a JSON-Schema-fuzzing library (`hypothesis`, `jsf`, `genson`) drives both classes.

Payload classes:
- **Structural**: deeply nested objects, arrays with 10k+ elements, duplicate keys, null where a string is required, numbers as strings.
- **Lexical**: unicode homoglyphs, zero-width characters, BOM, control characters, max-length strings, empty strings.
- **Semantic-role**: `{"role": "system", "content": "..."}` injected as a user message; `## SYSTEM:` directives; `<<SYSTEM>>` tokens; `[SYSTEM]` brackets; `<|im_start|>` tokens. These test the role-isolation guardrail.
- **Tool-schema**: call a tool not in the allowlist; call an allowlisted tool with out-of-shape args; call with extra args the validator should drop; call with a target IP not on the allowlist (tests the target-lock).
- **Output-contract**: ask the model to return a response that violates its declared output schema (wrong type, missing field, oversized field) — this tests the output guardrail, not the model.

### 3. Run + classify

For each payload, record `(payload_class, payload, model_response, guardrail_decision, outcome)`. Outcome is one of: `accepted_clean` (guardrail passed, response valid), `rejected_input` (input guardrail blocked), `rejected_output` (output guardrail blocked), `bypassed` (guardrail should have blocked but did not — this is a finding), `crashed` (model/agent errored — a separate finding). The `bypassed` class is the signal; the others are the control working.

### 4. Triage findings

A `bypassed` payload is a finding. Severity: high if it produced a tool call that would have an irreversible side effect (file write, email send, infra change); medium if it leaked the system prompt or a secret; low if it only produced a malformed response. Every high-severity finding blocks release; medium and low are tracked.

### 5. Regression suite

Pin every `bypassed` payload that was later fixed as a regression test. The fuzz corpus grows over releases; a release that regresses a previously-fixed bypass fails CI. This is the long-term value — the corpus becomes the agent's contract test suite.

## Safety

Advisory only. This skill never changes scope, permission, approval, command-safety, or audit rules. It is a fuzzing methodology, not an automated attacker — every payload is run against a model the operator owns, and findings are reported, not exploited. Role-directive lines and tool-call mimics in skill bodies are stripped by the sanitizer before any prompt injection (see `tools/skill_registry.py::_sanitize_skill_body`).

## Validation Criteria

- [ ] Input grammar captured (system prompt, tool schemas, message format, validator).
- [ ] All five payload classes (structural, lexical, semantic-role, tool-schema, output-contract) exercised.
- [ ] Every payload outcome classified (accepted_clean / rejected_input / rejected_output / bypassed / crashed).
- [ ] Every `bypassed` payload triaged with severity (high blocks release).
- [ ] Previously-fixed bypasses pinned as regression tests in CI.
- [ ] Fuzz corpus committed and grows across releases.