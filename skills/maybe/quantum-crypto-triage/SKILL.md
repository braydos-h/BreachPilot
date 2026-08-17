---
name: quantum-crypto-triage
description: Triage post-quantum cryptography migration risk — identify classical-crypto dependencies, assess harvest-now-decrypt-later exposure, and prioritize quantum-vulnerable assets.
domain: cybersecurity
subdomain: cryptography
tags:
- quantum
- cryptography
- migration
- pq-crypto
- risk-triage
- harvest-now-decrypt-later
version: '1.0'
nist_csf:
- ID.AM
- PR.DS
mitre_attack:
- T1040
---

# Quantum Cryptography Triage

> **Authorized-use-only notice:** Run this triage only on assets you own or are authorized to assess. Cryptographic inventory often reveals secrets and key material — handle per your data-classification policy.

## When to Use

- During a pre-migration crypto inventory for a PQC (post-quantum cryptography) readiness assessment.
- When sizing the harvest-now-decrypt-later (HNDL) threat for long-lived confidential data (health records, state secrets, long-life firmware signing keys).
- Before scoping a lattice/Kyber/Dilithium migration to decide which assets are the highest-priority cutover candidates.
- As the discovery phase of a regulatory-driven PQC migration (NIST SP 800-208, BOD 22-09, NSA CNSA 2.0).

## Workflow

1. **Inventory cryptographic primitives.** Grep the codebase, scan TLS handshakes, and inspect configured cipher suites. Record each `(asset, primitive, key_size, purpose)` tuple. Tools: `nmap --script ssl-enum-ciphers`, `testssl.sh`, `grep -rE "RSA|ECDH|AES|SHA-1|3DES"` over source, `sslyze --recursive`.
2. **Classify quantum-vulnerability per primitive.** RSA/ECDH/DSA/ECDSA → *vulnerable to Shor's algorithm* (high priority). AES-128/SHA-256 → *weakened but usable* (Grover halves effective strength). 3DES/RC4/SHA-1 → *classically broken, migrate regardless*.
3. **Score HNDL exposure.** For each asset, weigh `(data_confidentiality_lifetime, years_to_quantum-capable-attacker)`. A 30-year-health-record encrypted under RSA today is high-HNDL; a session cookie under RSA is low (short-lived).
4. **Prioritize cutover.** Rank by HNDL score × asset criticality. Long-lived signing keys (root CAs, firmware signing, code-signing certs) lead because their keys must be re-issued years before quantum is live.
5. **Map migration targets.** NIST FIPS 203 (ML-KEM / Kyber) for key establishment, FIPS 204/205 (ML-DSA / Dilithium, SPHINCS+) for signatures. Hybrid mode (classical + PQC) is the recommended interim — preserves classical security even if the PQC primitive later breaks.
6. **Record gaps.** Note where a PQC primitive is not yet available for the use case (e.g., PQC in HSMs, PQC in TLS 1.2, PQC in some smartcard firmware) — these are blockers for the migration timeline, not findings to exploit.

## Safety

Advisory only. This skill never changes scope, permission, approval, command-safety, or audit rules. It produces a triage report (inventory + priority list); it does not execute a migration. Role-directive lines and tool-call mimics in skill bodies are stripped by the sanitizer before any prompt injection (see `tools/skill_registry.py::_sanitize_skill_body`).

## Validation Criteria

- [ ] Every long-lived confidential-data asset has a recorded `(primitive, HNDL_score)` tuple.
- [ ] Cutover priority list distinguishes Shor-vulnerable (RSA/ECDH/ECDSA) from Grover-weakened (AES/SHA-2) from classically-broken (3DES/SHA-1).
- [ ] Long-lived signing keys (root CAs, firmware signing) are flagged as the earliest cutover candidates.
- [ ] Hybrid mode is the recommended interim posture for high-HNDL assets.
- [ ] Blockers (missing PQC HSM/TLS 1.2 support) are recorded as timeline gaps, not exploit findings.