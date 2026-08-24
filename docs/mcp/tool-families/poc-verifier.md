---
title: "Tool Family: poc-verifier"
sources:
  - tools/mcp_tools/poc_verifier.py
  - tools/poc_verifier.py
  - tools/kernel/audit.py
tests:
  - tests/test_poc_verifier.py
  - tests/test_mcp_tool_registration.py
subsystem: mcp
---

# Tool Family: poc-verifier

- **Registration source:** `tools/mcp_tools/poc_verifier.py:26 register_poc_verifier_tools(mcp, *, ctx)` — auto-discovered, always registers (even when feature disabled in config; the `enabled` flag controls whether `cve_to_exploit_synth` auto-invokes it, not whether the tool exists).
- **Gate:** `@audit_tool` — local-only, no target touch. Docstring warns: if a future variant runs a PoC *against the live target*, it **must** switch to `@require_allowlist()`.

## Tools Exported (1)

| Tool | Params | Result Shape | Notes |
|------|--------|--------------|-------|
| `verify_poc` | `code: str`, `image: str=""` | `render_verify_result(result)` → `syntax_ok: bool, docker_ok: bool?, stderr, code_sha256` text block | Validates `code` non-empty else `BLOCKED: code is required.` Resolves `image = (image.strip() or cfg["docker_image"])`; loads `cfg = poc_verification_config(config)` (`tools/poc_verifier.py`): `enabled, docker_image, compile_timeout_seconds, docker_network, docker_read_only, docker_memory`. Calls `_verify_poc_lib(code, image, timeout=cfg["compile_timeout_seconds"], network, read_only, memory, use_docker=cfg["enabled"])`. PoC is **never executed** — `py_compile` + optional Docker compile test with isolation `--network=none --read-only --memory=256m`. Docker container is fully isolated. |

## Dependencies

- `tools/poc_verifier.verify_poc`, `poc_verification_config`, `render_verify_result`
- `tools/kernel/audit.make_audit_tool`

## Config

- `poc_verification.enabled: bool` — controls Docker auto-invoke in synthesis loop; tool itself still available when false
- `poc_verification.docker_image: str`
- `poc_verification.compile_timeout_seconds: int`
- `poc_verification.docker_network: str` (default `none`), `docker_read_only: bool`, `docker_memory: str` (`256m`)

## Auditing

- `@audit_tool` — `code` arg not secret but still content-masked; `image` recorded. `started`/`completed|blocked` with duration.

## Validation

- Empty code → `BLOCKED`; Docker image defaults when empty; `use_docker` gates isolation flags.

## Tests

- `tests/test_poc_verifier.py` — `py_compile` pass/fail, Docker mock, timeout, read-only isolation
- `tests/test_mcp_tool_registration.py` — implicitly covered when all families enabled (not in legacy expected subset)

## Related Docs

- `docs/mcp/tool-families/attack-modules.md` — `cve_to_exploit_synth` self-heal loop that calls `verify_poc`
- `tools/poc_verifier.py` — implementation (never executes PoC)
