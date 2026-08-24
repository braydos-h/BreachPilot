---
title: MCP Registration — Registry, Decorators, collect_tools, AST Validation
sources:
  - tools/mcp_tools/registry.py
  - tools/mcp_shared.py
  - tools/kernel/audit.py
  - tools/kernel/allowlist.py
  - mcp_exploit_server.py
tests:
  - tests/test_mcp_tool_registration.py
  - tests/test_mcp_tool_scope.py
subsystem: mcp
---

# MCP Registration

Single-source registration for exploit MCP tools: add `@audit_tool` or `@require_allowlist()` in `tools/mcp_tools/<family>.py` only. `mcp_exploit_server.py` auto-discovers via `tools/mcp_tools/registry.collect_tools()` and fails CI if a tool lacks the gate.

## `ToolContext`

`tools/mcp_tools/registry.py:102-111` — frozen dataclass injected into every `register_*_tools(mcp, *, ctx)`:

```python
@dataclass(frozen=True)
class ToolContext:
    workspace: Path
    config: dict[str, Any] | None
    search: ExploitSearch
    nvd: NVDClient
    researcher: WebResearcher
    audit_tool: Any
    require_allowlist: Any
```

Built in `mcp_exploit_server.create_mcp_server` (`mcp_exploit_server.py:135-143`):

```python
require_allowlist = make_require_allowlist(workspace, config)
audit_tool = make_audit_tool(workspace)
ctx = ToolContext(workspace, config, search, nvd, researcher, audit_tool, require_allowlist)
```

Families do `from tools.mcp_tools.registry import *` and use local `audit_tool` / `require_allowlist` captured from `ctx` (`tools/mcp_tools/terminal.py:185-192`, etc.).

## The Two Decorators

### `@require_allowlist(target_param="target_ip")` — structured target gate

Factory `make_require_allowlist(workspace, config)` (`tools/kernel/audit.py:232-321`, re-exported via `tools/mcp_shared`). Usage:

- `@require_allowlist()` — target param defaults to `target_ip` (e.g. `tools/mcp_tools/recon.py:20`)
- `@require_allowlist("domain")` — domain families (e.g. `tools/mcp_tools/domain.py:292`)

Behavior (`tools/kernel/audit.py:239-321`):

1. Binds handler `*args/**kwargs` via `inspect.signature(fn).bind` and reads the named target param (`bound.arguments.get(target_param, "")`).
2. Calls `_check_allowlist(target_ip, config)` (`tools/kernel/allowlist.py:67-80`): if `exploit.require_explicit_allowlist` is `False` → allowed; else target must be in `_allowed_target_list(config)` via `is_target_in_allowlist`. Empty allowlist with flag `True` fails closed.
3. Writes `started` audit record (`approved=allowed`) with `_redact_args(dict(bound.arguments))` before gating; on `not allowed` returns `BLOCKED: ... ATTEMPT_ID: preflight`.
4. On allowed, awaits/calls handler, then inspects result string for blocked markers (`_result_is_blocked`) and writes `completed` or `blocked` (`approved=not blocked`). Handles both sync and `async` handlers, preserving `__signature__` for FastMCP introspection and setting `__wrapped_require_allowlist__` / `__wrapped_audit_tool__`.

### `@audit_tool` — audit for tools without a structured target

Factory `make_audit_tool(workspace)` (`tools/kernel/audit.py:324-387`, re-exported). Applied as bare `@audit_tool` (no call) to free-text command, callback-host, and local-only tools:

- `run_exploit_terminal`, `run_as_root`, `apt_install`, `generate_payload` (lhost), `msfconsole_command` (RHOSTS), `write_python_file`, `run_hash_crack`

Behavior:

1. Binds args, derives touched hosts via `_extract_audit_target(bound)` (`tools/kernel/audit.py:212-229`): extracts `RHOSTS/RHOST` + pivot hosts from `command`/`script_content` plus `lhost` arg.
2. Writes `started` record (`approved=True`), calls handler, then writes `blocked`/`completed` based on `_result_is_blocked(result)`.

Both decorators set `__wrapped_audit_tool__ = True` (and `__wrapped_require_allowlist__` for the allowlist variant) so AST validation can detect them by substring `audit_tool` / `require_allowlist` (`tools/mcp_tools/registry.py:384`).

### Choosing the gate (AGENTS.md rule 4)

- Structured `target_ip` param → `@require_allowlist()`
- Structured `domain` param → `@require_allowlist("domain")`
- Free-text command / script / `lhost` / `dc_ip` → `@audit_tool` + manual `check_targets_allowlist([...], config)` on extracted hosts inside the body (see `docs/mcp/security.md`)
- No target touch → `@audit_tool` only or nothing for pure queries (`list_workspace`, `list_attack_modules`)

## Discovery — `collect_tools()`

`tools/mcp_tools/registry.py:391-405`:

```python
def collect_tools() -> list[Any]:
    registrars = _discover_tool_registrars()
    errs = _validate_mcp_tool_decorators()
    if errs:
        raise RuntimeError("MCP tool decorator check failed:\n" + "\n".join(errs))
    return registrars
```

### `_discover_tool_registrars()` (`tools/mcp_tools/registry.py:311-342`)

- Returns cached `list(_TOOL_REGISTRARS)` if already populated (via decorator or prior discovery).
- Otherwise walks `tools.mcp_tools` package via `pkgutil.iter_modules(_pkg.__path__)`, skips `registry` and subpackages, imports each `tools.mcp_tools.<modname>` (swallows `Exception` per module), and collects every callable whose attribute name matches `register_*_tools` (`attr.startswith("register_") and attr.endswith("_tools")`).
- Appends to module global `_TOOL_REGISTRARS: list[Any] = []` (`tools/mcp_tools/registry.py:290`), so subsequent calls are cached. `register_tool_family(fn)` decorator (`tools/mcp_tools/registry.py:293-308`) also appends explicitly.

Consumed in `mcp_exploit_server.py:153-157`:

```python
for registrar in collect_tools():
    try:
        registrar(mcp, ctx=ctx)
    except Exception:
        logger.warning("MCP tool registration failed for %s", registrar.__name__, exc_info=True)
```

One bad family never breaks the rest; plugins follow same pattern (`mcp_exploit_server.py:159-171`).

### `_validate_mcp_tool_decorators()` (`tools/mcp_tools/registry.py:345-388`)

Static `ast` check over every `tools/mcp_tools/*.py` (skips `registry.py`, `__init__.py`):

- `ast.parse(py.read_text())`, walk `FunctionDef`/`AsyncFunctionDef`, collect `decorator_list`.
- `ast.unparse(decorator)` lowercased; `has_mcp_tool = "mcp.tool" in low or ".tool(" in low`; `has_audit = "audit_tool" in low or "require_allowlist" in low`.
- If `has_mcp_tool and not has_audit`, append `f"{py.name}:{node.lineno} {node.name} has @mcp.tool but lacks @audit_tool/@require_allowlist"`.

`collect_tools()` raises `RuntimeError` with those errors → CI fails if a tool lacks the gate. This is the single enforcement point for AGENTS.md rule 4.

## Shared Helpers Re-Exported via `registry`

`tools/mcp_tools/registry.py:60-87, 413-511` re-exports for families' `from tools.mcp_tools.registry import *`:

- `ToolContext` + `_run_with_pgrp_timeout` (compatibility shim that honors `mcp_exploit_server._run_with_pgrp_timeout` monkeypatch, `tools/mcp_tools/registry.py:113-136`)
- `_get_model_router` / `_get_model_client` / `_resolve_consult_aliases` / `_multi_model_enabled` / `_chat_content` / `_truncate_text` / `_skills_config` / `_runtime_skills_enabled`
- `_ensure_workspace_dirs` (`tools/mcp_tools/registry.py:276-279` → creates `plans/exploits/modules/campaigns`)
- `_attempt_dir`, `_extract_msf_rhosts`, `_extract_scanner_targets`, `check_targets_allowlist`, `ps_quote`
- `validate_target`, `validate_target_or_ip`, `is_target_in_allowlist`, `is_fqdn`, `resolve_target_to_ip`, `preflight_command_check`, `is_subdomain_of`
- stdlib modules `asyncio, datetime, json, os, re, signal, socket, time, _ssl_module, Path, Any`

## Adding a New Tool

1. In `tools/mcp_tools/<family>.py`, inside `register_<family>_tools(mcp, *, ctx)`, add:

   ```python
   @mcp.tool()
   @require_allowlist()   # or @audit_tool + manual check_targets_allowlist
   def my_tool(target_ip: str, ...) -> str: ...
   ```

2. Validate inputs (`validate_target_or_ip` on target args, regex on free-text, `shlex` + shell-metachar rejection for `options`).
3. Run subprocesses via `_run_with_pgrp_timeout(argv_list, timeout, ...)` with `text=True`, never a shell string.
4. Write artifacts under `_attempt_dir(workspace)` per attempt.
5. No edit to `mcp_exploit_server.py` or `registry.py` needed. Tests: mock `subprocess.Popen`/`_run_with_pgrp_timeout`, never live Nmap.

## Related Docs

- `docs/mcp/servers/exploit.md`
- `docs/mcp/security.md`
- `docs/mcp/tool-families/*.md`
