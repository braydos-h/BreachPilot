---
title: MCP Lifecycle — Boot Sequence, Transports, Timeouts, Exception Groups, Env Propagation
sources:
  - tools/mcp_session.py
  - tools/mcp_shared.py
  - tools/exceptions.py
  - mcp_exploit_server.py
  - tools/run_service/service.py
tests:
  - tests/test_mcp_http_lifecycle.py
  - tests/test_mcp_http_hardening.py
  - tests/test_mcp_shared_helpers.py
subsystem: mcp
---

# MCP Lifecycle

Boot sequence for the exploit MCP session (`tools/mcp_session.py`), stdio/HTTP transports, timeouts, exception-group handling, and env-var propagation.

## Boot Sequence

### `open_exploit_mcp_session` (public entry point)

`tools/mcp_session.py:117-196` — `open_exploit_mcp_session(*, transport, config_path, target_ip, exploit_port, workspace, soft_fail, fallback_to_stdio, original_target, resolved_ip, boot_cb)`:

- Normalizes to `_open_exploit_mcp_session_once`. If `transport != "http"` or `fallback_to_stdio=False`, it opens that single transport directly.
- For `transport="http"` + fallback (the run path): tries HTTP with `startup_soft_fail=True` and collects `http_startup_errors`. If a session was yielded, done. Otherwise emits `ui.warning("Local MCP HTTP startup failed; falling back to stdio transport.")` and tries stdio with real `soft_fail`. If both fail, re-raises a combined `RuntimeError` with concise redacted messages.

`soft_fail` controls whether boot/mid-session death is swallowed and `None` is yielded (recon-first path degrades to `UNKNOWN` assessment, `tools/run_service/service.py:921-935`) vs. hard failure (attack path).

### `_open_exploit_mcp_session_once` (one transport, no fallback)

`tools/mcp_session.py:199-620`:

- Imports `mcp.ClientSession, StdioServerParameters, stdio_client` — on `ImportError` warns and yields `None` when `startup_soft_fail` else raises.
- Computes `server_path = Path(__file__).parent.parent / "mcp_exploit_server.py"` (resolved, `mcp_session.py:254-255`).
- Builds `env` copy + injections (see Env Propagation below) and boot checklist spinners (`ui.boot_section`, `ui.spinner` with `MCP_BOOT_TIMEOUT_SECONDS` heartbeat).
- **stdio branch** (`mcp_session.py:296-402`): `StdioServerParameters(command=sys.executable, args=[server_path, --transport stdio, --config, --workspace], env=env)` → `stdio_client(params)` → `ClientSession` → `await wait_for(session.initialize(), 30s)`. On `TimeoutError` soft-fails with `ui.warning` and yields `None`. Mid-session `await session` block is wrapped in `_EXC_GROUP_CATCH` so `BaseExceptionGroup` is caught.
- **http branch** (`mcp_session.py:404-620`): `start_exploit_http_server(...)` → `wait_for_mcp_http_ready(url, 30s)` (owned-child TCP listener) → `_streamable_http_transport(url, token)` → `ClientSession.initialize` capped at 30s → `yield session`. Each startup step has a matching soft-fail `yield None` (required: an `asynccontextmanager` must `yield` before `return`, otherwise `RuntimeError: async generator didn't yield`). Post-yield failure uses `soft_fail`, startup failure uses `startup_soft_fail` (`mcp_session.py:589`).

### Helpers

| Helper | Location | What it does |
|--------|----------|--------------|
| `start_exploit_http_server` | `mcp_session.py:623-671` | Guards `port_is_open` (fail fast if occupied), creates `workspace/mcp_exploit_server.log`, `Popen([sys.executable, server_path, --transport http, --host 127.0.0.1, --port, --config, --workspace], cwd=server_parent, env=env, stdout=log, stderr=STDOUT, text, CREATE_NEW_PROCESS_GROUP/start_new_session)` |
| `wait_for_mcp_http_ready` | `mcp_session.py:771-808` | Polls `port_is_open(host,port)` in `asyncio.sleep(delay)` loop until deadline `MCP_BOOT_TIMEOUT_SECONDS`; checks `process.poll()` each attempt and raises with redacted log tail if child exited |
| `_streamable_http_transport` | `mcp_session.py:720-742` | `httpx.AsyncClient(follow_redirects, headers=Bearer, timeout=Timeout(30, read=1800), trust_env=False)` → `streamable_http_client(url, http_client)` |
| `stop_process` | `mcp_session.py:811-865` | POSIX `killpg SIGTERM` → wait 5s → `killpg SIGKILL`; Windows `CTRL_BREAK_EVENT` → `taskkill /PID /T /F`; then `_verify_port_freed` polls port release and retries tree-kill once |
| `_server_log_tail` | `mcp_session.py:696-717` | Last 20 lines / 4000 chars of `mcp_exploit_server.log`, redacted via `_redact_startup_text` |
| `_redact_startup_text` | `mcp_session.py:682-693` | Masks exact secret values, `Bearer ...`, `url://user:pass@`, `key=value` assignments |
| `port_is_open` | `mcp_session.py:906-911` | `socket.create_connection((host,port), 0.5)` |
| `mcp_tools_to_ollama` | `mcp_session.py:934-957` | Converts `list_tools()` response to Ollama `function` schemas, honoring `disabled_tools` set |

## Timeouts and Constants

| Constant | Value | Location | Covers |
|----------|-------|----------|--------|
| `MCP_BOOT_TIMEOUT_SECONDS` | `30.0` | `mcp_session.py:32` | `session.initialize()` on both transports + `wait_for_mcp_http_ready` budget |
| `MCP_HTTP_RETRY_INITIAL_SECONDS` | `0.2` | `mcp_session.py:33` | Initial poll delay in `wait_for_mcp_http_ready` |
| HTTP read timeout | `1800s` | `mcp_session.py:734` | `httpx.Timeout` read for `_streamable_http_transport` (covers 600s msf/long terminal calls + idle) |
| HTTP boot `(connect+write)` | `30s` | `mcp_session.py:734` | Same timeout object first arg |
| Tool timeouts | 10..600s per tool | families | `check_environment 10s`, `git_clone 120s`, `run_exploit_terminal 300s`, `install_package apt 600s` (`tools/mcp_tools/*.py`) |
| `stop_process` wait | `5s` TERM + `5s` KILL | `mcp_session.py:846-855` | Graceful → hard kill escalation |
| `_verify_port_freed` | `3s` + `2s` retry | `mcp_session.py:868-903` | Port-release poll after Windows tree-kill (prevents 30s×2 readiness probe stall) |

Boot spinner shows elapsed `1s` heartbeat (`mcp_session.py:319-320, 493`) so cold start (5–15s of heavy imports) doesn't look frozen.

## Exception Groups (AGENTS.md rule 1)

`tools/exceptions.py:1-41`:

- Anyio task groups raise `BaseExceptionGroup` on subprocess death — **not** an `Exception` subclass — so `except Exception` misses it.
- `_EXC_GROUP_CATCH: tuple[type[BaseException], ...] = (Exception, BaseExceptionGroup)` on 3.11+ else `(Exception,)` (`tools/exceptions.py:38-41`)
- `_is_exception_group(exc)` (`tools/exceptions.py:15-19`) — `isinstance(BaseExceptionGroup)` plus `hasattr(exceptions)` duck-type
- `_log_nested_exceptions(exc)` (`tools/exceptions.py:22-35`) — recursively prints nested tracebacks with `[i]` prefix

Correct sites (`tools/mcp_session.py:188, 369, 479, 528, 568, 578, 598`):

```python
from tools.exceptions import _EXC_GROUP_CATCH, _is_exception_group, _log_nested_exceptions
try:
    async with stdio_client(params) as (r,w):
        async with ClientSession(r,w) as s:
            await s.initialize()
except _EXC_GROUP_CATCH as exc:
    if _is_exception_group(exc):
        _log_nested_exceptions(exc)
    raise
```

## Env Propagation

`_open_exploit_mcp_session_once` (`mcp_session.py:256-272`) copies `os.environ` and sets:

| Env var | Set to | Consumed by | Notes |
|---------|--------|-------------|-------|
| `EXPLOIT_TARGET` | `target_ip` (literal `--target`, IP or domain) | `tools/kernel/allowlist._allowed_target_list` (`tools/mcp_shared.py:494-534`) | Primary lock identity |
| `EXPLOIT_WORKSPACE` | `str(workspace.resolve())` | families, `tools/kernel/workspace` | Per-run workspace root |
| `EXPLOIT_TARGET_IP` | `resolved_ip` (when `original_target` + `resolved_ip` both set) | same union | Lets IP tools target resolved host |
| `EXPLOIT_TARGET_DOMAIN` | `original_target` (domain string) | same union | Lets HTTP tools use Host/SNI |
| `AI_NMAP_MULTI_MODEL_ENABLED` | `1/0` when `multi_model_enabled` not None | `tools/mcp_tools/registry._multi_model_enabled` | Per-run peer-consult override |
| `AI_NMAP_ACTIVE_MODEL_ALIAS` | `active_model_alias` when non-empty | `tools/mcp_tools/registry._resolve_consult_aliases` | Excludes active model from self-consult |
| `MCP_HTTP_TOKEN` | operator env (passed through) | `tools/mcp_shared.run_mcp_http_server` server + `_streamable_http_transport` client | Optional bearer secret |

`_allowed_target_list` unions `config["exploit"]["allowed_targets"]` with those env vars plus `EXPLOIT_DISCOVERED_TARGETS` (comma-separated, via `add_discovered_target` in `tools/mcp_tools/domain.py:475`).

`_filter_env_for_log` / `_sensitive_env_values` (`mcp_session.py:91-113`) mask secrets when logging boot diagnostics; `_server_log_tail` caps and redacts the server log before appending to startup errors.

## HTTP Transport Hardening (shared)

`tools/mcp_shared.run_mcp_http_server` (`tools/mcp_shared.py:384-405`) + `assert_loopback_bind` (`tools/mcp_shared.py:334-350`) + `_wrap_http_auth` (`tools/mcp_shared.py:353-381`):

1. **Loopback gate** — `_LOOPBACK_HOSTS = {127.0.0.1, localhost, ::1}`. Non-loopback `host` raises `ValueError` unless **both** `allow_public_bind=True` (the `--allow-public-bind` flag) and `MCP_ALLOW_PUBLIC_BIND` env var truthy (`1/true/yes/on`). Two-person rule.
2. **Bearer auth** — when `MCP_HTTP_TOKEN` set, ASGI app wrapped by `_wrap_http_auth`: pure-ASGI middleware requiring `Authorization: Bearer <token>` compared with `hmac.compare_digest`; otherwise `401 Unauthorized` with `WWW-Authenticate: Bearer`.
3. Client sends the token via `Authorization` header in `_streamable_http_transport` (`mcp_session.py:736`).

## Related Docs

- `docs/mcp/overview.md`
- `docs/mcp/servers/exploit.md`
- `docs/mcp/security.md`
- `docs/mcp-wiring.md` — wiring companion with mermaid flow
