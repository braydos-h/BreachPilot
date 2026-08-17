# MCP Wiring

How the three MCP servers are launched, how clients connect over stdio and
streamable HTTP, how the exploit agent's tool-call layer dispatches into a
live `ClientSession`, and what happens when the MCP subprocess dies.

Companion docs: `docs/mcp-tools.md` (tool registration, decorators, audit
trail), `docs/architecture.md` (system shape), `docs/troubleshooting.md`
(symptom → fix), `CLAUDE.md` (boot sequence, permission model).

## The Three Servers

| Server | File | Role | Transport | Default port (HTTP) |
|---|---|---|---|---|
| Exploit | `mcp_exploit_server.py` | Permissive exploitation surface for the exploit agent / recon-first paths. ~90 tools across 16 families (`tools/mcp_tools/`). Target-IP allowlist lock + audit trail. | stdio (default) or streamable HTTP | `8001` (`mcp_exploit_server.py:206-208`) |
| Engine | `mcp_engine_server.py` | Read-only advisory + history surface for foreign assistants (Claude Desktop, Cursor): `search_skills`, `get_skill`, `cve_lookup`, `list_runs`, `get_run`. No target touching, no terminal (`mcp_engine_server.py:1-11`). | stdio (default) or streamable HTTP | `8002` (`mcp_engine_server.py:200-203`) |
| Defensive (legacy) | `mcp_server.py` | Scope-enforced Nmap scanning against `research.allowed_assets`; every tool checks `_is_in_allowlist` (`mcp_server.py:79-108`), terminal is allowlisted Nmap shapes only (`mcp_server.py:283-312`). | stdio (default) or streamable HTTP | `8000` (`mcp_server.py:346-349`) |

All three share one HTTP serving path — `tools.mcp_shared.run_mcp_http_server`
(`tools/mcp_shared.py:1064-1084`): it asserts the loopback gate, builds the
ASGI app via `mcp.streamable_http_app()`, wraps it with optional
`MCP_HTTP_TOKEN` bearer auth, and serves with uvicorn. The exploit server
delegates through a thin `run_http_server` wrapper
(`mcp_exploit_server.py:191-199`) and the engine/defensive servers call the
shared function directly (`mcp_engine_server.py:218`, `mcp_server.py:370`).

## Connection Flow

```text
operator ── python main.py --target <ip> --mode attack
   └─ main.py:open_exploit_mcp_session            (main.py:104-132)
       └─ tools/mcp_session.open_exploit_mcp_session (mcp_session.py:117)
           ├─ transport="http" (run path is ALWAYS forced to http,
           │    service.py:1059; --mcp-transport is ignored, main.py:353-354)
           │   └─ start_exploit_http_server        (mcp_session.py:609)
           │       └─ Popen: python mcp_exploit_server.py
           │            --transport http --host 127.0.0.1 --port <8001>
           │            --config config.yaml --workspace exploit_workspace
           │            (mcp_session.py:635-651, stdout→mcp_exploit_server.log)
           │       └─ wait_for_mcp_http_ready       (owned-child TCP listener)
           │       └─ _streamable_http_transport    (mcp_session.py:718; Bearer token)
           │       └─ ClientSession.initialize()    (mcp_session.py:486-497)
           │       └─ yield session  →  run_exploit_agent(loop.py) → call_tool
           └─ transport="stdio" (fallback / direct)
               └─ StdioServerParameters(python mcp_exploit_server.py
                    --transport stdio ...)          (mcp_session.py:288-297)
               └─ stdio_client(params) → ClientSession.initialize()
                    (mcp_session.py:315-330)
               └─ yield session

foreign assistant (Claude Desktop/Cursor)
   └─ (their own MCP client) → python mcp_engine_server.py --transport http --port 8002
        or --transport stdio (engine server has no in-repo client; the
        advisory surface is consumed by external hosts)

operator ── python mcp_server.py --transport http --host 127.0.0.1 --port 8000
   └─ defensive server, no in-repo client (Flow B cli.py path uses it historically)
```

The recon-first path opens the same exploit session with `soft_fail=True` so a
dead MCP server degrades to an `UNKNOWN` OS verdict instead of aborting
(`tools/run_service/service.py:921-935`).

## How Each Server Is Launched

### From CLI flags (standalone)

All three take identical flags (`mcp_exploit_server.py:202-214`,
`mcp_engine_server.py:197-208`, `mcp_server.py:342-354`):

```text
python mcp_exploit_server.py --transport stdio                # default
python mcp_exploit_server.py --transport http --host 127.0.0.1 --port 8001
python mcp_engine_server.py  --transport http --port 8002
python mcp_server.py         --transport http --port 8000
```

`--allow-public-bind` alone is not enough for a non-loopback bind — it also
requires `MCP_ALLOW_PUBLIC_BIND=1` (two-person rule, `tools/mcp_shared.py:1014-1030`).

Linux/macOS convenience targets: `make mcp-exploit`, `make mcp-defensive`,
`make mcp-engine` (`Makefile:41-48`). Windows: run the `python` commands
directly.

### From the exploit agent (the run path)

`main.py` → `AssessmentService.execute` → `_run_session`
(`service.py:1044-1067`) → `tools/exploit_session.run_exploit_session`
(`exploit_session.py:70`) → `open_exploit_mcp_session`
(`exploit_session.py:186-196`). The transport is **always `"http"`** here —
`service.py:1059` hardcodes it so the target-IP lock (env vars) reaches the
server process; `--mcp-transport` on `main.py:353` is documented as ignored
on the run path. The port comes from `mcp.http_port` (default 8001,
`config_manager.py:81`).

`open_exploit_mcp_session` (`tools/mcp_session.py:117-196`) tries the
requested transport first; **only HTTP-startup failures fall back to stdio**
(`mcp_session.py:160-195`). A live HTTP session is never replaced after it
has been yielded — that could repeat a partially completed tool call.

### From the WebUI

The `--web`/`--daemon`/`--demon` daemon (`main.py:509-560`) serves the FastAPI
app on loopback (`--api-host` must be 127.0.0.1/localhost/::1, `main.py:516`).
A run started via `POST /runs` executes through the same
`AssessmentService` (`tools/api/run_manager.py:202-258`), which opens the MCP
session exactly as the CLI run path does (HTTP transport, `service.py:1059`).
The manual tool gateway reuses the live session:
`POST /runs/{id}/tools/{name}/calls` → policy gate → `session.call_tool`
(`run_manager.py:358-387`). The session/schemas/policy reach the manager via
the `session_attach` callback (`run_manager.py:227-229`, `395-403`).

### From the swarm

The swarm never opens its own MCP session — it shares the one
`run_exploit_session` opens, via `SwarmMcpBridge` (`tools/swarm_bridge.py:1-37`).
`_setup_swarm` builds the bridge (`service.py:651-663`) and the attach
callback wires it with the live session + schemas + policy + main loop
(`service.py:697-709`). The swarm's `tool_executor` is `swarm_bridge.dispatch`
(`service.py:1020`); the swarm's Path A exploit agent runs `run_exploit_agent`
on the main loop via `run_coroutine_threadsafe`
(`tools/swarm/agents/exploit_agent.py:230-276`).

## How the Exploit Agent Dispatches Tool Calls

The loop (`tools/exploit_agent/loop.py`) does, per round:

1. **Phase-narrow the catalog** — `select_tools_for_phase` (`tool_catalog.py:102-133`)
   keeps the universal set plus the current phase's families
   (`PHASE_TOOL_FAMILIES`, `tool_catalog.py:93-99`), hidden control-plane tools
   excluded (`_HIDDEN`, `tool_catalog.py:83-90`), and intersects with the live
   MCP session's registered tool names (`loop.py:829-836`).
2. **Normalize + validate the model's tool calls** — `_filter_and_validate_tool_calls`
   (`tool_calls.py:328-379`) drops empty/malformed calls and validates each
   against its MCP schema via `validate_tool_call` (`tool_catalog.py:165-206`,
   required fields, primitive types, enums) so bad calls never waste an MCP
   round-trip.
3. **Policy gate** — `policy.approve_action(name, command)` (`loop.py:1158-1162`;
   `full_access` auto-approves; `read_only` proposes only). The one attack-mode
   safety — the target-IP allowlist lock — is enforced at the MCP tool layer,
   not here.
4. **Dispatch** — `session.call_tool(name, arguments=args)` (`loop.py:1229`),
   caught with `_EXC_GROUP_CATCH` and auto-corrected once on recoverable
   syntax/target errors via `_attempt_retry_correction` (`tool_calls.py:382-423`).
5. **Track outcome** — `_ToolOutcomeTracker` (`tool_calls.py:89-273`) counts
   blocked/unavailable results and feeds the terminal-constraint and
   peer-consult tripwires.

The tool schemas themselves come from `session.list_tools()` → converted to
Ollama function-call format by `mcp_tools_to_ollama` (`mcp_session.py:911-935`)
in `exploit_session.py:197-198`.

## Tool Catalog

`tools/exploit_agent/tool_catalog.py` is the phase-aware narrowing + local
schema-validation module:

- `PHASE_TOOL_FAMILIES` (`tool_catalog.py:93-99`) maps `recon` /
  `service_enumeration` / `vulnerability_research` / `validation` / `reporting`
  to `frozenset`s of tool names, always unioned with `_UNIVERSAL`
  (`tool_catalog.py:30-43`): shell, python file write/run, workspace reads,
  OS check, runtime skills, peer consult.
- `_HIDDEN` (`tool_catalog.py:83-90`) removes nested control-plane tools
  (`create_attack_plan`, `replan`, `start_autonomous_campaign`, package
  installers) the worker agent must not drive directly.
- `select_tools_for_phase` falls back to the full list when the phase is
  unknown or the filtered set would be empty (`tool_catalog.py:130-133`).
- `validate_tool_call` (`tool_catalog.py:165-206`) is intentionally lenient on
  unknown properties — MCP schemas are not strict JSON-Schema.

## The MCP Bridge Used by Swarm (`tools/swarm_bridge.py`)

`SwarmMcpBridge` adapts the sync swarm `tool_executor` shape to the async,
main-loop-bound MCP `ClientSession`:

- `attach(session, schemas, policy, loop)` (`swarm_bridge.py:46-56`) stashes
  the live session and the running loop — the swarm's recon loop runs in a
  worker thread (`asyncio.to_thread`), the session belongs to the main loop.
- `dispatch(name, args)` (`swarm_bridge.py:103-133`) is the sync entry point:
  builds the analysis payload, runs `policy.approve_action` on the main loop
  via `asyncio.run_coroutine_threadsafe` (`_run_async`, `swarm_bridge.py:61-67`),
  then `session.call_tool`. Denials return `BLOCKED:`; transport failures
  return `TOOL_EXECUTION_ERROR:` (both wrapped in `_EXC_GROUP_CATCH`).
- `_extract_text` (`swarm_bridge.py:69-101`) pulls text blocks out of an MCP
  `call_tool` result, mirroring the agent loop's extraction.
- Single-session invariant: the swarm shares the ONE session the session
  runner opens — it never spawns a second one (`swarm_bridge.py:33-36`).
- Regression tests: `tests/test_swarm_mcp_bridge.py` (dispatch from a worker
  thread, deny path, pre-attach BLOCKED).

## Env Vars Reaching the MCP Server Process

`_open_exploit_mcp_session_once` copies the parent env and injects
(`tools/mcp_session.py:254-270`); both stdio and HTTP children inherit it
(`StdioServerParameters(env=env)` `mcp_session.py:288-297`; `Popen(env=env)`
`mcp_session.py:635-651`):

| Env var | Set where | Consumed where |
|---|---|---|
| `EXPLOIT_TARGET` | `mcp_session.py:255` — the operator's literal `--target` (IP or domain). Primary allowlist-lock identity. | `mcp_shared._allowed_target_list` `mcp_shared.py:523`; `terminal._target_lock_block` `terminal.py:57` |
| `EXPLOIT_TARGET_IP` | `mcp_session.py:265` — resolved IP for a domain `--target` | `mcp_shared.py:523` |
| `EXPLOIT_TARGET_DOMAIN` | `mcp_session.py:266` — the domain string | `mcp_shared.py:523` |
| `EXPLOIT_DISCOVERED_TARGETS` | `mcp_shared.add_discovered_target` `mcp_shared.py:537-555` (subdomain expansion auto-authorizes) | `mcp_shared.py:528-533` |
| `EXPLOIT_WORKSPACE` | `mcp_session.py:256` — workspace root | `cve_lookup.py:171` (KEV cache), `mcp_tools/workspace.py:139` |
| `AI_NMAP_MULTI_MODEL_ENABLED` | `mcp_session.py:268` | `mcp_tools/registry.py:220` |
| `AI_NMAP_ACTIVE_MODEL_ALIAS` | `mcp_session.py:270` | `mcp_tools/registry.py:201`, `mcp_tools/peer_models.py:80` |
| `MCP_HTTP_TOKEN` | operator env (optional) | server: `run_mcp_http_server` `mcp_shared.py:1081`; client: `_streamable_http_transport` `mcp_session.py:706-725` |
| `MCP_ALLOW_PUBLIC_BIND` | operator env (optional) | `assert_loopback_bind` `mcp_shared.py:1022` |

The allowlist lock unions the env vars with `exploit.allowed_targets` at check
time (`mcp_shared.py:494-534`), so the runtime `--target` is authorized in the
server process without editing config.

## HTTP Transport Hardening (Shared)

All three servers share `run_mcp_http_server` (`tools/mcp_shared.py:1064-1084`):

1. **Loopback gate** — `assert_loopback_bind` (`mcp_shared.py:1014-1030`)
   refuses any non-loopback host unless BOTH `--allow-public-bind` AND
   `MCP_ALLOW_PUBLIC_BIND=1` are set (two-person rule).
2. **Optional bearer auth** — when `MCP_HTTP_TOKEN` is set, the ASGI app is
   wrapped by `_wrap_http_auth` (`mcp_shared.py:1033-1061`): a pure-ASGI
   middleware requiring `Authorization: Bearer <token>`, compared with
   `hmac.compare_digest` (no timing side channel); otherwise 401.
3. **The client side sends the token** — `_streamable_http_transport`
   (`mcp_session.py:717-737`) builds an httpx client with the Bearer header
   when `MCP_HTTP_TOKEN` is configured. It sets `trust_env=False` because this
   is always a loopback connection and must not be routed through an OS proxy.

## Exception-Group Handling (AGENTS.md rule 1)

Anyio task groups (used by `stdio_client`, `streamable_http_client`, and
`ClientSession`) raise `BaseExceptionGroup` on subprocess death — **not** an
`Exception` subclass — so bare `except Exception` silently misses real errors.
`tools/exceptions.py` provides the required helpers:

```python
from tools.exceptions import _EXC_GROUP_CATCH, _is_exception_group, _log_nested_exceptions

try:
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as session:
            await session.initialize()
except _EXC_GROUP_CATCH as exc:          # (Exception, BaseExceptionGroup) on 3.11+
    if _is_exception_group(exc):          # exceptions.py:15-19
        _log_nested_exceptions(exc)       # exceptions.py:22-35
    raise
```

`_EXC_GROUP_CATCH` degrades to `(Exception,)` below Python 3.11
(`tools/exceptions.py:38-41`). Correct call sites: `mcp_session.py:188, 361,
369, 518, 560, 568` (stdio boot, HTTP init, mid-session death), `loop.py:1230`,
`swarm_bridge.py:120, 128`, `run_manager.py:243, 380`, `service.py:729, 936`.

## Client Connection Snippet (in-repo client)

The canonical in-repo client is `open_exploit_mcp_session`
(`tools/mcp_session.py`). The stdio shape:

```python
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

server_params = StdioServerParameters(
    command=sys.executable,
    args=[str(server_path), "--transport", "stdio",
          "--config", str(config_path), "--workspace", str(workspace)],
    env=env,  # EXPLOIT_TARGET etc. -- see env table
)
async with stdio_client(server_params) as (read_stream, write_stream):
    async with ClientSession(read_stream, write_stream) as session:
        await asyncio.wait_for(session.initialize(), timeout=MCP_BOOT_TIMEOUT_SECONDS)
        tools = await session.list_tools()          # -> mcp_tools_to_ollama()
        result = await session.call_tool("run_exploit_terminal",
                                         arguments={"command": "id", "target_ip": target})
```

The HTTP shape (`mcp_session.py:718-737`):

```python
import httpx
from mcp.client.streamable_http import streamable_http_client

headers = {"Authorization": f"Bearer {token}"} if token else None
timeout = httpx.Timeout(30, read=300)
async with httpx.AsyncClient(headers=headers, timeout=timeout, trust_env=False) as client:
    async with streamable_http_client(url, http_client=client) as streams:
        async with ClientSession(*streams) as session:
            await session.initialize()
```

Boot is always capped at `MCP_BOOT_TIMEOUT_SECONDS` (30s, `mcp_session.py:32`)
via `asyncio.wait_for` on `initialize()`; the HTTP branch first waits for the
owned Uvicorn child's TCP listener, which opens only after application startup.
The real `ClientSession.initialize()` remains the authoritative MCP handshake.

## If the MCP Subprocess Dies

**Symptom A — session dies with no visible error; `except Exception` never fires.**
The anyio task group raised `BaseExceptionGroup`. Check `reports/<run_id>/session_error.log`
(`main.py:779` writes it via `_EXC_GROUP_CATCH`, `service.py:729-741`). Fix: catch
`_EXC_GROUP_CATCH` and unpack with `_log_nested_exceptions` (see above).

**Symptom B — recon-first run reports `MCP recon unavailable` / `UNKNOWN` verdict.**
Expected behavior: `soft_fail=True` degrades a dead MCP server to a minimal
assessment (`service.py:921-935`). If it instead *crashes*, a
`BaseExceptionGroup` escaped a soft-fail branch — the HTTP-branch soft-fail
gaps were fixed at `mcp_session.py:421-426, 456-467, 500-512, 530-540, 587-593`.

**Symptom C — "Exploit MCP HTTP port 8001 is already in use".**
An orphaned server from a previous run holds the port. `port_is_open` guard at
`mcp_session.py:617-620`; find and kill the holder
(`netstat -ano | findstr :8001`), or move `mcp.http_port` in config.yaml
(`tools/doctor.py:294-296`).

**Symptom D — boot timeout after 30s.**
The server imports heavy modules (exploit_search, cve_lookup, web_researcher,
recon_pipeline, attack_planner, metasploit_bridge) and can take 5–15s on a
cold start (`mcp_session.py:25-33`). A hung boot past 30s means the subprocess
is stuck, not slow — stdio yields `None` with `[WARN]` when `soft_fail`
(`mcp_session.py:332-348`).

**Symptom E — HTTP server started but session init fails.**
Startup errors append a bounded, credential-redacted tail of
`exploit_workspace/mcp_exploit_server.log` to the message
(`_server_log_tail`, `mcp_session.py:682-703`; secrets redacted via
`_redact_startup_text`, `mcp_session.py:668-679`). Check that log first.

**Symptom F — WebUI run stuck "running" forever.**
`_execute_run` catches `_EXC_GROUP_CATCH` (`run_manager.py:243-251`) so MCP
subprocess death marks the run FAILED instead of hanging. If a run hangs
anyway, the MCP session never died — check `GET /runs/{id}/events` and the
ticker output (`service.py:675-692`).

**Shutdown hygiene.** The HTTP child runs in its own process group
(`CREATE_NEW_PROCESS_GROUP` on Windows, `start_new_session` on POSIX,
`mcp_session.py:626-634`); `stop_process` (`mcp_session.py:841-880`) signals
the group, escalates to `taskkill /T /F` on Windows, and SIGKILLs the group on
POSIX so tool subprocesses die with the server.
