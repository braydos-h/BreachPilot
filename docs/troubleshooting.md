# Troubleshooting

Practical fixes for the failures you will actually hit, organized by symptom.
Every entry lists the symptom, the likely cause, an exact check command, and
an exact fix. When in doubt, start with the diagnostics table below — the
`--doctor` check names the failing subsystem and prints its own hint.

## Diagnostics at a glance

| Command | What it checks | Exit code |
|---|---|---|
| `python main.py --doctor` | Python >= 3.11, imports, nmap binary, workspace writable, config validity, Ollama reachability + model registry, MCP/WebUI port free, (Linux) root/sudo + Kali tooling | 0 = all pass, 1 = any fail (`tools/doctor.py:305`) |
| `python main.py --self-test` | Safe localhost-only smoke test; writes `reports/self_test_<run_id>/self_test_report.{json,md}` | 0 = pass, 1 = fail (`tools/self_test.py:65`) |
| `python -m pytest tests/ -v` | Full suite (~250 files, all mocked — no live nmap/network) | 0 = pass |
| `ruff check .` | Lint (line-length 120, E/F/W/I, E501 ignored) | 0 = clean |
| `python main.py --setup-api-keys` | Prompt for provider keys, save to `secr.json` (gitignored) | — |

`--doctor` and `--self-test` are mutually exclusive with each other and with
`--web`/`--demon`/`--menu`/`--demo`/`--eval` — combining them exits 2
(`main.py:838`).

## 1. Setup problems

### Python version too old

- **Symptom:** `--doctor` reports `[FAIL] python_version`.
- **Cause:** the doctor requires Python >= 3.11 (`tools/doctor.py:31`); the
  project metadata targets 3.10+ but 3.11+ is recommended.
- **Check:** `python --version`
- **Fix:** install Python >= 3.11 from https://www.python.org/downloads/ and
  recreate the venv:
  ```powershell
  python -m venv .venv
  .\.venv\Scripts\Activate.ps1
  python -m pip install -r requirements.txt
  ```

### Missing dependencies / import errors

- **Symptom:** `--doctor` reports `[FAIL] python_imports` listing `yaml`,
  `ollama`, `mcp`, `uvicorn`, `websockets`, `questionary`, `pytest`; or a
  startup `ModuleNotFoundError`.
- **Cause:** deps not installed in the active venv (`tools/doctor.py:45`).
- **Check:** `python -m pip list | findstr /i "ollama mcp uvicorn"` (Windows)
  or `python -m pip list | grep -iE "ollama|mcp|uvicorn"` (Linux/macOS)
- **Fix:**
  ```powershell
  python -m pip install -r requirements.txt
  python -m pip install -e ".[dev]"   # adds ruff + pytest + coverage
  ```
  If the MCP SDK import fails at session start you get
  `RuntimeError: The MCP Python SDK is not installed. Run: python -m pip install -r requirements.txt`
  (`tools/mcp_session.py:245`).

### nmap not found

- **Symptom:** `--doctor` reports `[FAIL] nmap_binary` with
  `nmap 'nmap' not on PATH`.
- **Cause:** nmap missing, or installed somewhere not on PATH.
- **Check:** `nmap --version` (or `where nmap` on Windows)
- **Fix:** install it, or point the doctor at it via config:
  ```bash
  # Debian/Ubuntu
  sudo apt install nmap
  # macOS
  brew install nmap
  ```
  ```yaml
  # config.yaml
  nmap:
    path: /usr/local/bin/nmap
  ```
  The doctor honors `nmap.path` (`tools/doctor.py:66`).

### nmap needs root on Linux (`-O` / `-sS` fail)

- **Symptom:** scans fail with `requires root` / `raw socket` /
  `cap_net_raw` / `must be run as root`; `--doctor` prints a
  `linux_privilege` note.
- **Cause:** OS detection (`-O`) and SYN scans (`-sS`) need root or
  CAP_NET_RAW. The defensive server's service scan uses `-O`
  (`tools/doctor.py:82`).
- **Check:** `id -u` (0 = root); `sudo -n true; echo $?` (0 = passwordless
  sudo works)
- **Fix:** one of:
  ```yaml
  # config.yaml — run root-only scans via sudo -n (needs passwordless sudo)
  nmap:
    sudo: true
  ```
  or run as root. Otherwise `nmap.priv_fallback` (default true) auto-downgrades
  `-sS` to `-sT` and strips `-O` with a note (`tools/nmap_priv.py:70`). With
  `sudo: true` and no passwordless sudo, `sudo -n` fails fast instead of
  hanging on a password prompt (`tools/nmap_priv.py:79`).

### OLLAMA_API_KEY missing → auth failure on first chat

- **Symptom:** `--doctor` reports `[FAIL] ollama_reachable` (401) against
  `https://api.ollama.com`; or the first LLM call fails with an auth error.
- **Cause:** the default model path is Ollama Cloud; the ollama client
  auto-attaches `Authorization: Bearer $OLLAMA_API_KEY` to every request, so
  a missing key 401s on the first chat (`tools/model_router.py:287`,
  `tools/doctor.py:145`). Keys are read from **process environment variables
  or `secr.json`** — there is no `.env` auto-load.
- **Check:** `echo $env:OLLAMA_API_KEY` (PowerShell) /
  `echo $OLLAMA_API_KEY` (bash); or `python main.py --doctor` and read the
  `ollama_reachable` line.
- **Fix:**
  ```bash
  python main.py --setup-api-keys      # prompts + writes secr.json (gitignored)
  ```
  or export it in your shell before running. Startup also loads saved keys
  from `secr.json` into the environment (`tools/api_key_store.py:199`,
  `tools/config_cli.py:175`).

### Cloud vs local Ollama host

- **Symptom:** you want a local daemon but the app keeps hitting the cloud;
  or the doctor pings the wrong host.
- **Cause:** `ollama.host` defaults to `https://api.ollama.com`; a host swap
  is the whole wiring — no probe, no local→cloud fallback
  (`tools/config_manager.py:30`, `tools/model_router.py:290`).
- **Check:** `python main.py --doctor` shows the host it pings.
- **Fix:**
  ```yaml
  # config.yaml
  ollama:
    host: http://localhost:11434
  ```
  Embeddings stay local by default via `ollama.embed_host` (falls back to
  `ollama.host` when absent). Local daemons ignore the Authorization header,
  so sending it unconditionally is safe (`tools/doctor.py:148`).

### Missing local model

- **Symptom:** `--doctor` reports `[FAIL] model_registry` with a
  `ollama pull <spec>` hint.
- **Cause:** a configured local model isn't pulled. Cloud models
  (`*:cloud`) are verified by a 1-token generation instead — `ollama pull`
  only registers a pointer and isn't a real test (`tools/doctor.py:206`,
  `tools/doctor.py:361`).
- **Check:** `ollama list`
- **Fix:** `ollama pull <spec>` for local models; for cloud models run
  `ollama run <spec>` once to register + verify. The doctor self-heals
  missing cloud models by pinging them via `/api/generate`
  (`tools/doctor.py:361`).

## 2. Startup failures

### config.yaml invalid

- **Symptom:** `--doctor` reports `[FAIL] config_valid` with a list of
  errors; or startup aborts with
  `ValueError: Config validation failed: ...`.
- **Cause:** YAML parse error, non-mapping root, or a type/range violation
  (e.g. `api.port` not in 1-65535, `eval.enabled` not a boolean). The
  validator reports per-key errors (`tools/config_manager.py:544`); the
  strict loader raises on any error (`tools/config_manager.py:1043`).
- **Check:**
  ```bash
  python main.py --doctor          # prints errors + warnings + unknown keys
  ```
  or directly:
  ```bash
  python -c "from tools.config_manager import validate_config_file; r = validate_config_file('config.yaml'); print(r.errors)"
  ```
- **Fix:** correct the reported keys in `config.yaml`. The doctor's
  `_check_config` uses the real validator — a parseable-but-broken YAML
  reports `ok: False`, not a false green (`tools/doctor.py:262`).

### Import error at startup

- **Symptom:** `ModuleNotFoundError` / `ImportError` before the menu shows.
- **Cause:** missing dep (see §1) or a broken editable install.
- **Check:** `python -c "import yaml, ollama, mcp, uvicorn, questionary"`
- **Fix:** `python -m pip install -r requirements.txt`; if that fails,
  reinstall editable metadata: `python -m pip install -e ".[dev]"`.

### Port already in use (MCP 8001 / WebUI 8765)

- **Symptom:** `--doctor` reports `[FAIL] port_8001_free` /
  `port_8080_free`; or session start fails with
  `Exploit MCP HTTP port 8001 is already in use. Stop the process using it.`
  (`tools/mcp_session.py:617`); or the daemon says it's "already running".
- **Cause:** an orphaned server or another app holds the port.
- **Check:** `netstat -ano | findstr :8001` (Windows) /
  `lsof -i :8001` (Linux/macOS) — the doctor prints this hint itself
  (`tools/doctor.py:294`).
- **Fix:** stop the holder, or move the port:
  ```yaml
  # config.yaml
  mcp:
    http_port: 8002
  api:
    port: 8766
  ```
  The WebUI daemon also refuses non-loopback binds:
  `--api-host must be loopback (127.0.0.1/localhost/::1)` (`main.py:516`,
  `tools/api/auth.py:30`).

## 3. Runtime failures

### MCP subprocess death hidden by `except Exception`

- **Symptom:** a session dies with no visible error, or an error that a bare
  `except Exception` should have caught never fires; the CLI prints
  `Exploitation session failed unexpectedly` and points at
  `reports/<run_id>/session_error.log` (`main.py:779`).
- **Cause:** anyio task groups raise `BaseExceptionGroup` (PEP 654) on
  subprocess death, which is **not** a subclass of `Exception`. Bare
  `except Exception` silently misses it.
- **Check:** the session error log; look for `ExceptionGroup` /
  `BaseExceptionGroup` in the traceback.
- **Fix:** any code wrapping `stdio_client` / `streamable_http_client` /
  `ClientSession.initialize()` must catch `_EXC_GROUP_CATCH` and unpack with
  `_is_exception_group` + `_log_nested_exceptions` from
  `tools/exceptions.py:15` (the tuple is `(Exception, BaseExceptionGroup)`
  on 3.11+, `tools/exceptions.py:38`). Reference pattern:
  ```python
  from tools.exceptions import _EXC_GROUP_CATCH, _is_exception_group, _log_nested_exceptions
  try:
      ...
  except _EXC_GROUP_CATCH as exc:
      if _is_exception_group(exc):
          _log_nested_exceptions(exc)
  ```
  Existing correct call sites: `main.py:779`, `tools/mcp_session.py:188`,
  `tools/api/run_manager.py:243`, `tools/exploit_agent/ollama_client.py:35`.

### LLM server disconnected / timeouts

- **Symptom:** `ERROR: LLM server disconnected after retries. Last error: ...`
  or repeated `[OLLAMA RETRY n/3]` lines.
- **Cause:** transient network errors (httpx `ReadTimeout`, `ConnectError`,
  `RemoteProtocolError`) against the Ollama backend.
- **Check:** `python main.py --doctor` (Ollama reachability); watch the
  retry lines — 3 retries with exponential backoff
  (`tools/exploit_agent/ollama_client.py:19`).
- **Fix:** confirm the backend is up and the key is set (§1); for long
  generations use `--long-session`, which raises the LLM call timeout
  (`config.yaml` `long_session.request_timeout_seconds`, default 600).
  Retryable errors are matched in
  `tools/exploit_agent/ollama_client.py:9`.

### Command timeouts

- **Symptom:** tools return `timed out after 300s` (terminal/python/msfvenom)
  or `secretsdump timed out after 300s` etc.
- **Cause:** the operational command timeout (default 300s terminal/python,
  600s msf) killed a long-running command.
- **Check:** `config.yaml` → `exploit.command_timeout_seconds` (default 300,
  `tools/config_manager.py:114`).
- **Fix:** raise the budget for the run:
  ```yaml
  exploit:
    command_timeout_seconds: 600
  ```
  or use `--long-session` which raises round/command/duration budgets
  (`tools/cli_exploit_settings.py:116`).

### No targets in allowlist → target lock blocks every tool

- **Symptom:** every target-touching tool returns
  `Target <ip> is not in the explicit allowlist. Add it to config.yaml exploit.allowed_targets to authorize.`
  or `require_explicit_allowlist is True but allowed_targets is empty`.
- **Cause:** the target-IP allowlist lock is the one attack-mode safety,
  enforced at the MCP tool layer, not in policy. The effective list is
  `exploit.allowed_targets` UNION the runtime env vars `EXPLOIT_TARGET`,
  `EXPLOIT_TARGET_IP`, `EXPLOIT_TARGET_DOMAIN`, `EXPLOIT_DISCOVERED_TARGETS`
  (`tools/mcp_shared.py:494`). With `require_explicit_allowlist: true` and an
  empty list, everything is blocked (`tools/mcp_shared.py:558`).
- **Check:** `python main.py --doctor` (config section); or
  ```bash
  python -c "from tools.mcp_shared import _allowed_target_list; print(_allowed_target_list(__import__('yaml').safe_load(open('config.yaml'))))"
  ```
- **Fix:** pass `--target <ip>` (it is unioned in via `EXPLOIT_TARGET`,
  `tools/mcp_session.py:255`), or add the host to config:
  ```yaml
  exploit:
    require_explicit_allowlist: true
    allowed_targets:
      - 10.0.0.50
      - 10.0.0.0/24        # CIDR and *.wildcard supported
  ```
  Callback/C2 hosts must be added explicitly; domain enumeration
  auto-authorizes discovered hosts via `add_discovered_target`
  (`tools/mcp_shared.py:537`). The lock itself lives in
  `tools/mcp_tools/terminal.py:57` (`_target_lock_block`).

### MCP server fails to boot (stdio/http)

- **Symptom:** `MCP HTTP server failed to start on port 8001: ...` or the
  boot spinner times out after 30s (`MCP_BOOT_TIMEOUT_SECONDS`,
  `tools/mcp_session.py:33`).
- **Cause:** the exploit server subprocess crashed at import, or the port is
  taken, or a heavy import exceeded the boot window.
- **Check:** the server log tail is printed in the error; also
  `exploit_workspace/<ip>/mcp_exploit_server.log`.
- **Fix:** fix the underlying import/port issue (§1, §2). The recon-first
  path tolerates MCP being unavailable (soft-fail → `[WARN]`, session
  degrades to a minimal assessment) but a hard import failure still aborts
  (`tools/mcp_session.py:228`).

## 4. Test failures

### Tests need live nmap / network

- **Symptom:** a test fails with `nmap not found` or tries to reach the
  network.
- **Cause:** you ran a test that isn't mocked — but the whole suite is
  designed to be offline. All ~250 tests mock subprocess/network; no live
  Nmap, no live network (README §Testing).
- **Check:** `python -m pytest tests/ -v`
- **Fix:** nothing to install. If a specific test still hits the network,
  it's a bug — report it. Run a single file:
  ```bash
  python -m pytest tests/test_doctor.py -v
  python -m pytest tests/ -v -k "scope"
  ```

### Async tests fail with "no running event loop" / coroutine warnings

- **Symptom:** `RuntimeError: no running event loop` or
  `coroutine ... was never awaited`.
- **Cause:** pytest isn't picking up the asyncio plugin config.
- **Check:** `pyproject.toml` has `asyncio_mode = "auto"` and
  `testpaths = ["tests"]` (`pyproject.toml:81`).
- **Fix:** ensure pytest + pytest-asyncio are installed:
  `python -m pip install -e ".[dev]"`. With `asyncio_mode = "auto"` you do
  not need `@pytest.mark.asyncio` on every test.

### Lint failures

- **Symptom:** `ruff check .` reports E/F/W/I violations.
- **Cause:** style drift; config is line-length 120, `select = ["E","F","W","I"]`,
  `ignore = ["E501"]`.
- **Check:** `ruff check .`
- **Fix:** `ruff check . --fix` for auto-fixable issues; manually fix the
  rest. No CI is configured — run it before a PR.

## 5. WebUI issues

### `webui/dist/` missing or stale

- **Symptom:** `--web` fails with `Node/npm not found on PATH` or
  `npm install exited 1`, or the SPA shows old content.
- **Cause:** first `--web` run builds `webui/dist/`; it needs Node.js + npm
  (`main.py:436`). The build is skipped when `dist/index.html` exists.
- **Check:** `Test-Path webui\dist\index.html` (Windows) /
  `test -f webui/dist/index.html` (Linux)
- **Fix:**
  ```bash
  cd webui
  npm install
  npm run build
  cd ..
  python main.py --web
  ```
  The auto-build runs `npm install --no-audit --no-fund` then
  `npm run build` with a 600s timeout (`main.py:449`).

### Port conflict / daemon already running

- **Symptom:** `WebUI API daemon is already running on http://127.0.0.1:8765`
  or bind errors.
- **Cause:** another daemon instance holds the port (default 8765,
  `tools/config_manager.py:468`).
- **Check:** `netstat -ano | findstr :8765` (Windows) /
  `lsof -i :8765` (Linux/macOS)
- **Fix:** stop the other instance, or change the port:
  ```yaml
  api:
    port: 8766
  ```
  `--api-port` overrides it per-run (`main.py:514`). Only one run can be
  active at a time — a second run returns HTTP 409
  (`tools/api/run_manager.py:120`).

### Token auth failures (401)

- **Symptom:** API/WebSocket calls return 401; the SPA can't connect.
- **Cause:** every route except `/health` requires a bearer token. The token
  is auto-generated into `.webui_secret_key` (gitignored) on first boot, or
  overridden by `BREACHPILOT_API_TOKEN` (`tools/api/auth.py:39`). WebSocket
  clients must send `{"auth": "<token>"}` as the first message or get closed
  with 4401 (`tools/api/auth.py:8`).
- **Check:** `Get-Content .webui_secret_key` (Windows) /
  `cat .webui_secret_key` (Linux)
- **Fix:** set a stable token:
  ```powershell
  $env:BREACHPILOT_API_TOKEN = "your-token"
  python main.py --web
  ```
  or delete `.webui_secret_key` to regenerate. The token is never logged or
  returned through the API.

## 6. Platform-specific

### Windows

- **Symptom:** `make install` / `make test` fail; exploit tools like
  `searchsploit`/`msfconsole` are missing.
- **Cause:** Makefile targets don't run on Windows (AGENTS.md §Commands);
  the Windows attacker profile is Python-only — the exploit agent's system
  prompt is OS-aware and pivots to workspace Python implementations
  (`tools/env_probe.py:43`).
- **Check:** `python main.py --doctor` — `linux_privilege` reports
  `n/a (Windows)` and `optional_tools` lists what's missing
  (informational, never a failure, `tools/doctor.py:114`).
- **Fix:** use the PowerShell commands from §1. For missing tools the agent
  writes Python fallbacks instead of attempting `apt_install` — the
  pre-flight probe tells it up front which tools to pivot on
  (`tools/env_probe.py:67`). `sudo` is never used on Windows
  (`tools/nmap_priv.py:91`, `tools/env_probe.py:54`).

### Linux / macOS

- **Symptom:** `-O`/`-sS` scans fail as non-root; `apt_install` hangs on a
  password prompt.
- **Cause:** root-only nmap flags (§1) and interactive sudo.
- **Check:** `id -u`; `sudo -n true; echo $?`
- **Fix:** set `nmap.sudo: true` (uses `sudo -n`, fails fast without
  passwordless sudo) or run as root. The tool layer pre-checks
  `_can_passwordless_sudo` and returns a `BLOCKED:` pivot message instead of
  spawning a hanging `sudo` (`tools/mcp_tools/terminal.py:97`). Full Kali
  arsenal (searchsploit/metasploit/hydra/crackmapexec/impacket) is expected
  on Linux; `scripts/setup-linux.sh` bootstraps venv + deps + doctor.
