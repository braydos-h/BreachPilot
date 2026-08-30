"""`--doctor` self-check (Phase 2.4).

Runs a battery of diagnostics on the local environment and prints a
structured report. Exits 0 on success, 1 on any failure.

Checks:
  1. Python version >= 3.11
  2. Required third-party imports are importable
  3. nmap binary is on PATH
  4. Ollama is reachable (HTTP GET /api/tags)
  5. Models declared in config are reachable from Ollama
  6. Workspace directory is writable
  7. config.yaml parses and validates
  8. Default MCP ports are free
"""

from __future__ import annotations

import importlib
import json
import os
import shutil
import socket
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


def _check_python() -> dict[str, Any]:
    v = sys.version_info
    ok = (v.major, v.minor) >= (3, 11)
    result: dict[str, Any] = {
        "name": "python_version",
        "ok": ok,
        "value": f"{v.major}.{v.minor}.{v.micro}",
        "expected": ">= 3.11",
    }
    if not ok:
        result["hint"] = "Install Python >= 3.11 from https://www.python.org/downloads/"
    return result


def _check_imports() -> dict[str, Any]:
    required = [
        "yaml",
        "ollama",
        "mcp",
        "uvicorn",
        "websockets",
        "questionary",
        "pytest",
    ]
    missing: list[str] = []
    for mod in required:
        try:
            importlib.import_module(mod)
        except Exception:
            missing.append(mod)
    result: dict[str, Any] = {
        "name": "python_imports",
        "ok": not missing,
        "missing": missing,
    }
    if missing:
        result["hint"] = "Install missing deps: python -m pip install -r requirements.txt"
    return result


def _check_nmap(config: dict[str, Any] | None = None) -> dict[str, Any]:
    # Honor config.yaml's nmap.path override so a non-PATH nmap
    # (e.g. /usr/local/bin/nmap) is found. CLAUDE.md says nmap can be
    # "set in config.yaml"; this is what actually honors that.
    nmap_cfg = (config or {}).get("nmap", {}) or {}
    configured = str(nmap_cfg.get("path", "nmap")) or "nmap"
    path = shutil.which(configured)
    if not path:
        hint = "install nmap (apt install nmap / brew install nmap) or set nmap.path in config.yaml to its full path"
        return {"name": "nmap_binary", "ok": False, "error": f"nmap '{configured}' not on PATH", "hint": hint}
    return {"name": "nmap_binary", "ok": True, "path": path}


def _check_linux_privilege() -> dict[str, Any]:
    """POSIX-only: report euid and whether root-only nmap scans will work.

    On Linux, nmap OS detection (-O) and SYN scans (-sS) need root or
    CAP_NET_RAW. The defensive server's run_nmap_service_scan uses -O, so a
    non-root user would hit a permission error unless nmap.sudo is enabled or
    the priv_fallback downgrades the flags. This check surfaces that clearly.
    """
    if os.name == "nt":
        return {"name": "linux_privilege", "ok": True, "value": "n/a (Windows)"}
    try:
        euid = os.geteuid()
    except AttributeError:
        return {"name": "linux_privilege", "ok": True, "value": "n/a"}
    sudo_on = bool(_DOCTOR_NMAP_CFG.get("sudo", False))
    if euid == 0:
        return {"name": "linux_privilege", "ok": True, "value": f"root (euid={euid})"}
    if sudo_on:
        return {
            "name": "linux_privilege",
            "ok": True,
            "value": f"euid={euid} (sudo enabled)",
            "note": "nmap.sudo=true: -O/-sS run via sudo -n (needs passwordless sudo)",
        }
    return {
        "name": "linux_privilege",
        "ok": True,
        "value": f"euid={euid} (non-root)",
        "note": "nmap -O/-sS need root. The server auto-downgrades them when unprivileged; set nmap.sudo: true or rerun as root to enable OS/SYN scans.",
    }


# Holds the nmap config slice between run_doctor() and _check_linux_privilege().
_DOCTOR_NMAP_CFG: dict[str, Any] = {}


def _check_optional_tools(config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Probe Kali tooling; report present/missing as INFO (never a failure).

    A Debian/Ubuntu attacker host won't have searchsploit/msfconsole/etc. by
    default. Failing the doctor on that would block a perfectly runnable
    read_only session, so we surface it as informational guidance instead.
    """
    exploit_cfg = (config or {}).get("exploit", {}) or {}
    probes = {
        "searchsploit": str(exploit_cfg.get("searchsploit_path", "searchsploit")),
        "msfconsole": str(exploit_cfg.get("msfconsole_path", "msfconsole")),
        "tmux": "tmux",
        "hydra": "hydra",
        "impacket-secretsdump": "impacket-secretsdump",
    }
    present: list[str] = []
    missing: list[str] = []
    for label, binary in probes.items():
        if shutil.which(binary):
            present.append(label)
        else:
            missing.append(label)
    return {
        "name": "optional_tools",
        "ok": True,  # informational only
        "value": f"{len(present)}/{len(probes)} present",
        "present": present,
        "missing": missing,
    }


def _check_ollama(host: str, timeout: float = 3.0) -> dict[str, Any]:
    """Ping ``/api/tags`` to confirm the Ollama backend (local or cloud) is up.

    Cloud hosts (``https://api.ollama.com``) require ``Authorization: Bearer
    $OLLAMA_API_KEY`` — without it the request 401s and is reported unreachable.
    Local daemons ignore the header, so sending it unconditionally is safe.
    """
    url = f"{host.rstrip('/')}/api/tags"
    req = urllib.request.Request(url)
    api_key = (os.environ.get("OLLAMA_API_KEY", "") or "").strip()
    if api_key:
        req.add_header("Authorization", f"Bearer {api_key}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        models = [m.get("name") for m in data.get("models", [])]
        return {"name": "ollama_reachable", "ok": True, "host": host, "models": models}
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return {"name": "ollama_reachable", "ok": False, "host": host, "error": str(exc)}


def _check_models(host: str, configured: list[str], timeout: float = 3.0) -> dict[str, Any]:
    """Verify each configured model is reachable from Ollama.

    ``configured`` is a list of model *specs* as written in config.yaml's
    ``models.registry`` *values* (e.g. ``"kimi-k2.6:cloud"``), NOT the registry
    keys/aliases (``"kimi"``). The old code compared aliases against the
    untagged base names reported by ``/api/tags`` (``"kimi-k2.6"``), so an alias
    like ``"kimi"`` never matched and *every* configured model was reported
    missing -- a false-negative that masked the real state of the registry.

    A spec is considered present when Ollama lists either the full
    ``name:tag`` form or the untagged base ``name``.
    """
    url = f"{host.rstrip('/')}/api/tags"
    req = urllib.request.Request(url)
    api_key = (os.environ.get("OLLAMA_API_KEY", "") or "").strip()
    if api_key:
        req.add_header("Authorization", f"Bearer {api_key}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        return {"name": "model_registry", "ok": False, "error": str(exc)}
    available_full = {m.get("name", "") for m in data.get("models", [])}
    available_base = {n.split(":")[0] for n in available_full if n}

    def _present(spec: str) -> bool:
        base = (spec or "").split(":")[0]
        return bool(spec) and (spec in available_full or base in available_base)

    missing = [spec for spec in configured if not _present(spec)]
    return {
        "name": "model_registry",
        "ok": not missing,
        "available": sorted({x for x in available_full if x}),
        "configured": configured,
        "missing": missing,
    }


def _is_cloud_spec(spec: str) -> bool:
    """True for Ollama Cloud models (e.g. ``glm-5.2:cloud``, ``gpt-oss:20b-cloud``).

    Cloud models aren't local weights — ``ollama pull`` only registers a
    pointer and on some installs hangs or reports failure, so the doctor must
    not advise pulling them. They're verified by *running* them (a real
    generation through the cloud backend), which is what ``_ping_cloud_model``
    does and what the operator-facing hint tells the user to do.
    """
    tag = (spec or "").split(":")[-1].lower()
    return tag.endswith("cloud")


def _ping_cloud_model(host: str, spec: str, timeout: float = 45.0) -> bool:
    """Run a 1-token generation against a cloud model to register + verify it.

    This is the programmatic equivalent of ``ollama run <spec>`` — the only
    real test that a cloud model is reachable from the operator's Ollama
    daemon. Unlike ``ollama run``/``pull``, a raw generate call does not cache
    the model in ``/api/tags``, so this verifies reachability without leaving
    a pointer behind. Any error (unknown model, cloud auth missing, timeout)
    → False.
    """
    url = f"{host.rstrip('/')}/api/generate"
    body = json.dumps(
        {
            "model": spec,
            "prompt": "ok",
            "stream": False,
            "options": {"num_predict": 1},
        }
    ).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    api_key = (os.environ.get("OLLAMA_API_KEY", "") or "").strip()
    if api_key:
        req.add_header("Authorization", f"Bearer {api_key}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8") or "{}")
        # Ollama returns an ``error`` field on unknown/unreachable cloud models.
        return "error" not in data
    except (urllib.error.URLError, OSError, ValueError):
        return False


def _check_chatgpt(config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Check the ChatGPT (openai-oauth) provider readiness.

    Never reads or prints OAuth token contents — only checks file existence.
    Sub-checks: provider configured, openai-oauth source present, runtime (bun
    or node) on PATH, OAuth login present, proxy /health up, /v1/models
    reachable. Aggregated ``ok`` is True only when the proxy is reachable AND
    models list non-empty (the operator can still run with auth missing — the
    hint tells them to sign in).
    """
    import shutil as _shutil

    from tools.config_manager import get_chatgpt_config

    cfg = get_chatgpt_config(config)
    host = str(cfg.get("host") or "127.0.0.1")
    port = int(cfg.get("port") or 10531)
    root = f"http://{host}:{port}"
    repo = Path(str(cfg.get("local_repo") or "./oauth"))
    if not repo.is_absolute():
        repo = Path.cwd() / repo
    entry = repo / "packages" / "openai-oauth" / "src" / "cli.ts"

    sub: list[dict[str, Any]] = []
    sub.append({"name": "provider_configured", "ok": bool(cfg.get("enabled")) or True})
    sub.append({"name": "openai_oauth_source", "ok": entry.exists(), "path": str(entry)})
    bun = _shutil.which("bun")
    node = _shutil.which("node")
    runtime = "bun" if bun else ("node" if node else "")
    sub.append({"name": "runtime", "ok": bool(runtime), "runtime": runtime or "none"})
    # Auth file existence only — NEVER read contents.
    auth_exists = False
    codex_home = os.environ.get("CODEX_HOME")
    candidates = []
    if codex_home:
        candidates.append(os.path.join(codex_home, "auth.json"))
    candidates.append(os.path.join(os.path.expanduser("~"), ".codex", "auth.json"))
    auth_exists = any(os.path.exists(p) for p in candidates)
    sub.append({"name": "oauth_login", "ok": auth_exists})

    # Proxy /health + /v1/models via urllib (consistent with the rest of doctor).
    proxy_ok = False
    try:
        with urllib.request.urlopen(f"{root}/health", timeout=2.0) as resp:
            proxy_ok = resp.status < 500
    except Exception:
        proxy_ok = False
    sub.append({"name": "proxy_running", "ok": proxy_ok, "url": f"{root}/health"})

    models_ok = False
    models: list[str] = []
    if proxy_ok:
        try:
            req = urllib.request.Request(f"{root}/v1/models")
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                data = json.loads(resp.read().decode("utf-8") or "{}")
            models = [str(m.get("id", "")) for m in data.get("data", []) if m.get("id")]
            models_ok = bool(models)
        except Exception:
            models_ok = False
    sub.append({"name": "models_reachable", "ok": models_ok, "models": models})

    ok = proxy_ok and models_ok
    hint = ""
    if not auth_exists:
        hint = "Sign in via the interactive menu ('Sign in with ChatGPT') or `python main.py --doctor` after login."
    elif not proxy_ok:
        hint = f"Proxy down at {root}/health — start it via the menu or POST /api/v1/providers/chatgpt/proxy/start."
    elif not models_ok:
        hint = f"Proxy up but /v1/models returned no models at {root}/v1/models."
    if not entry.exists():
        hint = (
            hint + " " if hint else ""
        ) + "openai-oauth source not found — clone EvanZhouDev/openai-oauth into oauth/ and run `bun install`."
    return {"name": "chatgpt_provider", "ok": ok, "subchecks": sub, "hint": hint, "runtime": runtime, "models": models}


def _check_opencode_go(config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Check the OpenCode Go (Responses API) provider readiness.

    Never logs the API key.  Sub-checks: provider configured, API key present,
    base_url syntactically valid, ``GET {base_url}/models`` reachable, default
    model present, ``/responses`` configuration valid (base_url + model).
    Aggregated ``ok`` requires key present, models reachable, and default
    present — otherwise the operator sees a clear auth or reachability hint.
    """
    from tools.config_manager import get_opencode_go_config

    cfg = get_opencode_go_config(config)
    base_url = str(cfg.get("base_url") or "https://opencode.ai/zen/go/v1").rstrip("/")
    env_name = str(cfg.get("api_key_env") or "OPENCODE_GO_API_KEY")
    api_key = (os.environ.get(env_name, "") or "").strip()
    default_model = str(cfg.get("default_model") or "muse-spark-1.2-contributor")

    sub: list[dict[str, Any]] = []
    sub.append({"name": "provider_configured", "ok": bool(cfg.get("enabled")) or True})
    sub.append({"name": "base_url", "ok": bool(base_url), "value": base_url})
    sub.append({"name": "api_key_present", "ok": bool(api_key), "env": env_name})
    sub.append({"name": "default_model", "ok": bool(default_model), "value": default_model})

    # Probe /models
    models_ok = False
    models: list[str] = []
    models_error: str = ""
    if api_key:
        try:
            req = urllib.request.Request(f"{base_url}/models", headers={"Authorization": f"Bearer {api_key}"})
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                data = json.loads(resp.read().decode("utf-8") or "{}")
            raw = data.get("data") if isinstance(data, dict) else None
            if isinstance(raw, list):
                models = [str(m.get("id", "")) for m in raw if isinstance(m, dict) and m.get("id")]
                models_ok = True  # reachable counts even if list empty (discovery failure + fallback still usable)
            else:
                models_ok = False
                models_error = "unexpected shape"
        except Exception as exc:
            txt = str(exc)
            if api_key and api_key in txt:
                txt = txt.replace(api_key, "[REDACTED]")
            models_error = txt[:300]
            models_ok = False
    else:
        models_error = f"API key not set ({env_name})"

    sub.append(
        {
            "name": "models_reachable",
            "ok": models_ok,
            "models": models[:20],
            "error": models_error,
            "url": f"{base_url}/models",
        }
    )

    default_present = bool(default_model and (default_model in models if models else True))
    # When discovery returned empty but key present, we still consider default valid (fallback path)
    if not models and api_key:
        default_present = True
    sub.append({"name": "default_model_present", "ok": default_present, "value": default_model})

    # /responses config valid: base_url ends with v1 + model non-empty
    responses_ok = bool(base_url) and bool(default_model)
    sub.append({"name": "responses_config", "ok": responses_ok, "url": f"{base_url}/responses", "model": default_model})

    ok = bool(api_key) and models_ok and default_present and responses_ok
    hint = ""
    if not api_key:
        hint = f"Set {env_name} via env or secr.json (python main.py --setup-api-keys). Get a key at https://opencode.ai/zen/go."
    elif not models_ok:
        hint = f"OpenCode Go /models unreachable at {base_url}/models — check base_url, API key, and network."
    elif not default_present:
        hint = f"Default model {default_model!r} not in discovered list — check opencode_go.default_model or opencode_go.models."
    return {
        "name": "opencode_go_provider",
        "ok": ok,
        "subchecks": sub,
        "hint": hint,
        "models": models,
        "base_url": base_url,
    }


def _check_workspace(workspace: Path) -> dict[str, Any]:
    try:
        workspace.mkdir(parents=True, exist_ok=True)
        probe = workspace / ".doctor-probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return {"name": "workspace_writable", "ok": True, "path": str(workspace)}
    except OSError as exc:
        return {"name": "workspace_writable", "ok": False, "path": str(workspace), "error": str(exc)}


def _check_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"name": "config_valid", "ok": False, "path": str(path), "error": "missing"}
    try:
        from tools.config_manager import ConfigValidator

        # ConfigValidator takes a *path*, not a dict -- passing a dict makes
        # ``Path(data)`` raise TypeError, which the old code swallowed via a
        # bare ``except`` and degraded to ``ok = isinstance(data, dict)``,
        # yielding a false-green for any parseable YAML (even a broken one).
        # ``load_and_validate`` reads + parses + validates in one call and
        # surfaces real errors (type mismatches, etc.) instead.
        validator = ConfigValidator(path)
        _config, result = validator.load_and_validate()
        return {
            "name": "config_valid",
            "ok": result.is_valid,
            "path": str(path),
            "errors": list(result.errors),
            "warnings": list(result.warnings),
            "unknown_keys": list(result.unknown_keys),
        }
    except Exception as exc:
        # YAML parse error, non-mapping root, etc. -- a genuine failure, not a
        # silent pass. Report it so the operator sees the config is broken.
        return {"name": "config_valid", "ok": False, "path": str(path), "error": str(exc)}


def _check_port(host: str, port: int) -> dict[str, Any]:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        try:
            sock.connect((host, port))
            hint = (
                f"Find the holder: `netstat -ano | findstr :{port}` (Windows) / "
                f"`lsof -i :{port}` (Linux/macOS); stop it or set mcp.http_port "
                f"in config.yaml to a free port."
            )
            return {"name": f"port_{port}_free", "ok": False, "host": host, "port": port, "in_use": True, "hint": hint}
        except OSError:
            return {"name": f"port_{port}_free", "ok": True, "host": host, "port": port}


def _check_sandbox(config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Sandbox readiness: Docker CLI, daemon reachability, worker image.

    When ``sandbox.enabled`` is true this check COUNTS toward failures: with
    the sandbox on, attack execution is fail-closed, so a missing daemon or
    worker image blocks every offensive command. When disabled it is an
    informational pass with a note (legacy host-execution mode).
    """
    sandbox_cfg = (config or {}).get("sandbox", {}) or {}
    enabled = bool(sandbox_cfg.get("enabled", False))
    image = str(sandbox_cfg.get("image", "breachpilot-sandbox:latest") or "breachpilot-sandbox:latest")
    result: dict[str, Any] = {"name": "sandbox", "enabled": enabled, "image": image}
    if not enabled:
        result["ok"] = True
        result["note"] = "sandbox disabled -- legacy host-execution mode (uncontained)"
        return result
    try:
        from tools.sandbox.docker_backend import docker_image_exists, docker_version
    except Exception as exc:  # noqa: BLE001 -- doctor must never crash on import
        result["ok"] = False
        result["error"] = f"sandbox subsystem import failed: {exc}"
        return result
    daemon_ok, daemon_reason = docker_version()
    if not daemon_ok:
        result["ok"] = False
        result["error"] = daemon_reason
        result["hint"] = (
            "Start Docker Desktop (Windows/macOS) or docker.io/docker-ce (Linux). "
            "With sandbox.enabled: true attack execution is blocked until the daemon "
            "is reachable (fail closed)."
        )
        return result
    try:
        image_ok = docker_image_exists(image)
    except Exception as exc:  # noqa: BLE001 -- image probe failure is a real failure
        result["ok"] = False
        result["error"] = str(exc)
        return result
    if not image_ok:
        result["ok"] = False
        result["error"] = f"sandbox image {image!r} not found"
        result["hint"] = f"Build it: docker build -t {image} docker/sandbox"
        return result
    result["ok"] = True
    result["value"] = image
    return result


def _collect_doctor_checks(config_path: Path) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    """Collect all doctor checks and config for JSON or human output."""
    import yaml

    config: dict[str, Any] = {}
    load_error: str | None = None
    if config_path.exists():
        try:
            with config_path.open("r", encoding="utf-8") as handle:
                config = yaml.safe_load(handle) or {}
        except Exception as exc:
            load_error = str(exc)
            config = {}
    ollama_host = (config.get("ollama") or {}).get("host", "https://api.ollama.com")
    models_cfg = config.get("models", {}).get("registry", {}) or {}
    configured_models = list(models_cfg.values())
    workspace = Path(config.get("research", {}).get("workspace_dir", "research_workspace"))
    mcp_http = int((config.get("mcp") or {}).get("http_port", 8001))
    web_port = 8080

    _DOCTOR_NMAP_CFG.clear()
    _DOCTOR_NMAP_CFG.update((config.get("nmap") or {}))

    checks: list[dict[str, Any]] = [
        _check_python(),
        _check_imports(),
        _check_nmap(config),
        _check_workspace(workspace),
        _check_config(config_path),
        _check_ollama(ollama_host),
        _check_models(ollama_host, configured_models),
        _check_port("127.0.0.1", mcp_http),
        _check_port("127.0.0.1", web_port),
    ]
    if os.name != "nt":
        checks.append(_check_linux_privilege())
        checks.append(_check_optional_tools(config))
    from tools.config_manager import get_ai_provider

    if get_ai_provider(config) == "chatgpt":
        checks.append(_check_chatgpt(config))
    if get_ai_provider(config) == "opencode_go":
        checks.append(_check_opencode_go(config))
    checks.append(_check_sandbox(config))

    # Self-heal missing cloud models: ping each via /api/generate
    for c in checks:
        if c.get("name") != "model_registry":
            continue
        missing = list(c.get("missing") or [])
        recovered: list[str] = []
        for spec in missing:
            if _is_cloud_spec(spec) and _ping_cloud_model(ollama_host, spec):
                recovered.append(spec)
        if recovered:
            still_missing = [s for s in missing if s not in set(recovered)]
            c["missing"] = still_missing
            c["ok"] = not still_missing
            c["registered_cloud"] = recovered

    info: dict[str, Any] = {"load_error": load_error}
    return checks, config, info


def build_doctor_report(config_path: Path) -> dict[str, Any]:
    """Build machine-readable doctor report for --doctor --json / CI.

    Returns {checks:[{name, ok, error}], is_valid, unknown_keys, errors, warnings}
    for ``make doctor --json | jq -e '.is_valid'``.
    """
    checks, _config, _info = _collect_doctor_checks(config_path)
    # Derive unknown_keys and validation errors from the config_valid check
    unknown_keys: list[str] = []
    config_errors: list[str] = []
    config_warnings: list[str] = []
    for c in checks:
        if c.get("name") == "config_valid":
            unknown_keys = list(c.get("unknown_keys") or [])
            config_errors = list(c.get("errors") or [])
            if c.get("error"):
                config_errors.append(str(c.get("error")))
            config_warnings = list(c.get("warnings") or [])
            break
    # Also honour a YAML load error as invalid
    if _info.get("load_error"):
        config_errors.append(_info["load_error"])
    # Compact checks to {name, ok, error} for the spec, but keep full fields too
    compact_checks: list[dict[str, Any]] = []
    for c in checks:
        err = c.get("error")
        if err is None:
            # Prefer missing/errors/warnings as error string when not ok
            if not c.get("ok"):
                err = c.get("missing") or c.get("errors") or c.get("warnings") or ""
                if isinstance(err, list):
                    err = "; ".join(str(x) for x in err)
                err = str(err) if err else ""
            else:
                err = ""
        compact_checks.append(
            {"name": c.get("name", "unknown"), "ok": bool(c.get("ok")), "error": str(err) if err else ""}
        )
    # Exclude informational optional_tools / linux_privilege from failure count
    optional_names = {"optional_tools", "linux_privilege"}
    failed = sum(1 for c in checks if not c.get("ok") and c.get("name") not in optional_names)
    # config_valid ok already reflects is_valid, but strict unknown also fails via errors
    is_valid = failed == 0
    return {
        "checks": compact_checks,
        "full_checks": checks,
        "is_valid": is_valid,
        "unknown_keys": unknown_keys,
        "errors": config_errors,
        "warnings": config_warnings,
    }


def run_doctor(config_path: Path, json_output: bool = False) -> int:
    import yaml

    if json_output:
        report = build_doctor_report(config_path)
        # Strip full_checks for lean CI output; keep checks, is_valid, unknown_keys
        lean = {
            "checks": report["checks"],
            "is_valid": report["is_valid"],
            "unknown_keys": report["unknown_keys"],
            "errors": report["errors"],
            "warnings": report["warnings"],
        }
        print(json.dumps(lean, indent=2))
        return 0 if report["is_valid"] else 1

    print("=" * 60)
    print("  BreachPilot - Self-Check (`--doctor`)")
    print("=" * 60)

    # Load config first (other checks may need it)
    config: dict[str, Any] = {}
    if config_path.exists():
        try:
            with config_path.open("r", encoding="utf-8") as handle:
                config = yaml.safe_load(handle) or {}
        except Exception as exc:
            print(f"  [!] Could not load {config_path}: {exc}")
    ollama_host = (config.get("ollama") or {}).get("host", "https://api.ollama.com")
    models_cfg = config.get("models", {}).get("registry", {}) or {}
    # Pass the registry *values* (actual model specs like "kimi-k2.6:cloud"),
    # not the alias keys ("kimi") -- see _check_models docstring.
    configured_models = list(models_cfg.values())
    workspace = Path(config.get("research", {}).get("workspace_dir", "research_workspace"))
    mcp_http = int((config.get("mcp") or {}).get("http_port", 8001))
    web_port = 8080

    # Capture the nmap config slice for the (POSIX-only) privilege check.
    _DOCTOR_NMAP_CFG.clear()
    _DOCTOR_NMAP_CFG.update((config.get("nmap") or {}))

    checks: list[dict[str, Any]] = [
        _check_python(),
        _check_imports(),
        _check_nmap(config),
        _check_workspace(workspace),
        _check_config(config_path),
        _check_ollama(ollama_host),
        _check_models(ollama_host, configured_models),
        _check_port("127.0.0.1", mcp_http),
        _check_port("127.0.0.1", web_port),
    ]
    # Linux/macOS-only: privilege + optional Kali tooling. Informational, never
    # counts toward the failure total (a non-Kali Linux host is still runnable).
    if os.name != "nt":
        checks.append(_check_linux_privilege())
        checks.append(_check_optional_tools(config))
    # ChatGPT / OpenCode Go provider checks — only when selected, so the default (ollama)
    # doctor output is unchanged. Counts toward failures when that provider is selected.
    from tools.config_manager import get_ai_provider

    if get_ai_provider(config) == "chatgpt":
        checks.append(_check_chatgpt(config))
    if get_ai_provider(config) == "opencode_go":
        checks.append(_check_opencode_go(config))
    checks.append(_check_sandbox(config))

    failed = 0

    # Self-heal missing *cloud* models: ping each via /api/generate (the
    # programmatic ``ollama run`` — the only real test that a cloud model is
    # reachable). A successful ping verifies the cloud backend serves the
    # model, so the operator doesn't have to manually run every newly-
    # configured cloud model. The model isn't cached in /api/tags by a
    # generate call, so a future doctor run re-pings it (a cheap, real
    # verification — strictly stronger than the old /api/tags pointer check).
    # Local models are never auto-pulled (a real multi-GB download) — they
    # keep the pull hint below.
    for c in checks:
        if c.get("name") != "model_registry":
            continue
        missing = list(c.get("missing") or [])
        recovered: list[str] = []
        for spec in missing:
            if _is_cloud_spec(spec) and _ping_cloud_model(ollama_host, spec):
                recovered.append(spec)
        if recovered:
            still_missing = [s for s in missing if s not in set(recovered)]
            c["missing"] = still_missing
            c["ok"] = not still_missing
            c["registered_cloud"] = recovered

    for c in checks:
        status = "OK" if c.get("ok") else "FAIL"
        name = c.get("name", "unknown")
        value = c.get("value") or c.get("path") or c.get("host") or ""
        print(f"  [{status}] {name:<24} {value}")
        if not c.get("ok"):
            failed += 1
            err = c.get("error") or c.get("missing") or c.get("issues") or ""
            if err:
                print(f"        -> {err}")
            hint = c.get("hint")
            if hint:
                print(f"        -> {hint}")
        # Drill down on model registry
        if name == "model_registry":
            registered = c.get("registered_cloud") or []
            if registered:
                print(f"        -> verified cloud models by running a test generation: {', '.join(registered)}")
            missing = c.get("missing") or []
            if missing:
                cloud_missing = [s for s in missing if _is_cloud_spec(s)]
                local_missing = [s for s in missing if not _is_cloud_spec(s)]
                for spec in cloud_missing:
                    print(
                        f"        -> cloud model not reachable: run it to register & verify: ollama run {spec}"
                        f" (cloud models aren't local weights — `ollama pull` only registers a pointer"
                        f" and isn't a real test; `ollama run` hits the cloud backend)"
                    )
                for spec in local_missing:
                    print(f"        -> pull missing local model: ollama pull {spec}")
        if name == "ollama_reachable" and not c.get("ok"):
            print("        -> start Ollama, set OLLAMA_API_KEY, or update ollama.host in config.yaml")
        if name == "sandbox":
            if c.get("note"):
                print(f"        -> {c['note']}")
            elif c.get("ok"):
                print(f"        -> worker image ready: {c.get('image', '')} (attack commands run contained)")
        # Informational drill-downs (these checks never fail)
        if name == "linux_privilege" and c.get("note"):
            print(f"        -> {c['note']}")
        if name == "optional_tools":
            if c.get("present"):
                print(f"        -> present: {', '.join(c['present'])}")
            if c.get("missing"):
                print(f"        -> missing: {', '.join(c['missing'])} (apt/pip install as needed)")
        if name == "chatgpt_provider":
            for s in c.get("subchecks") or []:
                sstatus = "OK" if s.get("ok") else "FAIL"
                print(f"        -> [{sstatus}] {s['name']}")
            if c.get("models"):
                print(f"        -> discovered models: {', '.join(c['models'])[:200]}")
            if c.get("hint"):
                print(f"        -> {c['hint']}")
        if name == "opencode_go_provider":
            for s in c.get("subchecks") or []:
                sstatus = "OK" if s.get("ok") else "FAIL"
                extra = s.get("value") or s.get("env") or s.get("url") or ""
                print(f"        -> [{sstatus}] {s['name']}{' ' + str(extra) if extra else ''}")
                if s.get("error"):
                    print(f"              error: {s['error']}")
            if c.get("models"):
                print(f"        -> discovered models: {', '.join(c['models'])[:200]}")
            if c.get("base_url"):
                print(f"        -> base_url: {c['base_url']} (endpoint: /responses)")
            if c.get("hint"):
                print(f"        -> {c['hint']}")

    print("=" * 60)
    if failed == 0:
        print(f"  All {len(checks)} checks passed. You're ready to run.")
        return 0
    print(f"  {failed} of {len(checks)} checks failed.")
    return 1


if __name__ == "__main__":
    import argparse as _ap

    _p = _ap.ArgumentParser()
    _p.add_argument("--config", type=Path, default=Path("config.yaml"))
    _p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    _args = _p.parse_args()
    raise SystemExit(run_doctor(_args.config, json_output=_args.json))
