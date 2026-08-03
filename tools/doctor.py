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
        "yaml", "ollama", "mcp", "uvicorn", "websockets",
        "questionary", "pytest",
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
        hint = (
            "install nmap (apt install nmap / brew install nmap) or set "
            "nmap.path in config.yaml to its full path"
        )
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
            "name": "linux_privilege", "ok": True, "value": f"euid={euid} (sudo enabled)",
            "note": "nmap.sudo=true: -O/-sS run via sudo -n (needs passwordless sudo)",
        }
    return {
        "name": "linux_privilege", "ok": True, "value": f"euid={euid} (non-root)",
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
    url = f"{host.rstrip('/')}/api/tags"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
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
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
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
    body = json.dumps({
        "model": spec,
        "prompt": "ok",
        "stream": False,
        "options": {"num_predict": 1},
    }).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8") or "{}")
        # Ollama returns an ``error`` field on unknown/unreachable cloud models.
        return "error" not in data
    except (urllib.error.URLError, OSError, ValueError):
        return False


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
            return {"name": f"port_{port}_free", "ok": False, "host": host, "port": port,
                    "in_use": True, "hint": hint}
        except OSError:
            return {"name": f"port_{port}_free", "ok": True, "host": host, "port": port}


def run_doctor(config_path: Path) -> int:
    import yaml

    print("=" * 60)
    print("  NetAttackAI - Self-Check (`--doctor`)")
    print("=" * 60)

    # Load config first (other checks may need it)
    config: dict[str, Any] = {}
    if config_path.exists():
        try:
            with config_path.open("r", encoding="utf-8") as handle:
                config = yaml.safe_load(handle) or {}
        except Exception as exc:
            print(f"  [!] Could not load {config_path}: {exc}")
    ollama_host = (config.get("ollama") or {}).get("host", "http://localhost:11434")
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
                    print(f"        -> cloud model not reachable: run it to register & verify: ollama run {spec}"
                          f" (cloud models aren't local weights — `ollama pull` only registers a pointer"
                          f" and isn't a real test; `ollama run` hits the cloud backend)")
                for spec in local_missing:
                    print(f"        -> pull missing local model: ollama pull {spec}")
        if name == "ollama_reachable" and not c.get("ok"):
            print("        -> start Ollama or update ollama.host in config.yaml")
        # Informational drill-downs (these checks never fail)
        if name == "linux_privilege" and c.get("note"):
            print(f"        -> {c['note']}")
        if name == "optional_tools":
            if c.get("present"):
                print(f"        -> present: {', '.join(c['present'])}")
            if c.get("missing"):
                print(f"        -> missing: {', '.join(c['missing'])} (apt/pip install as needed)")

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
    raise SystemExit(run_doctor(_p.parse_args().config))
