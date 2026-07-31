"""Shared dependencies and helpers for exploit MCP tool registration."""

from __future__ import annotations

import argparse
import asyncio
import functools
import hashlib
import inspect
import json
import os
import platform
import re
import shutil
import signal
import socket
import ssl as _ssl_module
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.api_key_store import (
    DEFAULT_API_KEY_FILE,
    disabled_research_tools_message,
    load_api_keys_into_env,
    research_api_keys_available,
)
from tools.attack_modules import list_modules, get_module, ModuleContext
from tools.attack_planner import (
    AttackPlanner,
    build_planning_prompt,
    build_replanning_prompt,
    parse_plan_json,
    parse_replan_json,
)
from tools.autonomous_orchestrator import (
    AutonomousOrchestrator,
    AggressionLevel,
    AttackPhase as OrchAttackPhase,
    TaskStatus,
)
from tools.config_manager import CONFIG_SCHEMA
from tools.credential_store import CredentialRecord, CredentialStore
from tools.cve_lookup import NVDClient, format_cve_results
from tools.exceptions import _EXC_GROUP_CATCH, _is_exception_group
from tools.experience_store import ExperienceStore
from tools.exploit_mutator import ExploitMutator
from tools.exploit_search import ExploitSearch
from tools.mcp_shared import (
    _attempt_dir,
    _extract_msf_rhosts,
    _find_file,
    _is_inside_workspace,
    _resolve_workspace_file,
    _run_with_pgrp_timeout as _shared_run_with_pgrp_timeout,
    build_cve_search,
    build_researcher,
    build_search,
    check_targets_allowlist,
    load_config,
    make_audit_tool,
    make_require_allowlist,
)
from tools.metasploit_bridge import MetasploitBridge, get_metasploit_bridge
from tools.payload_crafter import CraftedPayload
from tools.persistent_session_manager import PersistentSessionManager, get_session_manager
from tools.recon_pipeline import ReconPipeline, ReconConfig, HostReconResult
from tools.skill_registry import load_skill_registry, render_skill_context
from tools.validation_utils import (
    extract_ips_from_command,
    is_target_in_allowlist,
    preflight_command_check,
    validate_ipv4,
    validate_target,
    validate_target_or_ip,
    is_fqdn,
    resolve_target_to_ip,
    resolve_target,
)
from tools.web_researcher import WebResearcher
from db import DatabaseManager, get_default_db

_ORIGINAL_SUBPROCESS_RUN = subprocess.run


def _platform_system() -> str:
    if os.name == "nt":
        return "Windows"
    try:
        return platform.system()
    except Exception:
        return "Linux"


@dataclass(frozen=True)
class ToolContext:
    workspace: Path
    config: dict[str, Any] | None
    search: ExploitSearch
    nvd: NVDClient
    researcher: WebResearcher
    audit_tool: Any
    require_allowlist: Any


def _run_with_pgrp_timeout(*args: Any, **kwargs: Any) -> Any:
    """Compatibility-aware wrapper around the shared subprocess timeout helper.

    Some older tests monkeypatch ``mcp_exploit_server._run_with_pgrp_timeout``.
    Tool modules call this wrapper so that patch point still controls execution.
    """
    server_mod = sys.modules.get("mcp_exploit_server")
    override = getattr(server_mod, "_run_with_pgrp_timeout", None) if server_mod else None
    if override is not None and override is not _run_with_pgrp_timeout:
        return override(*args, **kwargs)
    if subprocess.run is not _ORIGINAL_SUBPROCESS_RUN:
        proc = subprocess.run(
            args[0] if args else kwargs.get("args"),
            stdout=kwargs.get("stdout"),
            stderr=kwargs.get("stderr"),
            cwd=kwargs.get("cwd"),
            env=kwargs.get("env"),
            input=kwargs.get("input_text"),
            timeout=args[1] if len(args) > 1 else kwargs.get("timeout"),
            text=kwargs.get("text"),
            encoding=kwargs.get("encoding"),
        )
        return proc.returncode, proc.stdout, proc.stderr
    return _shared_run_with_pgrp_timeout(*args, **kwargs)


_model_router_cache: Any = None
_model_router_init_attempted: bool = False
_model_router_lock = threading.Lock()

_consultation_count: int = 0
_consultation_lock = threading.Lock()


def _get_model_router_impl(config: dict[str, Any] | None) -> Any | None:
    """Lazily build and cache a ModelRouter from config. Returns None on failure."""
    global _model_router_cache, _model_router_init_attempted
    with _model_router_lock:
        if _model_router_init_attempted:
            return _model_router_cache
        _model_router_init_attempted = True
        try:
            from tools.model_router import build_router
            registry = (config or {}).get("models", {}).get("registry", {})
            host = (config or {}).get("ollama", {}).get("host", "http://localhost:11434")
            _model_router_cache = build_router(registry=registry if registry else None, host=str(host))
            return _model_router_cache
        except ImportError:
            return None
        except Exception:
            return None


def _get_model_router(config: dict[str, Any] | None) -> Any | None:
    """Compatibility-aware model-router lookup for moved peer-model tools."""
    server_mod = sys.modules.get("mcp_exploit_server")
    override = getattr(server_mod, "_get_model_router", None) if server_mod else None
    if override is not None and override is not _get_model_router:
        return override(config)
    return _get_model_router_impl(config)


def _get_model_client(config: dict[str, Any] | None) -> tuple[Any | None, str]:
    """Return (client, model_name) from the router for the default alias."""
    router = _get_model_router(config)
    if router is None:
        return None, ""
    default_alias = (config or {}).get("models", {}).get("default_alias", "glm")
    try:
        client = router.get_client(default_alias)
        return client, default_alias
    except Exception:
        return None, ""


def _resolve_consult_aliases(config: dict[str, Any] | None) -> list[str]:
    """Return the peer aliases the active model may consult.

    Intersection of ``multi_model.consult_aliases`` with the actually-registered
    ``models.registry`` aliases, minus the active ``default_alias`` (a model never
    consults itself). Preserves the order given in ``consult_aliases``.
    """
    cfg = config or {}
    mm = cfg.get("multi_model", {}) or {}
    requested = [str(a) for a in (mm.get("consult_aliases") or ["kimi", "deepseek", "deepseek_flash", "glm", "minimax"])]
    registry = cfg.get("models", {}).get("registry", {}) or {}
    active = os.environ.get("AI_NMAP_ACTIVE_MODEL_ALIAS") or cfg.get("models", {}).get("default_alias", "glm")
    available = set(registry.keys())
    return [a for a in requested if a in available and a != active]


def _env_bool(value: str | None) -> bool | None:
    """Parse a boolean environment override, returning None when unset/unknown."""
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return None


def _multi_model_enabled(config: dict[str, Any] | None) -> bool:
    """Return the effective peer-consult setting, honoring per-run env override."""
    override = _env_bool(os.environ.get("AI_NMAP_MULTI_MODEL_ENABLED"))
    if override is not None:
        return override
    return bool(((config or {}).get("multi_model", {}) or {}).get("enabled", False))


def _positive_int(value: Any, default: int) -> int:
    try:
        ivalue = int(value)
    except (TypeError, ValueError):
        return default
    return ivalue if ivalue > 0 else default


def _chat_content(response: Any) -> str:
    """Extract assistant text from an Ollama response-like object."""
    if isinstance(response, dict):
        message = response.get("message", {}) or {}
        if isinstance(message, dict):
            return str(message.get("content", "") or "")
        return str(getattr(message, "content", "") or "")
    message = getattr(response, "message", None)
    if isinstance(message, dict):
        return str(message.get("content", "") or "")
    if message is not None:
        return str(getattr(message, "content", "") or "")
    return str(response or "")


def _truncate_text(value: str, max_chars: int) -> str:
    text = str(value or "")
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n[truncated]"


def _skills_config(config: dict[str, Any] | None) -> dict[str, Any]:
    base = dict(CONFIG_SCHEMA.get("skills", {}) or {})
    overlay = ((config or {}).get("skills", {}) or {})
    if isinstance(overlay, dict):
        base.update(overlay)
    return base


def _runtime_skills_enabled(config: dict[str, Any] | None) -> bool:
    cfg = _skills_config(config)
    return bool(cfg.get("enabled", True) and cfg.get("allow_model_lookup", True))


def _ensure_workspace_dirs(workspace: Path) -> None:
    """Create standard subdirectories under the workspace."""
    for sub in ["plans", "exploits", "modules", "campaigns"]:
        (workspace / sub).mkdir(parents=True, exist_ok=True)



def read_workspace(workspace: Path, filename: str) -> str:
    """Read any file on the operator box by path.

    LAB BUILD: operator-box filesystem is unrestricted. The path-traversal,
    sensitive-credential, hardlink, and TOCTOU gates were removed -- the AI
    may inspect any path (e.g. /etc/hosts, workspace logs, loot). A 120k-char
    truncation guard is kept solely to avoid OOM on very large files; the
    returned text notes truncation.
    """
    raw = str(filename or "").strip()
    if not raw:
        return "BLOCKED: empty filename."
    target = Path(raw)
    if not target.is_absolute():
        workspace.mkdir(parents=True, exist_ok=True)
        target = workspace / raw
    if not target.exists() or not target.is_file():
        return f"FILE_NOT_FOUND: {Path(filename).name}"
    try:
        text = target.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return f"BLOCKED: could not read {filename!r}: {exc}"
    if len(text) > 120_000:
        text = text[:120_000] + "\n[truncated]"
    return text


def ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


# H4: scanner verbs whose first non-flag positional argument is the scan target.
# ``command_analyzer._NETVERB_HOST_RE`` covers ssh/nc/curl/... but omits scanners
# (nmap/masscan/rustscan/...), so a bare hostname target after a scanner would
# slip past the allowlist gate. This captures the first non-flag positional
# after a scanner verb so it is checked against the operator allowlist.
_SCANNER_TARGET_RE = re.compile(
    r"\b(?:nmap|masscan|rustscan|nikto|nuclei|gobuster|feroxbuster|sqlmap|"
    r"smbclient|enum4linux|hydra|whatweb|wpscan|dirb|dirbuster|amass|sublist3r)\b"
    r"(?:\s+-[^\s]+)*"
    r"\s+([^\s-][^\s]*)",
    re.IGNORECASE,
)



__all__ = [
    "AggressionLevel",
    "AttackPlanner",
    "AutonomousOrchestrator",
    "CONFIG_SCHEMA",
    "CraftedPayload",
    "CredentialRecord",
    "CredentialStore",
    "DEFAULT_API_KEY_FILE",
    "DatabaseManager",
    "ExperienceStore",
    "ExploitMutator",
    "ExploitSearch",
    "HostReconResult",
    "MetasploitBridge",
    "ModuleContext",
    "NVDClient",
    "OrchAttackPhase",
    "PersistentSessionManager",
    "ReconConfig",
    "ReconPipeline",
    "TaskStatus",
    "ToolContext",
    "WebResearcher",
    "build_cve_search",
    "build_planning_prompt",
    "build_replanning_prompt",
    "build_researcher",
    "build_search",
    "check_targets_allowlist",
    "disabled_research_tools_message",
    "extract_ips_from_command",
    "format_cve_results",
    "get_default_db",
    "get_metasploit_bridge",
    "get_module",
    "get_session_manager",
    "is_target_in_allowlist",
    "list_modules",
    "load_api_keys_into_env",
    "load_config",
    "load_skill_registry",
    "make_audit_tool",
    "make_require_allowlist",
    "parse_plan_json",
    "parse_replan_json",
    "preflight_command_check",
    "ps_quote",
    "read_workspace",
    "render_skill_context",
    "research_api_keys_available",
    "validate_ipv4",
    "validate_target",
    "validate_target_or_ip",
    "is_fqdn",
    "resolve_target_to_ip",
    "resolve_target",
    # ponytail: underscore-prefixed helpers used by runtime_skills.py via import *
    "_get_model_client",
    "_positive_int",
    "_runtime_skills_enabled",
    "_skills_config",
    "_truncate_text",
    # ponytail: stdlib modules and helpers used by terminal.py / metasploit.py / workspace.py / recon.py via import *
    "asyncio",
    "datetime",
    "json",
    "os",
    "Path",
    "re",
    "signal",
    "socket",
    "time",
    "timezone",
    "_ssl_module",
    "_attempt_dir",
    "_extract_msf_rhosts",
    "_platform_system",
    "_run_with_pgrp_timeout",
    "_SCANNER_TARGET_RE",
]
