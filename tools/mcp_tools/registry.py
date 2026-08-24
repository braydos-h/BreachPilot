"""Shared dependencies and helpers for exploit MCP tool registration."""
# NetAttackAI by @braydos-h — https://github.com/braydos-h/NetAttackAi

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import platform
import re
import shlex
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

from db import DatabaseManager, get_default_db
from tools.api_key_store import (
    DEFAULT_API_KEY_FILE,
    disabled_research_tools_message,
    load_api_keys_into_env,
    research_api_keys_available,
)
from tools.attack_modules import ModuleContext, get_module, list_modules
from tools.attack_planner import (
    AttackPlanner,
    build_planning_prompt,
    build_replanning_prompt,
    parse_plan_json,
    parse_replan_json,
)
from tools.autonomous_orchestrator import (
    AggressionLevel,
    AutonomousOrchestrator,
    TaskStatus,
)
from tools.autonomous_orchestrator import (
    AttackPhase as OrchAttackPhase,
)
from tools.config_manager import CONFIG_SCHEMA
from tools.credential_store import CredentialRecord, CredentialStore
from tools.cve_lookup import NVDClient, format_cve_results
from tools.experience_store import ExperienceStore
from tools.exploit_mutator import ExploitMutator
from tools.exploit_search import ExploitSearch
from tools.kernel.allowlist import _extract_scanner_targets
from tools.kernel.workspace import read_workspace
from tools.mcp_shared import (
    _attempt_dir,
    _extract_msf_rhosts,
    add_discovered_target,
    build_cve_search,
    build_researcher,
    build_search,
    check_targets_allowlist,
    load_config,
    make_audit_tool,
    make_require_allowlist,
)
from tools.mcp_shared import (
    _run_with_pgrp_timeout as _shared_run_with_pgrp_timeout,
)
from tools.metasploit_bridge import MetasploitBridge, get_metasploit_bridge
from tools.payload_crafter import CraftedPayload
from tools.persistent_session_manager import PersistentSessionManager, get_session_manager
from tools.recon_pipeline import HostReconResult, ReconConfig, ReconPipeline
from tools.skill_registry import load_skill_registry, render_skill_context
from tools.validation_utils import (
    extract_ips_from_command,
    is_fqdn,
    is_subdomain_of,
    is_target_in_allowlist,
    preflight_command_check,
    resolve_target,
    resolve_target_to_ip,
    validate_ipv4,
    validate_target,
    validate_target_or_ip,
)
from tools.web_researcher import WebResearcher

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
            from tools.config_manager import get_ai_provider, get_chatgpt_config
            from tools.model_router import build_router
            registry = (config or {}).get("models", {}).get("registry", {})
            host = (config or {}).get("ollama", {}).get("host", "http://localhost:11434")
            provider = get_ai_provider(config)
            kwargs: dict[str, Any] = {"host": str(host)}
            if registry:
                kwargs["registry"] = registry
            if provider == "chatgpt":
                kwargs["provider"] = "chatgpt"
                kwargs["chatgpt_config"] = get_chatgpt_config(config)
                kwargs["config"] = config
            _model_router_cache = build_router(**kwargs)
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


# Ponytail: single-source registry for MCP tool families.
# Each ``tools/mcp_tools/<family>.py`` defines ``register_<family>_tools(mcp, ctx)``.
# The old 2-place wiring (decorator + manual list in mcp_exploit_server.py) is
# collapsed to 1: ``mcp_exploit_server._discover_tool_registrars()`` walks the
# ``tools.mcp_tools`` package at import time and collects every
# ``register_*_tools`` callable. Adding a new family now requires only one file
# edit — create ``tools/mcp_tools/foo.py`` with ``register_foo_tools``; no edit
# to ``mcp_exploit_server.py`` or ``registry.py``.
_TOOL_REGISTRARS: list[Any] = []  # populated by _discover_tool_registrars on first use


def register_tool_family(fn: Any) -> Any:
    """Decorator for explicit registration (alternative to auto-discovery).

    Usage::

        @register_tool_family
        def register_foo_tools(mcp, ctx): ...

    The decorator appends ``fn`` to ``_TOOL_REGISTRARS`` and returns it
    unchanged. ``mcp_exploit_server.create_mcp_server`` also auto-discovers
    ``register_*_tools`` via package walk, so this decorator is optional —
    the single source is the function name, not the list.
    """
    if fn not in _TOOL_REGISTRARS:
        _TOOL_REGISTRARS.append(fn)
    return fn


def _discover_tool_registrars() -> list[Any]:
    """Auto-discover ``register_*_tools`` callables in ``tools.mcp_tools``.

    Walks ``tools.mcp_tools`` submodules, imports each, and collects callables
    named ``register_*_tools``. Result is cached in ``_TOOL_REGISTRARS`` after
    first call. Explicit ``@register_tool_family`` entries are merged in.
    """
    import importlib
    import pkgutil

    # Return cached if already populated via decorator or prior discovery
    if _TOOL_REGISTRARS:
        return list(_TOOL_REGISTRARS)
    try:
        import tools.mcp_tools as _pkg
    except ImportError:
        return []
    for _, modname, ispkg in pkgutil.iter_modules(_pkg.__path__):
        if ispkg:
            continue
        if modname == "registry":
            continue
        try:
            mod = importlib.import_module(f"tools.mcp_tools.{modname}")
        except Exception:
            continue
        for attr in dir(mod):
            if attr.startswith("register_") and attr.endswith("_tools"):
                fn = getattr(mod, attr, None)
                if callable(fn) and fn not in _TOOL_REGISTRARS:
                    _TOOL_REGISTRARS.append(fn)
    return list(_TOOL_REGISTRARS)



# -- Kernel re-exports (Phase 3) --
# read_workspace now lives in tools.kernel.workspace; re-export for backwards compat
# (from tools.mcp_tools.registry import read_workspace still works).
# See tools/kernel/workspace.py

def ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


# -- Kernel re-exports (Phase 3) --
# _extract_scanner_targets + helpers now live in tools.kernel.allowlist;
# re-export for backwards compat (from tools.mcp_tools.registry import _extract_scanner_targets still works).
# See tools/kernel/allowlist.py

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
    "add_discovered_target",
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
    "is_subdomain_of",
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
    "_extract_scanner_targets",
    # ponytail: Phase 2 collapsed registration — single source via _discover_tool_registrars
    "_TOOL_REGISTRARS",
    "register_tool_family",
    "_discover_tool_registrars",
    "Any",
]
