"""Shared configuration helpers for both MCP servers.

Centralizes the duplicated config-loading and builder logic that previously
lived in both ``mcp_server.py`` and ``mcp_exploit_server.py``.
"""

from __future__ import annotations

import functools
import inspect
import json
import os
import re
import secrets
import signal
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from tools.cve_lookup import CVESearchSettings, NVDClient
from tools.exploit_search import ExploitSearch, ExploitSearchSettings
from tools.reliability import RateLimiter
from tools.validation_utils import is_target_in_allowlist
from tools.web_researcher import (
    OllamaResearchSettings,
    SerpAPIResearchSettings,
    WebResearcher,
    WebResearcherSettings,
)


# Tier 1.8: process-wide shared NVD rate budget. Keyed by the configured
# per-minute rate so that concurrent MCP requests -- each of which calls
# build_cve_search() and would otherwise get its OWN NVDClient with its own
# per-instance 6s throttle -- instead share ONE token bucket, keeping the
# whole process within NVD's rate limit (not just each client instance).
# Module-level so the limiter survives across requests in a long-running
# HTTP-transport server. Loop-agnostic (threading.Lock based) so it is safe
# regardless of which event loop a caller runs in.
_SHARED_NVD_LIMITERS: dict[float, RateLimiter] = {}


def _shared_nvd_limiter(per_minute: float) -> RateLimiter:
    """Return the process-wide shared NVD RateLimiter for ``per_minute``,
    creating + caching it on first use."""
    lim = _SHARED_NVD_LIMITERS.get(per_minute)
    if lim is None:
        lim = RateLimiter.from_per_minute(per_minute, burst=1)
        _SHARED_NVD_LIMITERS[per_minute] = lim
    return lim


def load_config(path: Path) -> dict[str, Any]:
    """Load a YAML config mapping, returning an empty dict if missing."""
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}
    if not isinstance(loaded, dict):
        raise ValueError(f"{path} must contain a YAML mapping.")
    return loaded


def build_search(config: dict[str, Any]) -> ExploitSearch:
    """Build an ``ExploitSearch`` from the ``exploit``/``search`` config blocks."""
    exploit_cfg = config.get("exploit", {}) or {}
    research_cfg = config.get("research", {}) or {}
    search_cfg = config.get("search", {}) or {}
    serpapi_cfg = research_cfg.get("serpapi", {}) or {}

    def web_cfg(key: str, default: Any) -> Any:
        return serpapi_cfg.get(key, search_cfg.get(key, default))

    settings = ExploitSearchSettings(
        enabled=bool(exploit_cfg.get("enabled", False)),
        searchsploit_path=str(exploit_cfg.get("searchsploit_path", "searchsploit")),
        web_endpoint=str(web_cfg("endpoint", "https://serpapi.com/search.json")),
        web_engine=str(web_cfg("engine", "duckduckgo")),
        web_region=str(web_cfg("region", "us-en")),
        web_api_key_env=str(web_cfg("api_key_env", "SERPAPI_API_KEY")),
        web_timeout_seconds=int(research_cfg.get("timeout_seconds", search_cfg.get("timeout_seconds", 20))),
        web_max_results=int(research_cfg.get("max_results", search_cfg.get("max_results", 5))),
        cache_ttl_seconds=float(exploit_cfg.get("cache_ttl_seconds", 3600.0)),
        cache_max_entries=int(exploit_cfg.get("cache_max_entries", 50)),
        max_query_chars=int(exploit_cfg.get("max_query_chars", 200)),
    )
    return ExploitSearch(settings)


def build_cve_search(config: dict[str, Any]) -> NVDClient:
    """Build an NVD client from the ``cve_lookup`` config block.

    Tier 1.8: also wires a process-wide shared ``RateLimiter`` (built from
    ``cve_lookup.search_rate_limit_per_minute``, default 10/min = the ~6s NVD
    gap) so concurrent MCP requests share one NVD budget instead of each
    NVDClient hammering at its own per-instance gap. ``rate_limit_seconds``
    remains the per-instance FALLBACK used only when no shared limiter is
    passed (e.g. vuln_agent constructing NVDClient directly)."""
    cve_cfg = config.get("cve_lookup", {}) or {}
    settings = CVESearchSettings(
        enabled=bool(cve_cfg.get("enabled", True)),
        timeout_seconds=int(cve_cfg.get("timeout_seconds", 30)),
        max_results=int(cve_cfg.get("max_results", 5)),
        cache_ttl_seconds=int(cve_cfg.get("cache_ttl_seconds", 3600)),
        cache_max_entries=int(cve_cfg.get("cache_max_entries", 100)),
        rate_limit_seconds=float(cve_cfg.get("rate_limit_seconds", 6.0)),
        api_key_env=str(cve_cfg.get("api_key_env", "NVD_API_KEY")),
        circuit_failure_threshold=int(cve_cfg.get("circuit_failure_threshold", 5)),
        circuit_recovery_timeout=float(cve_cfg.get("circuit_recovery_timeout", 60.0)),
    )
    search_per_minute = float(cve_cfg.get("search_rate_limit_per_minute", 10))
    limiter = _shared_nvd_limiter(search_per_minute) if search_per_minute > 0 else None
    return NVDClient(settings, rate_limiter=limiter)


def build_researcher(config: dict[str, Any]) -> WebResearcher:
    """Build a web researcher from the ``research`` config block."""
    research_cfg = config.get("research", {}) or {}
    ollama_cfg = research_cfg.get("ollama", {}) or {}
    serpapi_cfg = research_cfg.get("serpapi", {}) or {}

    def list_cfg(key: str, default: list[str]) -> list[str]:
        value = research_cfg.get(key, default)
        return value if isinstance(value, list) else default

    settings = WebResearcherSettings(
        enabled=bool(research_cfg.get("enabled", True)),
        provider=str(research_cfg.get("provider", "ollama")),
        fallback_provider=str(research_cfg.get("fallback_provider", "serpapi")),
        timeout_seconds=int(research_cfg.get("timeout_seconds", 15)),
        max_results=int(research_cfg.get("max_results", 8)),
        max_fetch_depth=int(research_cfg.get("max_fetch_depth", 5)),
        max_content_chars=int(research_cfg.get("max_content_chars", 12000)),
        cache_ttl_seconds=float(research_cfg.get("cache_ttl_seconds", 1800.0)),
        cache_max_entries=int(research_cfg.get("cache_max_entries", 250)),
        min_source_quality=str(research_cfg.get("min_source_quality", "medium")),
        allow_local_fetch=bool(research_cfg.get("allow_local_fetch", False)),
        allowed_domains=list_cfg("allowed_domains", []),
        blocked_domains=list_cfg(
            "blocked_domains",
            [
                "doubleclick.net",
                "googleadservices.com",
                "googlesyndication.com",
                "facebook.com",
                "twitter.com",
                "instagram.com",
                "tiktok.com",
            ],
        ),
        ollama=OllamaResearchSettings(
            api_key_env=str(ollama_cfg.get("api_key_env", "OLLAMA_API_KEY")),
            max_results=int(ollama_cfg.get("max_results", research_cfg.get("max_results", 8))),
            use_web_search=bool(ollama_cfg.get("use_web_search", True)),
            use_web_fetch=bool(ollama_cfg.get("use_web_fetch", True)),
        ),
        serpapi=SerpAPIResearchSettings(
            api_key_env=str(serpapi_cfg.get("api_key_env", "SERPAPI_API_KEY")),
            endpoint=str(serpapi_cfg.get("endpoint", "https://serpapi.com/search.json")),
            engine=str(serpapi_cfg.get("engine", "duckduckgo")),
            region=str(serpapi_cfg.get("region", "us-en")),
        ),
    )
    return WebResearcher(settings)


# ── Exploit-server workspace / audit helpers ────────────────────────────────

def _is_inside_workspace(workspace: Path, target: Path) -> bool:
    root = workspace.resolve()
    try:
        target.resolve().relative_to(root)
        return True
    except ValueError:
        return False


def _find_file(workspace: Path, filename: str) -> Path | None:
    resolved = _resolve_workspace_file(workspace, filename)
    if not resolved.exists() or not resolved.is_file():
        return None
    # Tier 4: _resolve_workspace_file's candidate loop already gates on
    # _is_inside_workspace, but its rglob fallback (below) follows symlinks and
    # could return a path that resolves OUTSIDE the workspace (a ``link -> /etc``
    # inside the workspace). Re-assert here so non-read_workspace callers of
    # _find_file cannot receive an escaped path.
    root = workspace.resolve()
    try:
        if not _is_inside_workspace(root, resolved.resolve()):
            return None
    except OSError:
        return None
    return resolved


def _resolve_workspace_file(workspace: Path, filename: str, suffix: str | None = None) -> Path:
    """Resolve a workspace file by absolute path, relative path, or basename.

    Tool outputs often hand the model a full PATH. Older code discarded that
    path and looked only in a newly-created attempt directory, which made
    write_python_file -> run_python_file fail. This resolver keeps full and
    relative paths when they stay under the workspace, and falls back to the
    most recently modified basename match for legacy calls.
    """
    workspace.mkdir(parents=True, exist_ok=True)
    root = workspace.resolve()
    raw = str(filename or "").strip().strip("\"'")
    if not raw:
        return root / "__missing__"

    normalized = raw.replace("\\", "/")
    raw_path = Path(raw)
    candidates: list[Path] = []
    if raw_path.is_absolute():
        candidates.append(raw_path)
    elif "/" in normalized:
        candidates.append(root / normalized)

    safe_name = Path(normalized).name.lstrip("/").lstrip("\\")
    if safe_name:
        candidates.append(root / safe_name)

    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if not _is_inside_workspace(root, resolved):
            continue
        if resolved.is_file() and (suffix is None or resolved.name.endswith(suffix)):
            return resolved

    if not safe_name:
        return root / "__missing__"

    # Tier 4: rglob follows symlinks, so a ``link -> /etc`` inside the workspace
    # could yield a match that resolves OUTSIDE root. Filter every match through
    # _is_inside_workspace on its resolved path so the fallback cannot return an
    # escaped file (the candidate loop above already gates on this; this closes
    # the rglob path for non-read_workspace callers of _find_file).
    matches: list[Path] = []
    for candidate in root.rglob(safe_name):
        if not candidate.is_file() or (suffix is not None and not candidate.name.endswith(suffix)):
            continue
        try:
            resolved_cand = candidate.resolve()
        except OSError:
            continue
        if _is_inside_workspace(root, resolved_cand):
            matches.append(resolved_cand)
    if matches:
        return max(matches, key=lambda p: p.stat().st_mtime if p.exists() else 0)

    return root / safe_name


# ── Audit-log credential redaction ─────────────────────────────────────────
#
# The exploit audit trail (``exploit_audit.jsonl``) is append-only plaintext, so
# any credential / NTLM / Kerberos material the LLM supplies to ``lateral_exec``,
# ``dump_credentials``, or ``kerberoast`` would otherwise land on disk in
# cleartext. Every audit-log write site routes its ``bound.arguments`` through
# ``_redact_args``: the parameter *name* is kept (the trail still shows that a
# secret was supplied and which parameter carried it) but the *value* is masked.
# Matching is case-insensitive on the parameter name. Dict-valued args (e.g. an
# ``options`` map passed to ``run_msf_module`` / ``generate_payload``) are walked
# one level deep so a nested ``PASSWORD`` key is masked too.
_SECRET_ARG_NAMES = frozenset({
    # login / authentication material
    "password", "passwd", "pass", "passphrase",
    "secret", "shared_secret", "pre_shared_key", "secret_key", "signing_key",
    # NTLM / Kerberos material harvested by lateral_exec / dump_credentials / kerberoast
    "ntlm_hash", "ntlm", "hash",
    "kerberos_ticket", "asrep_key", "rc4_key", "aes_key",
    # bearer / session material
    "token", "auth_token", "access_token", "refresh_token", "session_key",
    "cookies", "authorization",
    # api keys
    "api_key", "apikey",
    # generic credential buckets
    "credential", "credentials", "creds",
    # private keys
    "private_key", "priv_key",
})

_REDACTED = "***REDACTED***"

# ── Inline-secret content masking ───────────────────────────────────────────
#
# Name-based redaction only masks a value when its *parameter* name is a secret
# name. Free-text fields the agent fills with a whole command/option string --
# ``command``, ``options``, ``input_text``, ``code``, ``script_content`` -- are
# never in ``_SECRET_ARG_NAMES``, so a credential embedded *inside* the value
# (``curl -u admin:s3cret``, ``impacket-secretsdump -hashes :NTLM``,
# ``SMBPass=hunter2``, ``password = "s3cret"``) leaked into the audit log in
# cleartext. ``_mask_secret_content`` scans the string value itself for the
# common inline-credential *shapes* and masks the secret part, keeping the
# keyword/flag so the trail still shows that a credential was supplied.
#
# This runs only on values destined for ``exploit_audit.jsonl`` (the audit log
# is write-only -- nothing reads it back for execution), so cosmetic
# over-redaction of a non-secret token is harmless; *under*-redaction (leaking
# a real secret) is the only failure that matters.
#
# scheme://user:pass@host  (URL-embedded basic auth -- masks the user:pass)
_MASK_URL_AUTH_RE = re.compile(r"(?<=://)[^@\s:/]+:[^@\s:/]+(?=@)", re.IGNORECASE)
# -u / --user user:pass  (curl/wget --user; colon form is unambiguously a cred)
_MASK_U_FLAG_RE = re.compile(
    r"((?<![\w-])(?:-u|--user)\s+)[^\s:]+:[^\s]+", re.IGNORECASE,
)
# --password / --passwd / --passphrase / --pass / --pwd / -pass <value>
_MASK_LONG_PW_RE = re.compile(
    r"((?<![\w-])(?:--password|--passwd|--passphrase|--pass|--pwd|-pass)\s+)[^\s]+",
    re.IGNORECASE,
)
# hydra/medusa ``-p <password>`` (in those tools ``-p`` is always the password,
# never a port -- scoping to the tool name avoids masking ``ssh -p 2222`` /
# ``nc -p 4444`` / ``nmap -p 80`` ports). crackmapexec/netexec/evil-winrm share
# the same ``-p`` password convention.
_MASK_HYDRA_P_RE = re.compile(
    r"(\b(?:hydra|medusa|crackmapexec|netexec|cme|evil-winrm)\b[^\n]*?(?<![\w-])-p\s+)[^\s]+",
    re.IGNORECASE,
)
# msf resource-script ``set SMBPass value`` (space-separated, not ``KEY=VALUE``)
_MASK_MSF_SET_RE = re.compile(
    r"(\bset\s+(?:SMBPass|PASSWORD|PASSWD|DbUserPass|DbPassword|DbPass|SECRET|SECRETKEY|"
    r"SECRET_KEY|TOKEN|API_KEY|APIKEY|NTLM_HASH|PRIVATE_KEY|PRIV_KEY|ACCESS_KEY|"
    r"AUTH_TOKEN|CREDENTIAL|DB_PASSWORD|DBPASS)\s+)[^\s]+",
    re.IGNORECASE,
)
# impacket ``-hashes LM:NT`` / ``:NT`` (empty LM) / bare NT
_MASK_HASHES_RE = re.compile(
    r"((?<![\w-])-hashes\s+)(?:[\da-fA-F]{16,}:[\da-fA-F]{16,}|:[\da-fA-F]{16,}|[\da-fA-F]{16,})",
    re.IGNORECASE,
)
# impacket ``-ntlm <hash>``
_MASK_NTLM_FLAG_RE = re.compile(
    r"((?<![\w-])-ntlm\s+)[\da-fA-F]{16,}", re.IGNORECASE,
)
# msf / config / code  SECRETKEY=VALUE (focused key list; group 1 captures the
# key plus the ``=``/spaces so the replacement keeps the ``=``; value excludes
# expression chars so ``password = os.environ[...]`` masks only the leading
# token, not the whole expression -- audit-only, so this is acceptable).
_MASK_KV_SECRET_RE = re.compile(
    r"\b((?:SMBPass|PASSWORD|PASSWD|DbUserPass|DbPassword|DbPass|SECRETKEY|SECRET_KEY|"
    r"SECRET|TOKEN|API_KEY|APIKEY|NTLM_HASH|PRIVATE_KEY|PRIV_KEY|ACCESS_KEY|"
    r"AUTH_TOKEN|CREDENTIAL|CREDENTIALS|DB_PASSWORD|DBPASS)\s*=\s*)"
    r"[^\s,;=.\[\(\$\{]+",
    re.IGNORECASE,
)
# Authorization: <scheme> <token>  (also inside ``-H "Authorization: ..."``)
_MASK_AUTH_HDR_RE = re.compile(
    r"(Authorization\s*:\s*(?:Basic|Bearer|Digest|Negotiate|NTLM)\s+)[^\s,;'\"]+",
    re.IGNORECASE,
)
# python requests ``auth=("user","pass")`` tuple
_MASK_PY_AUTH_TUPLE_RE = re.compile(
    r"(\bauth\s*=\s*\(\s*)[\"'][^\"']+[\"']\s*,\s*[\"'][^\"']+[\"'](\s*\))",
    re.IGNORECASE,
)

_MASK_RES = (
    _MASK_URL_AUTH_RE,
    _MASK_U_FLAG_RE,
    _MASK_LONG_PW_RE,
    _MASK_HYDRA_P_RE,
    _MASK_MSF_SET_RE,
    _MASK_HASHES_RE,
    _MASK_NTLM_FLAG_RE,
    _MASK_KV_SECRET_RE,
    _MASK_AUTH_HDR_RE,
    _MASK_PY_AUTH_TUPLE_RE,
)

# Free-text fields that are inherently credential-bearing and whose content
# cannot be reliably parsed for *which* token is the secret -- interactive
# session input (``admin\npassword\n``) is bare lines, not ``KEY=VALUE``, and
# ``cred_store_add``'s ``notes`` is free-text engagement context the model is
# encouraged to fill, which can mirror the secret (``"reused from ssh; plaintext
# is hunter2"``). ``_mask_secret_content`` only matches KNOWN inline-credential
# *shapes*, so a bare secret or prose in these fields would pass through to the
# append-only plaintext audit log in cleartext. The whole value is therefore
# masked in the audit log (audit-only; execution still uses the raw value).
_WHOLESALE_REDACT_FIELDS = frozenset({"input_text", "notes"})


def _mask_secret_content(value: Any) -> Any:
    """Mask inline-credential *shapes* inside a free-text string value.

    Returns non-strings unchanged. The scan is conservative by construction:
    every pattern targets a specific credential shape (URL ``user:pass@``,
    ``-u user:pass``, ``--password <v>``, ``-hashes <NT>``, ``SMBPass=v``,
    ``Authorization: Bearer <t>``, ``auth=(\"u\",\"p\")``) so a benign command
    like ``nmap -sV 10.0.0.50`` or a port like ``-p 4444`` is never altered.
    """
    if not isinstance(value, str) or not value:
        return value
    out = value
    for rx in _MASK_RES:
        if rx is _MASK_URL_AUTH_RE:
            out = rx.sub(_REDACTED, out)
        elif rx is _MASK_PY_AUTH_TUPLE_RE:
            out = rx.sub(rf"\1{_REDACTED}\2", out)
        else:
            out = rx.sub(rf"\1{_REDACTED}", out)
    return out


def _redact_nested(value: Any) -> Any:
    """Mask secret-named keys inside dict-valued args, and inline creds in any
    nested string value (one level deep).
    """
    if isinstance(value, dict):
        return {
            k: (
                _REDACTED
                if isinstance(k, str) and k.lower() in _SECRET_ARG_NAMES
                else _redact_nested(v)
            )
            for k, v in value.items()
        }
    if isinstance(value, str):
        return _mask_secret_content(value)
    return value


def _redact_args(args: dict[str, Any] | None) -> dict[str, Any]:
    """Return a copy of ``args`` with secret-named values masked for the audit log.

    Two layers: (1) values whose *parameter name* is a secret name are masked
    wholesale (see ``_SECRET_ARG_NAMES``); (2) any remaining string value is
    scanned for inline-credential *shapes* (``-u user:pass``, ``SMBPass=...``,
    ``Authorization: Bearer ...``, ``password = "..."``) so a credential
    embedded in a free-text ``command`` / ``options`` / ``code`` field is also
    masked -- name-based redaction alone misses those. A None or empty mapping
    yields an empty dict (matching the prior ``args or {}`` fallback).
    """
    if not args:
        return {}
    redacted: dict[str, Any] = {}
    for name, value in args.items():
        lname = name.lower() if isinstance(name, str) else ""
        if lname in _SECRET_ARG_NAMES:
            redacted[name] = _REDACTED
        elif lname in _WHOLESALE_REDACT_FIELDS and value:
            # Wholesale-redact non-empty free-text secret-bearing fields (notes,
            # input_text). An EMPTY value is left as-is so the audit log doesn't
            # show a misleading "***REDACTED***" for a field the caller left blank.
            redacted[name] = _REDACTED
        elif isinstance(value, str):
            redacted[name] = _mask_secret_content(value)
        else:
            redacted[name] = _redact_nested(value)
    return redacted


def _audit_log(
    audit_path: Path,
    *,
    target_ip: str,
    tool_name: str,
    approved: bool,
    status: str,
    command: str = "",
    args: dict[str, Any] | None = None,
    attempt_id: str = "",
    code_sha256: str = "",
    duration_seconds: float = 0.0,
) -> None:
    """Append an audit record to exploit_audit.jsonl."""
    import json as _json
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target_ip": target_ip,
        "tool_name": tool_name,
        "approved": approved,
        "status": status,
        # Mask inline creds in a free-text command (e.g. ``curl -u admin:pass``
        # passed directly to _audit_log) the same way _redact_args does for the
        # ``command`` arg, so the raw command field never leaks a secret.
        "command": _mask_secret_content(command) if command else "",
        "args": args or {},
        "attempt_id": attempt_id,
        "code_sha256": code_sha256,
        "duration_seconds": duration_seconds,
    }
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    with audit_path.open("a", encoding="utf-8") as handle:
        handle.write(_json.dumps(record, default=str) + "\n")


def _allowed_target_list(config: dict[str, Any] | None) -> list[str]:
    """The effective allowlist = config ``exploit.allowed_targets`` UNION the
    runtime target injected via the ``EXPLOIT_TARGET`` env var (set in
    ``tools/mcp_session.open_exploit_mcp_session`` to the ``--target`` IP).

    LAB BUILD: this union is the target-IP lock. An empty config list is the
    lab default -- the runtime ``--target`` is auto-authorized, so the AI is
    locked to the single target it was launched against without per-run config
    edits. Extra operator-authorized hosts (e.g. a callback/C2 listener) may be
    added to ``exploit.allowed_targets`` on top of the runtime target.
    """
    exploit_cfg = (config or {}).get("exploit", {})
    allowed = list(exploit_cfg.get("allowed_targets", []))
    env_target = os.environ.get("EXPLOIT_TARGET", "").strip()
    if env_target:
        allowed.append(env_target)
    return allowed


def _check_allowlist(target_ip: str, config: dict[str, Any] | None) -> tuple[bool, str]:
    """Return (allowed, reason) for target_ip against config allowlist."""
    exploit_cfg = (config or {}).get("exploit", {})
    if not exploit_cfg.get("require_explicit_allowlist", False):
        return True, "allowlist not required"
    allowed_targets = _allowed_target_list(config)
    if not allowed_targets:
        return False, "require_explicit_allowlist is True but allowed_targets is empty"
    if is_target_in_allowlist(target_ip, allowed_targets):
        return True, "target in allowlist"
    return False, (
        f"Target IP {target_ip} is not in the explicit allowlist. "
        f"Add it to config.yaml exploit.allowed_targets to authorize."
    )


# ── Multi-target allowlist check (free-text command tools) ──────────────────
#
# ``make_require_allowlist`` inspects a single ``target_ip`` parameter, so it
# only fits tools whose target is a structured arg. The Metasploit persistent-
# console tools (``msfconsole_command``, ``msf_run_resource_script``,
# ``msf_interact_session``) take free-text command strings that can contain
# ``set RHOSTS <any host>``, and ``msf_generate_payload`` / ``generate_payload``
# take an ``lhost`` callback host. A direct MCP client that bypasses the agent
# loop's ``ExploitPolicy.approve_action`` could otherwise target an out-of-scope
# host through these ``@audit_tool``-only tools. These helpers extract the host
# tokens and run them through the same allowlist as ``_check_allowlist``.
_MSF_RHOSTS_RE = re.compile(
    r"\bset(?:g)?\s+(?:RHOSTS|RHOST)\s+(\S+)", re.IGNORECASE,
)
# Meterpreter pivot verbs that name a remote host/subnet to pivot through,
# not via RHOSTS: ``portfwd add -r <host>`` (and reverse ``-R``), ``route add
# <subnet>``, and ``autoroute [-s] <subnet>``. Without these the target-IP
# lock is bypassable from an existing session (LAB BUILD: no pivoting).
_MSF_PIVOT_RE = re.compile(
    r"(?i:\bportfwd\b)[^\n]*?(?:\s-r\s+)(\S+)"
    r"|(?i:\broute\s+add\s+)(\S+)"
    r"|(?i:\bautoroute)(?:\s+add|\s+-s)?\s+(\S+)"
)


def _extract_msf_rhosts(text: str) -> list[str]:
    """Extract RHOSTS/RHOST values from msfconsole command or resource-script
    text, plus meterpreter pivot hosts (portfwd -r/-R, route, autoroute). Returns
    the raw tokens (may be a single IP, CIDR, range, or file path) so the caller
    can scope-check each."""
    if not text:
        return []
    out: list[str] = [m.strip().strip("\"'") for m in _MSF_RHOSTS_RE.findall(text)]
    for m in _MSF_PIVOT_RE.finditer(text):
        for g in m.groups():
            if g:
                tok = g.strip().strip("\"'")
                if tok and tok not in out:
                    out.append(tok)
    return out


def check_targets_allowlist(
    targets: list[str], config: dict[str, Any] | None
) -> tuple[bool, str]:
    """Return (allowed, reason) for a list of host tokens against the allowlist.

    Empty/blank tokens are skipped (a tool call that names no host -- e.g.
    ``msfconsole_command("sessions -l")`` -- touches no target and is allowed).
    If ``exploit.require_explicit_allowlist`` is False, all targets are allowed.
    Otherwise EVERY named host must be in ``exploit.allowed_targets``; the first
    offending host fails the call. This is defense-in-depth at the tool layer --
    the agent loop's ``ExploitPolicy.approve_action`` is the primary gate.
    """
    exploit_cfg = (config or {}).get("exploit", {})
    if not exploit_cfg.get("require_explicit_allowlist", False):
        return True, "allowlist not required"
    allowed_targets = _allowed_target_list(config)
    if not allowed_targets:
        return False, "require_explicit_allowlist is True but allowed_targets is empty"
    for t in targets:
        if not t:
            continue
        if not is_target_in_allowlist(t, list(allowed_targets)):
            return False, (
                f"Host {t} is not in the explicit allowlist. "
                f"Add it to config.yaml exploit.allowed_targets to authorize."
            )
    return True, "all named hosts in allowlist"


def make_require_allowlist(workspace: Path, config: dict[str, Any] | None):
    """Return a decorator factory that enforces target_ip allowlist on MCP tool handlers.

    The returned decorator captures ``workspace`` and ``config`` in its closure,
    so it is safe to use outside the lexical scope of ``create_mcp_server``.
    """
    def require_allowlist(target_param: str = "target_ip", *, audit: bool = True):
        """Decorator that enforces target_ip allowlist on MCP tool handlers.

        Preserves function signature and annotations so FastMCP introspection
        continues to work correctly. Handles both sync and async tool handlers.
        When audit=True, writes exploit_audit.jsonl records for every invocation.
        """
        def decorator(fn):
            sig = inspect.signature(fn)
            if inspect.iscoroutinefunction(fn):
                @functools.wraps(fn)
                async def async_wrapper(*args, **kwargs):
                    bound = sig.bind(*args, **kwargs)
                    bound.apply_defaults()
                    target_ip = bound.arguments.get(target_param, "")
                    allowed, reason = _check_allowlist(target_ip, config)
                    if audit:
                        _audit_log(
                            workspace / "exploit_audit.jsonl",
                            target_ip=target_ip,
                            tool_name=fn.__name__,
                            approved=allowed,
                            status="blocked" if not allowed else "started",
                            args=_redact_args(dict(bound.arguments)),
                        )
                    if not allowed:
                        return (
                            f"BLOCKED: {reason}\n"
                            f"ATTEMPT_ID: preflight\n"
                            f"TOOL: {fn.__name__}\n"
                            f"TARGET: {target_ip}"
                        )
                    result = await fn(*args, **kwargs)
                    if audit:
                        # Bug #16: the wrapped tool may itself block (e.g. its
                        # own validation rejects the args and returns a
                        # ``BLOCKED:`` marker). The completion audit must
                        # reflect that — mirror ``make_audit_tool`` and
                        # inspect the return value instead of always writing
                        # ``approved=True, status="completed"``.
                        blocked = _result_is_blocked(result)
                        _audit_log(
                            workspace / "exploit_audit.jsonl",
                            target_ip=target_ip,
                            tool_name=fn.__name__,
                            approved=not blocked,
                            status="blocked" if blocked else "completed",
                            args=_redact_args(dict(bound.arguments)),
                        )
                    return result
                async_wrapper.__signature__ = sig
                return async_wrapper
            else:
                @functools.wraps(fn)
                def wrapper(*args, **kwargs):
                    bound = sig.bind(*args, **kwargs)
                    bound.apply_defaults()
                    target_ip = bound.arguments.get(target_param, "")
                    allowed, reason = _check_allowlist(target_ip, config)
                    if audit:
                        _audit_log(
                            workspace / "exploit_audit.jsonl",
                            target_ip=target_ip,
                            tool_name=fn.__name__,
                            approved=allowed,
                            status="blocked" if not allowed else "started",
                            args=_redact_args(dict(bound.arguments)),
                        )
                    if not allowed:
                        return (
                            f"BLOCKED: {reason}\n"
                            f"ATTEMPT_ID: preflight\n"
                            f"TOOL: {fn.__name__}\n"
                            f"TARGET: {target_ip}"
                        )
                    result = fn(*args, **kwargs)
                    if audit:
                        # Bug #16: see the matching note in the async wrapper
                        # above — inspect the return value so a tool that
                        # blocks post-preflight is audited as blocked.
                        blocked = _result_is_blocked(result)
                        _audit_log(
                            workspace / "exploit_audit.jsonl",
                            target_ip=target_ip,
                            tool_name=fn.__name__,
                            approved=not blocked,
                            status="blocked" if blocked else "completed",
                            args=_redact_args(dict(bound.arguments)),
                        )
                    return result
                wrapper.__signature__ = sig
                return wrapper
        return decorator
    return require_allowlist


# Result-string markers that indicate a tool call was blocked (not executed).
# ``make_audit_tool`` inspects the wrapped tool's return value: when the text
# starts with one of these (case-insensitive, leading whitespace stripped), the
# completion audit record is written as ``approved=False, status="blocked"``
# instead of ``approved=True, status="completed"``.
_BLOCKED_RESULT_MARKERS = ("BLOCKED:", "TERMINAL_RESULT: BLOCKED", "ROOT_CMD_RESULT:")


def _result_is_blocked(result: Any) -> bool:
    """Return True if a tool result string carries a blocked marker.

    Defensive: any error in stringifying the result is treated as not-blocked so
    a non-string return value never flips a completion into a blocked record.
    """
    try:
        text = str(result).lstrip().upper()
    except Exception:
        return False
    return text.startswith(_BLOCKED_RESULT_MARKERS)


def _extract_audit_target(bound: "inspect.BoundArguments") -> str:
    """Best-effort real target attribution for ``@audit_tool``-only tools.

    These tools (``msfconsole_command``, ``msf_run_resource_script``,
    ``msf_generate_payload``, ``generate_payload``, ``msf_interact_session``)
    take no structured ``target_ip`` -- the target is embedded in a free-text
    ``command``/``script_content`` (as ``set RHOSTS <host>``) or carried by the
    ``lhost`` callback argument. Previously the audit row recorded
    ``target_ip=""`` even when the tool touched a specific host, so the trail
    could not answer "which host did this command hit". This extracts the
    RHOSTS/RHOST values (and lhost) and joins them into the ``target_ip``
    field. Credentials are still masked by ``_mask_secret_content``; only host
    strings are recorded.
    """
    args = bound.arguments
    hosts: list[str] = []
    for key in ("command", "script_content"):
        text = args.get(key)
        if isinstance(text, str) and text:
            hosts.extend(_extract_msf_rhosts(text))
    lhost = args.get("lhost")
    if isinstance(lhost, str) and lhost:
        hosts.append(lhost)
    # Dedupe preserving order, strip surrounding quotes left by the RHOSTS
    # regex on quoted values.
    seen: set[str] = set()
    cleaned: list[str] = []
    for h in hosts:
        v = h.strip().strip('"').strip("'")
        if v and v not in seen:
            seen.add(v)
            cleaned.append(v)
    return ",".join(cleaned)


def make_audit_tool(workspace: Path):
    """Return an audit decorator that captures ``workspace`` in its closure."""
    def audit_tool(fn):
        """Decorator that adds exploit_audit.jsonl logging for tools without a target_ip.

        Preserves signature for FastMCP introspection. Handles sync and async.
        Result-aware: if the wrapped tool returns a blocked marker (``BLOCKED:``,
        ``TERMINAL_RESULT: BLOCKED``, ``ROOT_CMD_RESULT:``), the completion record
        is written with ``approved=False, status="blocked"`` instead of
        ``approved=True, status="completed"``, so blocked results are not mis-recorded
        as approved completions in the audit trail. The "started" record is unchanged.

        Tier 3: the audit row now carries the real touched host(s) via
        ``_extract_audit_target`` (RHOSTS/lhost) instead of a blank ``target_ip``,
        so the trail can attribute a free-text command to the host it hit.
        """
        sig = inspect.signature(fn)
        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def async_wrapper(*args, **kwargs):
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                target_ip = _extract_audit_target(bound)
                _audit_log(
                    workspace / "exploit_audit.jsonl",
                    target_ip=target_ip,
                    tool_name=fn.__name__,
                    approved=True,
                    status="started",
                    args=_redact_args(dict(bound.arguments)),
                )
                result = await fn(*args, **kwargs)
                blocked = _result_is_blocked(result)
                _audit_log(
                    workspace / "exploit_audit.jsonl",
                    target_ip=target_ip,
                    tool_name=fn.__name__,
                    approved=not blocked,
                    status="blocked" if blocked else "completed",
                    args=_redact_args(dict(bound.arguments)),
                )
                return result
            async_wrapper.__signature__ = sig
            return async_wrapper
        else:
            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                target_ip = _extract_audit_target(bound)
                _audit_log(
                    workspace / "exploit_audit.jsonl",
                    target_ip=target_ip,
                    tool_name=fn.__name__,
                    approved=True,
                    status="started",
                    args=_redact_args(dict(bound.arguments)),
                )
                result = fn(*args, **kwargs)
                blocked = _result_is_blocked(result)
                _audit_log(
                    workspace / "exploit_audit.jsonl",
                    target_ip=target_ip,
                    tool_name=fn.__name__,
                    approved=not blocked,
                    status="blocked" if blocked else "completed",
                    args=_redact_args(dict(bound.arguments)),
                )
                return result
            wrapper.__signature__ = sig
            return wrapper
    return audit_tool



def _attempt_dir(workspace: Path) -> tuple[Path, str]:
    # Bug #17: the id was wall-clock microseconds only, so two tool calls
    # landing in the same microsecond (concurrent swarm dispatch) collided
    # on the same attempt dir and clobbered each other's artifacts. Append
    # a short random suffix so the dir is unique even under a tight burst.
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    attempt_id = f"{stamp}_{secrets.token_hex(4)}"
    attempt_dir = workspace / attempt_id
    attempt_dir.mkdir(parents=True, exist_ok=True)
    return attempt_dir, attempt_id


# ── Subprocess helper with process-group timeout kill ────────────────────────
#
# Reused by every shell-wrapper / ``subprocess.run(..., timeout=...)`` site in
# the exploit MCP server (M2 / M15 / M18 / H1-H2 / H5 / M5). On POSIX it opens the
# child in its own session (``start_new_session=True``) so a timeout can reap the
# *whole* process group with ``os.killpg(SIGKILL)`` -- shell-spawned children die
# with the parent instead of surviving the kill. On Windows process groups are
# unavailable, so it falls back to ``proc.kill()``.
#
# Re-raises ``subprocess.TimeoutExpired`` (rather than returning a structured
# result) so existing call sites that wrap ``subprocess.run(..., timeout=...)``
# in ``try/except subprocess.TimeoutExpired`` keep working unchanged.


def _run_with_pgrp_timeout(
    args,
    timeout,
    stdout=None,
    stderr=None,
    cwd=None,
    env=None,
    input_text=None,
    **popen_kwargs,
):
    """Run ``args`` with a hard ``timeout``, reaping the process group on timeout.

    On POSIX the child is started in a new session (``start_new_session=True``)
    so that on timeout the entire group is killed via
    ``os.killpg(os.getpgid(pid), SIGKILL)`` (guarded against
    ``ProcessLookupError`` / ``PermissionError`` with a ``proc.kill()`` fallback).
    On Windows (``os.name == "nt"``) ``start_new_session`` is a no-op and the
    timeout path uses ``proc.kill()`` (``os.killpg`` / ``SIGKILL`` are not
    available).

    ``stdout`` / ``stderr`` / ``cwd`` / ``env`` / ``input_text`` are forwarded to
    ``subprocess.Popen``; remaining ``popen_kwargs`` are passed through (e.g.
    ``text=True``, ``encoding="utf-8"``). When ``input_text`` is a ``str`` it is
    encoded to bytes for ``Popen.communicate(input=...)``.

    Returns ``(returncode, stdout, stderr)``. When text mode is requested (via
    ``text=True`` / ``universal_newlines=True`` / ``encoding=``) the captured
    streams are decoded to ``str``; otherwise they are ``bytes`` (or whatever the
    caller-supplied ``stdout``/``stderr`` sink yields, e.g. ``None`` when the
    caller passes ``subprocess.DEVNULL``).

    Re-raises ``subprocess.TimeoutExpired`` on timeout so callers can catch it,
    matching the existing ``subprocess.run(..., timeout=...)`` call-site pattern.
    """
    import subprocess

    text_mode = bool(
        popen_kwargs.get("text")
        or popen_kwargs.get("universal_newlines")
        or popen_kwargs.get("encoding") is not None
    )
    proc = subprocess.Popen(
        args,
        start_new_session=(os.name != "nt"),
        stdout=stdout,
        stderr=stderr,
        cwd=cwd,
        env=env,
        **popen_kwargs,
    )
    input_bytes = None
    if input_text is not None:
        input_bytes = input_text.encode() if isinstance(input_text, str) else input_text
    try:
        out, err = proc.communicate(input=input_bytes, timeout=timeout)
    except subprocess.TimeoutExpired:
        # Kill the whole process group on POSIX so shell-spawned children die
        # with the parent; on Windows fall back to killing the immediate proc.
        if os.name == "nt":
            try:
                proc.kill()
            except ProcessLookupError:
                pass
        else:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
        try:
            proc.wait()
        except Exception:
            pass
        raise
    returncode = proc.returncode
    if text_mode:
        if isinstance(out, bytes):
            out = out.decode(errors="replace")
        if isinstance(err, bytes):
            err = err.decode(errors="replace")
    return returncode, out, err


# ── HTTP transport hardening (loopback gate + optional shared-secret auth) ──
#
# CLAUDE.md documents that the MCP HTTP transport "refuses to bind to non-
# loopback interfaces unless ``--allow-public-bind`` AND
# ``MCP_ALLOW_PUBLIC_BIND=1`` are both set", and that there is no auth on the
# streamable-http endpoint. The loopback gate previously existed only in
# mcp_exploit_server.py (and the documented override flag did not exist at
# all); mcp_server.py (defensive) had no gate. These helpers give both servers
# the same gate + an optional ``MCP_HTTP_TOKEN`` bearer-token check so a
# public bind is not unauthenticated.

_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def assert_loopback_bind(host: str, allow_public_bind: bool = False) -> None:
    """Raise ``ValueError`` if ``host`` is non-loopback and the public-bind
    override is not satisfied. The override requires BOTH the caller passing
    ``allow_public_bind=True`` (the ``--allow-public-bind`` CLI flag) AND the
    ``MCP_ALLOW_PUBLIC_BIND`` env var set to a truthy value -- a two-person
    rule so a stray flag or env var alone never exposes the server."""
    if host in _LOOPBACK_HOSTS:
        return
    env = os.environ.get("MCP_ALLOW_PUBLIC_BIND", "").strip().lower()
    env_set = env in {"1", "true", "yes", "on"}
    if allow_public_bind and env_set:
        return
    raise ValueError(
        f"Refusing to bind MCP HTTP transport to non-loopback host {host!r}. "
        f"Binding a public interface exposes the MCP tools to the network. "
        f"To allow, pass --allow-public-bind AND set MCP_ALLOW_PUBLIC_BIND=1."
    )


def _wrap_http_auth(app: Any, token: str) -> Any:
    """Wrap an ASGI app to require ``Authorization: Bearer <token>``.

    Pure-ASGI (no Starlette import) so it works with the streamable-http app
    from FastMCP. When the ``MCP_HTTP_TOKEN`` env var is unset, callers should
    not wrap -- the server is loopback-only by default. Comparison uses
    ``hmac.compare_digest`` to avoid timing side channels.
    """
    import hmac

    expected = f"Bearer {token}".encode("utf-8")

    async def auth_app(scope, receive, send):
        if scope.get("type") != "http":
            return await app(scope, receive, send)
        headers = {k.lower(): v for k, v in scope.get("headers", [])}
        if hmac.compare_digest(headers.get(b"authorization", b""), expected):
            return await app(scope, receive, send)
        await send({
            "type": "http.response.start",
            "status": 401,
            "headers": [
                (b"content-type", b"text/plain"),
                (b"www-authenticate", b'Bearer realm="mcp"'),
            ],
        })
        await send({"type": "http.response.body", "body": b"Unauthorized: MCP_HTTP_TOKEN required"})

    return auth_app


def run_mcp_http_server(mcp: Any, host: str, port: int, *, allow_public_bind: bool = False) -> None:
    """Run a FastMCP server over streamable-http with loopback + optional auth.

    Centralizes the HTTP serving for both MCP servers so the loopback gate,
    the ``--allow-public-bind`` override, and the ``MCP_HTTP_TOKEN`` bearer
    auth live in one place. Uses ``mcp.streamable_http_app()`` + ``uvicorn.run``
    (the current SDK path) instead of the legacy ``server.run(transport="http")``.
    """
    assert_loopback_bind(host, allow_public_bind=allow_public_bind)
    try:
        import uvicorn
        app = mcp.streamable_http_app()
    except ImportError as exc:
        raise RuntimeError(
            "HTTP MCP transport needs uvicorn and starlette. "
            "Run: python -m pip install -r requirements.txt"
        ) from exc
    token = os.environ.get("MCP_HTTP_TOKEN", "").strip()
    if token:
        app = _wrap_http_auth(app, token)
    uvicorn.run(app, host=host, port=port, log_level="info")
