"""Audit-log helpers — credential redaction + audit decorators.

Extracted from ``tools.mcp_shared`` (Phase 2 kernel). ``tools.mcp_shared``
re-exports for backwards compat; ``tools.mcp_tools.registry`` re-imports
from there.

Ponytail: pure redaction + thin decorator factories. No behavior change —
verbatim move of ``_redact_*``, ``_mask_secret_content``, ``_audit_log``,
``_result_is_blocked``, ``_extract_audit_target``, ``make_audit_tool``,
``make_require_allowlist``.
"""

from __future__ import annotations

import functools
import hashlib
import inspect
import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, TypedDict

from tools.kernel.allowlist import (
    _check_allowlist,
    _extract_msf_rhosts,
    allowlist_env_audit_extra,
)
from tools.kernel.append_log import AppendLogWriter, get_append_writer

_SECRET_ARG_NAMES = frozenset(
    {
        "password",
        "passwd",
        "pass",
        "passphrase",
        "secret",
        "shared_secret",
        "pre_shared_key",
        "secret_key",
        "signing_key",
        "ntlm_hash",
        "ntlm",
        "hash",
        "kerberos_ticket",
        "asrep_key",
        "rc4_key",
        "aes_key",
        "token",
        "auth_token",
        "access_token",
        "refresh_token",
        "session_key",
        "cookies",
        "authorization",
        "api_key",
        "apikey",
        "credential",
        "credentials",
        "creds",
        "private_key",
        "priv_key",
    }
)

_REDACTED = "***REDACTED***"

_MASK_URL_AUTH_RE = re.compile(r"(?<=://)[^@\s:/]+:[^@\s:/]+(?=@)", re.IGNORECASE)
_MASK_U_FLAG_RE = re.compile(
    r"((?<![\w-])(?:-u|--user)\s+)[^\s:]+:[^\s]+",
    re.IGNORECASE,
)
_MASK_LONG_PW_RE = re.compile(
    r"((?<![\w-])(?:--password|--passwd|--passphrase|--pass|--pwd|-pass|-password|-passwd)\s+)[^\s]+",
    re.IGNORECASE,
)
_MASK_HYDRA_P_RE = re.compile(
    r"(\b(?:hydra|medusa|crackmapexec|netexec|cme|evil-winrm)\b[^\n]*?(?<![\w-])-[pP]\s+)[^\s]+",
    re.IGNORECASE,
)
_MASK_MSF_SET_RE = re.compile(
    r"(\bset\s+(?:SMBPass|PASSWORD|PASSWD|DbUserPass|DbPassword|DbPass|SECRET|SECRETKEY|"
    r"SECRET_KEY|TOKEN|API_KEY|APIKEY|NTLM_HASH|PRIVATE_KEY|PRIV_KEY|ACCESS_KEY|"
    r"AUTH_TOKEN|CREDENTIAL|DB_PASSWORD|DBPASS)\s+)[^\s]+",
    re.IGNORECASE,
)
_MASK_HASHES_RE = re.compile(
    r"((?<![\w-])-hashes\s+)(?:[\da-fA-F]{16,}:[\da-fA-F]{16,}|:[\da-fA-F]{16,}|[\da-fA-F]{16,})",
    re.IGNORECASE,
)
_MASK_NTLM_FLAG_RE = re.compile(
    r"((?<![\w-])-ntlm\s+)[\da-fA-F]{16,}",
    re.IGNORECASE,
)
_MASK_KV_SECRET_RE = re.compile(
    r"\b((?:SMBPass|PASSWORD|PASSWD|DbUserPass|DbPassword|DbPass|SECRETKEY|SECRET_KEY|"
    r"SECRET|TOKEN|API_KEY|APIKEY|NTLM_HASH|PRIVATE_KEY|PRIV_KEY|ACCESS_KEY|"
    r"AUTH_TOKEN|CREDENTIAL|CREDENTIALS|DB_PASSWORD|DBPASS)\s*=\s*)"
    r"[^\s,;=.\[\(\$\{]+",
    re.IGNORECASE,
)
_MASK_AUTH_HDR_RE = re.compile(
    r"(Authorization\s*:\s*(?:Basic|Bearer|Digest|Negotiate|NTLM)\s+)[^\s,;'\"]+",
    re.IGNORECASE,
)
_MASK_PY_AUTH_TUPLE_RE = re.compile(
    r"(\bauth\s*=\s*\(\s*)[\"'][^\"']+[\"']\s*,\s*[\"'][^\"']+[\"'](\s*\))",
    re.IGNORECASE,
)
# `password: hunter2` / `"password": "hunter2"` colon forms (YAML/JSON/tool
# output) -- the `=`-only KV mask above misses them. NTLM covers secretsdump
# `NTLM: <lm>:<nt>` lines; bare `32hex:32hex` pairs (no label) are caught by
# _MASK_NTLM_PAIR_RE below.
_MASK_KV_COLON_RE = re.compile(
    r"\b((?:PASSWORD|PASSWD|PASSPHRASE|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|NTLM(?:_HASH)?)\s*:\s*[\"']?)[^\s,\"']+",
    re.IGNORECASE,
)
# Bare NTLM hash pairs with no label (secretsdump `user:rid:lm:nt:::` lines,
# hashcat Potfile `hash:plain` leftovers): 32 hex, colon, 32 hex. Specific
# enough to avoid false positives on UUIDs/SHAs (neither is 32:32).
_MASK_NTLM_PAIR_RE = re.compile(r"\b[\da-fA-F]{32}:[\da-fA-F]{32}\b")
# PEM blocks pasted into commands/logs (heredoc'd keys) -- the whole block is
# key material.
_MASK_PEM_RE = re.compile(
    r"-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----",
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
    _MASK_KV_COLON_RE,
    _MASK_NTLM_PAIR_RE,
    _MASK_PEM_RE,
    _MASK_AUTH_HDR_RE,
    _MASK_PY_AUTH_TUPLE_RE,
)

_WHOLESALE_REDACT_FIELDS = frozenset({"input_text", "notes"})


def _mask_secret_content(value: Any) -> Any:
    if not isinstance(value, str) or not value:
        return value
    out = value
    for rx in _MASK_RES:
        if rx is _MASK_URL_AUTH_RE or rx is _MASK_PEM_RE or rx is _MASK_NTLM_PAIR_RE:
            # Group-less whole-match masks: replace the match itself.
            out = rx.sub(_REDACTED, out)
        elif rx is _MASK_PY_AUTH_TUPLE_RE:
            out = rx.sub(rf"\1{_REDACTED}\2", out)
        else:
            out = rx.sub(rf"\1{_REDACTED}", out)
    return out


def _redact_nested(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            k: (_REDACTED if isinstance(k, str) and k.lower() in _SECRET_ARG_NAMES else _redact_nested(v))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        # Credential dicts nested in lists (e.g. extra={creds: [{password: ...}]})
        # must be sanitized element-wise, not passed through.
        return [_redact_nested(v) for v in value]
    if isinstance(value, str):
        return _mask_secret_content(value)
    return value


def _redact_args(args: dict[str, Any] | None) -> dict[str, Any]:
    if not args:
        return {}
    redacted: dict[str, Any] = {}
    for name, value in args.items():
        lname = name.lower() if isinstance(name, str) else ""
        if lname in _SECRET_ARG_NAMES:
            redacted[name] = _REDACTED
        elif lname in _WHOLESALE_REDACT_FIELDS and value:
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
    extra: dict[str, Any] | None = None,
) -> None:
    import json as _json

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target_ip": target_ip,
        "tool_name": tool_name,
        "approved": approved,
        "status": status,
        "command": _mask_secret_content(command) if command else "",
        "args": args or {},
        "attempt_id": attempt_id,
        "code_sha256": code_sha256,
        "duration_seconds": duration_seconds,
    }
    if extra:
        # Optional structured context (e.g. the sandbox subsystem's container
        # id / network-policy fingerprint). Merged after the base keys so a
        # caller-supplied override is explicit. Sanitized with the SAME
        # pipeline as ordinary argument logging (secret-named keys at every
        # depth, secret-shaped strings, lists descended element-wise) —
        # callers must still keep secrets out, but anything that slips into
        # ``extra`` never reaches disk in cleartext.
        redacted_extra = _redact_args(extra)
        for key, value in redacted_extra.items():
            if value is not None:
                record[key] = value
    # ponytail: mkdir per audit row (2x per tool call) stats the fs every time.
    parent = audit_path.parent
    if str(parent) not in _MKDIR_CACHE:
        parent.mkdir(parents=True, exist_ok=True)
        _MKDIR_CACHE.add(str(parent))
    # P2-07: single-FD batched writer per path (no per-record open/close).
    # The record schema above is unchanged; only the transport moved.
    get_append_writer(audit_path).append(_json.dumps(record, default=str) + "\n")


_BLOCKED_RESULT_MARKERS = ("BLOCKED:", "TERMINAL_RESULT: BLOCKED", "ROOT_CMD_RESULT: BLOCKED", "ERROR:")

# Structured terminal statuses for audit records. ``failed`` covers any
# exception escaping the wrapped tool (including BaseExceptionGroup and
# cancellation) — every ``started`` record is guaranteed a terminal sibling.
# The legacy ``"BLOCKED:"`` text prefixes in MCP responses are preserved;
# this model describes the audit record, not the wire format.
AuditStatus = Literal["started", "completed", "blocked", "failed"]

# Max characters of sanitized exception text kept in a failure record.
_FAILURE_SUMMARY_LEN = 500

# ponytail: cache mkdir'd parents — audit fires 2x per tool call.
_MKDIR_CACHE: set[str] = set()


def _failure_extra(exc: BaseException) -> dict[str, Any]:
    """Build the audit ``extra`` payload for a tool failure.

    Records the exception class name plus a sanitized one-line summary run
    through the same credential-redaction pipeline as ordinary argument
    logging — passwords, tokens, hashes, private keys, and Authorization
    headers in exception text never reach disk in cleartext.
    """
    summary = _mask_secret_content(str(exc)) if str(exc) else ""
    summary = " ".join(summary.split())[:_FAILURE_SUMMARY_LEN]
    return {"error_class": type(exc).__name__, "error_summary": summary}


def _extract_attempt_id(bound: "inspect.BoundArguments") -> str:
    """Return the tool's attempt ID when it takes one, else ``""``."""
    attempt_id = bound.arguments.get("attempt_id", "")
    return attempt_id if isinstance(attempt_id, str) else ""


def _safe_audit_log(audit_path: Path, **record: Any) -> None:
    """Best-effort :func:`_audit_log` for the failure path only.

    A full disk (or vanished workspace) must never mask the tool's original
    exception — or erase its failure record by raising inside the handler.
    Swallowing here is deliberate and narrow: normal-path audit writes keep
    surfacing errors loudly.
    """
    import logging

    try:
        _audit_log(audit_path, **record)
    except Exception as exc:  # noqa: BLE001 -- best-effort failure-path logging only
        logging.getLogger(__name__).warning("audit failure record lost: %s", exc)


def _log_terminal(
    audit_path: Path,
    *,
    target_ip: str,
    tool_name: str,
    result: Any,
    args: dict[str, Any],
    attempt_id: str = "",
    duration_seconds: float = 0.0,
) -> None:
    """Write the ``completed``/``blocked`` record for a returned result."""
    blocked = _result_is_blocked(result)
    _audit_log(
        audit_path,
        target_ip=target_ip,
        tool_name=tool_name,
        approved=not blocked,
        status="blocked" if blocked else "completed",
        args=args,
        attempt_id=attempt_id,
        duration_seconds=duration_seconds,
    )


def _log_failure(
    audit_path: Path,
    *,
    target_ip: str,
    tool_name: str,
    exc: BaseException,
    args: dict[str, Any],
    attempt_id: str = "",
    duration_seconds: float = 0.0,
) -> None:
    """Write the terminal ``failed`` record for an escaping exception."""
    _safe_audit_log(
        audit_path,
        target_ip=target_ip,
        tool_name=tool_name,
        approved=False,
        status="failed",
        args=args,
        attempt_id=attempt_id,
        duration_seconds=duration_seconds,
        extra=_failure_extra(exc),
    )


def _result_is_blocked(result: Any) -> bool:
    try:
        text = str(result).lstrip().upper()
    except Exception:  # noqa: BLE001 -- str() on hostile result objects must never break audit classification
        return False
    return text.startswith(_BLOCKED_RESULT_MARKERS)


def _extract_audit_target(bound: "inspect.BoundArguments") -> str:
    args = bound.arguments
    hosts: list[str] = []
    for key in ("command", "script_content"):
        text = args.get(key)
        if isinstance(text, str) and text:
            hosts.extend(_extract_msf_rhosts(text))
    lhost = args.get("lhost")
    if isinstance(lhost, str) and lhost:
        hosts.append(lhost)
    seen: set[str] = set()
    cleaned: list[str] = []
    for h in hosts:
        v = h.strip().strip('"').strip("'")
        if v and v not in seen:
            seen.add(v)
            cleaned.append(v)
    return ",".join(cleaned)


def make_require_allowlist(workspace: Path, config: dict[str, Any] | None):
    def require_allowlist(target_param: str = "target_ip", *, audit: bool = True, host_param: str | None = None):
        """Gate a tool on the target-IP allowlist.

        ``host_param`` names an optional second bound argument holding a
        hostname that gives the target its context (e.g. ``vhost_enum``'s
        ``domain`` for the ``Host:`` header / TLS SNI). When the primary
        target alone is not allowlisted, the pair is accepted iff the
        hostname is allowlisted AND the provenance store ties the target IP
        to that hostname (see :mod:`tools.kernel.discovered`). A resolved
        IP is therefore usable only in a context tied to its hostname,
        unless the IP itself is explicitly allowlisted. ``None`` (the
        default) preserves the legacy single-target gate.
        """
        from tools.kernel.discovered import get_discovered_host, is_pair_authorized
        from tools.validation_utils import is_target_in_allowlist

        def _pair_fallback(target_ip: Any, bound: "inspect.BoundArguments") -> tuple[bool, str] | None:
            """Pair-aware second chance after the flat gate denies. None = no pair context."""
            if not host_param:
                return None
            hostname = bound.arguments.get(host_param, "")
            if not isinstance(hostname, str) or not hostname.strip():
                return None
            if not isinstance(target_ip, str) or not target_ip.strip():
                return None
            from tools.kernel.allowlist import _allowed_target_list

            allowed_targets = _allowed_target_list(config)
            if not is_target_in_allowlist(hostname.strip(), allowed_targets):
                return None
            if is_pair_authorized(target_ip, hostname, allowed=allowed_targets):
                entry = get_discovered_host(hostname)
                via = (
                    f" via {hostname.strip()} ({entry.source})"
                    if entry and entry.source
                    else f" via {hostname.strip()}"
                )
                return True, f"target in allowlist{via}"
            return None

        def decorator(fn):
            sig = inspect.signature(fn)
            if inspect.iscoroutinefunction(fn):

                @functools.wraps(fn)
                async def async_wrapper(*args, **kwargs):
                    bound = sig.bind(*args, **kwargs)
                    bound.apply_defaults()
                    target_ip = bound.arguments.get(target_param, "")
                    allowed, reason = _check_allowlist(target_ip, config)
                    if not allowed:
                        pair = _pair_fallback(target_ip, bound)
                        if pair is not None:
                            allowed, reason = pair
                    redacted = _redact_args(dict(bound.arguments)) if audit else {}
                    attempt_id = _extract_attempt_id(bound)
                    if audit:
                        _audit_log(
                            workspace / "exploit_audit.jsonl",
                            target_ip=target_ip,
                            tool_name=fn.__name__,
                            approved=allowed,
                            status="blocked" if not allowed else "started",
                            args=redacted,
                            attempt_id=attempt_id,
                            # Explicit env-widening event: when EXPLOIT_* env
                            # vars widen the lock beyond config.yaml, the
                            # widening is named on the row ({} otherwise).
                            extra=allowlist_env_audit_extra(config) or None,
                        )
                    if not allowed:
                        return f"BLOCKED: {reason}\nATTEMPT_ID: preflight\nTOOL: {fn.__name__}\nTARGET: {target_ip}"
                    # BaseException (not Exception): BaseExceptionGroup from
                    # anyio task groups and asyncio cancellation must still
                    # produce a terminal audit record — then re-raise
                    # unchanged so cancellation semantics are preserved.
                    start = time.monotonic()
                    try:
                        result = await fn(*args, **kwargs)
                    except BaseException as exc:
                        if audit:
                            _log_failure(
                                workspace / "exploit_audit.jsonl",
                                target_ip=target_ip,
                                tool_name=fn.__name__,
                                exc=exc,
                                args=redacted,
                                attempt_id=attempt_id,
                                duration_seconds=time.monotonic() - start,
                            )
                        raise
                    if audit:
                        _log_terminal(
                            workspace / "exploit_audit.jsonl",
                            target_ip=target_ip,
                            tool_name=fn.__name__,
                            result=result,
                            args=redacted,
                            attempt_id=attempt_id,
                            duration_seconds=time.monotonic() - start,
                        )
                    return result

                async_wrapper.__signature__ = sig  # type: ignore[attr-defined]
                async_wrapper.__wrapped_require_allowlist__ = True  # type: ignore[attr-defined]
                async_wrapper.__wrapped_audit_tool__ = bool(audit)  # type: ignore[attr-defined]
                return async_wrapper
            else:

                @functools.wraps(fn)
                def wrapper(*args, **kwargs):
                    bound = sig.bind(*args, **kwargs)
                    bound.apply_defaults()
                    target_ip = bound.arguments.get(target_param, "")
                    allowed, reason = _check_allowlist(target_ip, config)
                    if not allowed:
                        pair = _pair_fallback(target_ip, bound)
                        if pair is not None:
                            allowed, reason = pair
                    redacted = _redact_args(dict(bound.arguments)) if audit else {}
                    attempt_id = _extract_attempt_id(bound)
                    if audit:
                        _audit_log(
                            workspace / "exploit_audit.jsonl",
                            target_ip=target_ip,
                            tool_name=fn.__name__,
                            approved=allowed,
                            status="blocked" if not allowed else "started",
                            args=redacted,
                            attempt_id=attempt_id,
                            # Explicit env-widening event (see async_wrapper).
                            extra=allowlist_env_audit_extra(config) or None,
                        )
                    if not allowed:
                        return f"BLOCKED: {reason}\nATTEMPT_ID: preflight\nTOOL: {fn.__name__}\nTARGET: {target_ip}"
                    start = time.monotonic()
                    try:
                        result = fn(*args, **kwargs)
                    except BaseException as exc:
                        if audit:
                            _log_failure(
                                workspace / "exploit_audit.jsonl",
                                target_ip=target_ip,
                                tool_name=fn.__name__,
                                exc=exc,
                                args=redacted,
                                attempt_id=attempt_id,
                                duration_seconds=time.monotonic() - start,
                            )
                        raise
                    if audit:
                        _log_terminal(
                            workspace / "exploit_audit.jsonl",
                            target_ip=target_ip,
                            tool_name=fn.__name__,
                            result=result,
                            args=redacted,
                            attempt_id=attempt_id,
                            duration_seconds=time.monotonic() - start,
                        )
                    return result

                wrapper.__signature__ = sig  # type: ignore[attr-defined]
                wrapper.__wrapped_require_allowlist__ = True  # type: ignore[attr-defined]
                wrapper.__wrapped_audit_tool__ = bool(audit)  # type: ignore[attr-defined]
                return wrapper

        return decorator

    return require_allowlist


def make_audit_tool(workspace: Path):
    def audit_tool(fn):
        sig = inspect.signature(fn)
        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args, **kwargs):
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                target_ip = _extract_audit_target(bound)
                redacted = _redact_args(dict(bound.arguments))
                attempt_id = _extract_attempt_id(bound)
                _audit_log(
                    workspace / "exploit_audit.jsonl",
                    target_ip=target_ip,
                    tool_name=fn.__name__,
                    approved=True,
                    status="started",
                    args=redacted,
                    attempt_id=attempt_id,
                )
                start = time.monotonic()
                try:
                    result = await fn(*args, **kwargs)
                except BaseException as exc:
                    _log_failure(
                        workspace / "exploit_audit.jsonl",
                        target_ip=target_ip,
                        tool_name=fn.__name__,
                        exc=exc,
                        args=redacted,
                        attempt_id=attempt_id,
                        duration_seconds=time.monotonic() - start,
                    )
                    raise
                _log_terminal(
                    workspace / "exploit_audit.jsonl",
                    target_ip=target_ip,
                    tool_name=fn.__name__,
                    result=result,
                    args=redacted,
                    attempt_id=attempt_id,
                    duration_seconds=time.monotonic() - start,
                )
                return result

            async_wrapper.__signature__ = sig  # type: ignore[attr-defined]
            async_wrapper.__wrapped_audit_tool__ = True  # type: ignore[attr-defined]
            return async_wrapper
        else:

            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                target_ip = _extract_audit_target(bound)
                redacted = _redact_args(dict(bound.arguments))
                attempt_id = _extract_attempt_id(bound)
                _audit_log(
                    workspace / "exploit_audit.jsonl",
                    target_ip=target_ip,
                    tool_name=fn.__name__,
                    approved=True,
                    status="started",
                    args=redacted,
                    attempt_id=attempt_id,
                )
                start = time.monotonic()
                try:
                    result = fn(*args, **kwargs)
                except BaseException as exc:
                    _log_failure(
                        workspace / "exploit_audit.jsonl",
                        target_ip=target_ip,
                        tool_name=fn.__name__,
                        exc=exc,
                        args=redacted,
                        attempt_id=attempt_id,
                        duration_seconds=time.monotonic() - start,
                    )
                    raise
                _log_terminal(
                    workspace / "exploit_audit.jsonl",
                    target_ip=target_ip,
                    tool_name=fn.__name__,
                    result=result,
                    args=redacted,
                    attempt_id=attempt_id,
                    duration_seconds=time.monotonic() - start,
                )
                return result

            wrapper.__signature__ = sig  # type: ignore[attr-defined]
            wrapper.__wrapped_audit_tool__ = True  # type: ignore[attr-defined]
            return wrapper

    return audit_tool


# ---------------------------------------------------------------------------
# P2-08: segmented audit-chain checkpointing
# ---------------------------------------------------------------------------
# ``verify_audit_chain`` (legacy single-file, in tools/exploit_agent/policy.py)
# re-reads + re-hashes the whole ``exploit_audit.jsonl`` at session start, so
# old workspaces pay O(history) on every boot. This section is the opt-in
# segmented layout that keeps O(history) off session start WITHOUT weakening
# the integrity contract:
#
# - ``<stem>-0001.jsonl``, ``<stem>-0002.jsonl``, ... (10k records or 16MB per
#   segment). Each segment opens with a ``header`` envelope carrying
#   ``previous_segment_hash`` (the digest of the previous segment file, or
#   ``GENESIS``) and closes with a ``footer`` carrying ``segment_root_hash``
#   (sha256 over the header + data lines) plus the running record-chain
#   ``tail_hash``.
# - A ``<stem>.checkpoint.json`` records per-segment {digest, mtime_ns, size,
#   root_hash, records, tail_hash}. Startup verifies the active tail fully
#   and checks sealed segments against recorded digests (one streaming hash,
#   no JSON parse) unless mtime/size changed -- then that segment is
#   rescanned. A missing/corrupt checkpoint forces a full rescan.
# - Tamper-evidence comes from the CHAIN LINKS, not just per-segment
#   digests: segment N+1's header pins digest(N), verified against freshly
#   computed digests (never the checkpoint's values), so rewriting a segment
#   AND the checkpoint still breaks the next header. Record-level
#   hash/prev_hash linkage is threaded across segments on full passes, so
#   surgical edits cascade into a mismatch at the next chained row.
# - Rotation is crash-safe: footer line + fsync, then the checkpoint is
#   rewritten atomically (temp + fsync + rename + dir fsync). A crash leaves
#   either a sealed segment the next startup rescans, or a footerless tail
#   that is verified-or-quarantined -- never silently truncated.
# - Segments + checkpoint are 0o600.
#
# ``verify_audit_chain()`` (policy.py) is intentionally untouched and stays
# backward compatible for the legacy single-file layout.

SEGMENT_MAX_RECORDS = 10_000
SEGMENT_MAX_BYTES = 16 * 1024 * 1024
SEGMENT_CHECKPOINT_VERSION = 1
_GENESIS_SEGMENT_HASH = "GENESIS"

_SEGMENT_ENVELOPE_KEY = "segment_record"
_SEGMENT_HEADER = "header"
_SEGMENT_FOOTER = "footer"

_seg_log = logging.getLogger(__name__)


class _SegmentEntry(TypedDict):
    digest: str
    root_hash: str
    records: int
    bytes: int
    tail_hash: str
    mtime_ns: int
    size: int


def audit_segment_path(base_path: Path | str, index: int) -> Path:
    """Path of segment ``index`` (1-based) for a segmented log ``base_path``."""
    base = Path(base_path)
    return base.parent / f"{base.stem}-{index:04d}{base.suffix}"


def audit_checkpoint_path(base_path: Path | str) -> Path:
    """Path of the checkpoint file recording verified segment digests."""
    base = Path(base_path)
    return base.parent / f"{base.stem}.checkpoint.json"


def _segment_index_rx(base: Path) -> "re.Pattern[str]":
    return re.compile(rf"^{re.escape(base.stem)}-(\d{{4}}){re.escape(base.suffix)}$")


def _list_segment_indexes(base_path: Path | str) -> list[int]:
    """Sorted segment indexes present on disk (quarantine files excluded)."""
    base = Path(base_path)
    rx = _segment_index_rx(base)
    try:
        names = [p.name for p in base.parent.glob(f"{base.stem}-*{base.suffix}")]
    except OSError:
        return []
    indexes: list[int] = []
    for name in names:
        match = rx.fullmatch(name)
        if match:
            indexes.append(int(match.group(1)))
    return sorted(indexes)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _split_complete_lines(raw: bytes) -> list[bytes] | None:
    """Split file bytes into complete lines, or None on a partial tail.

    Every complete line ends with ``\\n``; a trailing fragment without one
    means the file was torn mid-write (crash) and must be quarantined, never
    silently truncated.
    """
    if not raw:
        return []
    if not raw.endswith(b"\n"):
        return None
    return raw.split(b"\n")[:-1]


def _parse_envelope(line: bytes, kind: str, index: int) -> tuple[dict[str, Any] | None, str]:
    try:
        obj = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        return None, f"segment {index:04d}: {kind} is not valid JSON: {exc}"
    if not isinstance(obj, dict) or obj.get(_SEGMENT_ENVELOPE_KEY) != kind:
        return None, f"segment {index:04d}: missing {kind} envelope"
    if obj.get("segment") != index:
        return None, f"segment {index:04d}: {kind} names segment {obj.get('segment')!r}"
    return obj, ""


def _verify_chained_objects(objs: list[Any], start_prev: str, label: str) -> tuple[bool, str, str]:
    """Thread record-level hash/prev_hash linkage (mirrors verify_audit_chain).

    Rows carrying ``hash`` are recomputed (canonical JSON excluding ``hash``)
    and linked; rows without ``hash`` are skipped unless they carry a
    mismatched ``prev_hash``. Returns (ok, reason, end_prev).
    """
    running = start_prev
    for pos, obj in enumerate(objs, start=1):
        if not isinstance(obj, dict):
            return False, f"{label}: record {pos} is not a JSON object", running
        rec_hash = obj.get("hash", "")
        if not rec_hash:
            prev_hash = obj.get("prev_hash", "")
            if prev_hash and prev_hash != running:
                return (
                    False,
                    (
                        f"{label}: record {pos} prev_hash mismatch (chain broken, "
                        f"expected {str(running)[:12]!r}, got {str(prev_hash)[:12]!r})"
                    ),
                    running,
                )
            continue
        prev_hash = obj.get("prev_hash", "")
        if prev_hash != running:
            return (
                False,
                (
                    f"{label}: record {pos} prev_hash mismatch (chain broken, "
                    f"expected {str(running)[:12]!r}, got {str(prev_hash)[:12]!r})"
                ),
                running,
            )
        payload = {k: v for k, v in obj.items() if k != "hash"}
        canonical = json.dumps(payload, sort_keys=True, default=str, ensure_ascii=True)
        expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if rec_hash != expected:
            return (
                False,
                (
                    f"{label}: record {pos} hash mismatch (entry tampered with, "
                    f"expected {expected[:12]!r}, got {str(rec_hash)[:12]!r})"
                ),
                running,
            )
        running = str(rec_hash)
    return True, f"{label}: chain ok", running


def _load_checkpoint(base_path: Path | str) -> dict[str, Any] | None:
    """Load the checkpoint payload, or None when missing/corrupt (→ rescan)."""
    path = audit_checkpoint_path(base_path)
    try:
        if not path.is_file():
            return None
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(raw, dict) or raw.get("version") != SEGMENT_CHECKPOINT_VERSION:
        return None
    segments = raw.get("segments")
    if not isinstance(segments, dict):
        return None
    return raw


def _write_checkpoint_atomically(base_path: Path | str, payload: dict[str, Any]) -> None:
    """Write the checkpoint via temp + fsync + rename + dir fsync (0o600)."""
    path = audit_checkpoint_path(base_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / f".{path.name}.tmp-{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        try:
            os.fchmod(fd, 0o600)
        except OSError:
            pass
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True, default=str))
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.replace(tmp, path)
    try:
        dir_fd = os.open(path.parent, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    finally:
        os.close(dir_fd)


def quarantine_segment(path: Path | str) -> Path:
    """Rename a corrupt tail aside for forensics. Never deletes data."""
    src = Path(path)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = src.parent / f"{src.stem}.quarantined-{stamp}{src.suffix}"
    src.rename(dest)
    try:
        os.chmod(dest, 0o600)
    except OSError:
        pass
    _seg_log.warning("quarantined corrupt audit segment %s -> %s", src, dest)
    return dest


def _rescan_sealed_segment(path: Path, index: int, start_prev: str) -> tuple[bool, str, str, str, str]:
    """Full parse of a sealed segment. Returns (ok, reason, root, digest, tail)."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        return False, f"segment {index:04d}: unreadable: {exc}", "", "", start_prev
    blines = _split_complete_lines(raw)
    if blines is None:
        return False, f"segment {index:04d}: truncated (missing trailing newline)", "", "", start_prev
    if len(blines) < 2:
        return False, f"segment {index:04d}: missing header/footer", "", "", start_prev
    header, reason = _parse_envelope(blines[0], _SEGMENT_HEADER, index)
    if header is None:
        return False, reason, "", "", start_prev
    footer, reason = _parse_envelope(blines[-1], _SEGMENT_FOOTER, index)
    if footer is None:
        return False, reason, "", "", start_prev
    root = hashlib.sha256()
    for line in blines[:-1]:
        root.update(line + b"\n")
    root_hex = root.hexdigest()
    if footer.get("segment_root_hash") != root_hex:
        return False, f"segment {index:04d}: root hash mismatch (content tampered)", "", "", start_prev
    data = blines[1:-1]
    if footer.get("records") != len(data):
        return False, f"segment {index:04d}: record count mismatch (truncated/spliced)", "", "", start_prev
    objs: list[Any] = []
    for pos, line in enumerate(data, start=1):
        try:
            objs.append(json.loads(line.decode("utf-8")))
        except (UnicodeDecodeError, ValueError) as exc:
            return False, f"segment {index:04d}: record {pos} is not valid JSON: {exc}", "", "", start_prev
    ok, reason, tail = _verify_chained_objects(objs, start_prev, f"segment {index:04d}")
    if not ok:
        return False, reason, "", "", start_prev
    digest = hashlib.sha256(raw).hexdigest()
    return True, f"segment {index:04d}: rescanned ({len(data)} records)", root_hex, digest, tail


def verify_segmented_chain(base_path: Path | str) -> tuple[bool, str]:
    """Verify a segmented audit log with O(tail) startup cost.

    Sealed segments whose mtime/size match the checkpoint are checked by a
    single streaming digest (no JSON parse); any metadata change, checkpoint
    mismatch, or missing checkpoint triggers a full rescan of that segment.
    The active tail is always fully parsed. Cross-segment links use freshly
    computed digests -- never checkpoint values -- so rewriting a segment
    AND the checkpoint still breaks the next header. Read-only: never
    quarantines or mutates; the writer does that at startup.
    """
    base = Path(base_path)
    indexes = _list_segment_indexes(base)
    if not indexes:
        return True, "no segments"
    if indexes != list(range(1, len(indexes) + 1)):
        return False, f"segment gap: found {indexes}"
    checkpoint = _load_checkpoint(base)
    entries: dict[str, Any] = checkpoint.get("segments", {}) if checkpoint else {}
    if not isinstance(entries, dict):
        entries = {}
    full_rescan = checkpoint is None
    try:
        fresh = {i: _sha256_file(audit_segment_path(base, i)) for i in indexes}
    except OSError as exc:
        return False, f"segment unreadable: {exc}"
    # Cross-segment links first (fresh digests only).
    last = indexes[-1]
    for i in indexes:
        seg_i = audit_segment_path(base, i)
        try:
            raw_i = seg_i.read_bytes()
        except OSError as exc:
            return False, f"segment {i:04d}: unreadable: {exc}"
        if not raw_i:
            if i != last:
                return False, f"segment {i:04d}: empty (missing header)"
            continue  # Empty active tail: no header to link yet; checked below.
        header, reason = _parse_envelope(raw_i.split(b"\n")[0], _SEGMENT_HEADER, i)
        if header is None:
            return False, reason
        expected_prev = _GENESIS_SEGMENT_HASH if i == 1 else fresh[i - 1]
        if header.get("previous_segment_hash") != expected_prev:
            return False, (
                f"segment {i:04d}: previous_segment_hash mismatch (chain broken; "
                "segment rewrite detected even if the checkpoint was updated)"
            )
    # Sealed content: fast digest path or full rescan.
    running = ""
    fast = 0
    rescanned = 0
    try:
        last_blob = audit_segment_path(base, last).read_bytes().rstrip(b"\n").split(b"\n")[-1]
    except OSError as exc:
        return False, f"segment {last:04d}: unreadable: {exc}"
    last_sealed = False
    try:
        last_footer = json.loads(last_blob.decode("utf-8"))
        last_sealed = isinstance(last_footer, dict) and last_footer.get(_SEGMENT_ENVELOPE_KEY) == _SEGMENT_FOOTER
    except (UnicodeDecodeError, ValueError):
        last_sealed = False
    sealed = indexes if last_sealed else indexes[:-1]
    for i in sealed:
        seg = audit_segment_path(base, i)
        try:
            stat = seg.stat()
        except OSError as exc:
            return False, f"segment {i:04d}: unreadable: {exc}"
        entry = entries.get(str(i))
        use_fast = (
            checkpoint is not None
            and isinstance(entry, dict)
            and entry.get("mtime_ns") == stat.st_mtime_ns
            and entry.get("size") == stat.st_size
            and entry.get("digest") == fresh[i]
        )
        if use_fast and isinstance(entry, dict):
            # Digest covers the footer, so the recorded tail_hash is trusted.
            running = str(entry.get("tail_hash", ""))
            fast += 1
            continue
        ok, reason, _root, _digest, tail = _rescan_sealed_segment(seg, i, running)
        if not ok:
            return False, reason
        running = tail
        rescanned += 1
    if last_sealed:
        tail_records = 0
    else:
        ok, reason, running, tail_records = _verify_tail_segment(base, last, running)
        if not ok:
            return False, reason
    mode = "full rescan (no checkpoint)" if full_rescan else f"fast-path {fast}, rescanned {rescanned}"
    return (
        True,
        f"segments ok ({len(sealed)} sealed [{mode}], tail {tail_records} records across {len(indexes)} segments)",
    )


def _verify_tail_segment(base: Path, index: int, start_prev: str) -> tuple[bool, str, str, int]:
    """Fully parse the active (footerless) tail. Returns (ok, reason, tail, records)."""
    seg = audit_segment_path(base, index)
    try:
        raw = seg.read_bytes()
    except OSError as exc:
        return False, f"segment {index:04d}: unreadable: {exc}", start_prev, 0
    if not raw:
        return True, f"segment {index:04d}: empty tail", start_prev, 0
    blines = _split_complete_lines(raw)
    if blines is None:
        return False, f"segment {index:04d}: partial tail (torn write; quarantine it)", start_prev, 0
    header, reason = _parse_envelope(blines[0], _SEGMENT_HEADER, index)
    if header is None:
        return False, reason, start_prev, 0
    objs: list[Any] = []
    for pos, line in enumerate(blines[1:], start=1):
        try:
            objs.append(json.loads(line.decode("utf-8")))
        except (UnicodeDecodeError, ValueError) as exc:
            return False, f"segment {index:04d}: tail record {pos} is not valid JSON: {exc}", start_prev, 0
    ok, reason, tail = _verify_chained_objects(objs, start_prev, f"segment {index:04d} tail")
    if not ok:
        return False, reason, start_prev, 0
    return True, reason, tail, len(objs)


class SegmentedAuditWriter:
    """Crash-safe segmented append-only log (P2-08 writer side).

    Data lines pass through unchanged (schemas untouched); each segment is
    wrapped in header/footer envelopes and sealed by rotation at
    ``max_records`` or ``max_bytes``. The active segment is written through
    an :class:`AppendLogWriter` (single FD, 0o600). Startup adopts the tail
    after envelope/JSON/link checks and quarantines a partial/corrupt tail
    (rename aside, never silent truncation). One owner per base path per
    process: rotation is not safe under two live writers on one base.
    """

    def __init__(
        self,
        base_path: Path | str,
        *,
        max_records: int = SEGMENT_MAX_RECORDS,
        max_bytes: int = SEGMENT_MAX_BYTES,
        durability: str = "balanced",
    ) -> None:
        self._base = Path(base_path)
        self._max_records = max(1, int(max_records))
        self._max_bytes = max(1024, int(max_bytes))
        self._durability = durability
        self._lock = threading.Lock()
        self._base.parent.mkdir(parents=True, exist_ok=True)
        self._records = 0
        self._bytes = 0
        self._root = hashlib.sha256()
        self._last_hash = ""
        self._fresh_header: str | None = None
        indexes = _list_segment_indexes(self._base)
        self._active_index = self._adopt_or_roll(indexes)
        self._writer = AppendLogWriter(audit_segment_path(self._base, self._active_index), durability=durability)
        if self._fresh_header is not None:
            header_line = self._fresh_header
            self._fresh_header = None
            self._writer.append(header_line)
            self._writer.checkpoint()
            self._root.update(header_line.encode("utf-8"))
            self._bytes += len(header_line.encode("utf-8"))

    def _reset_state(self) -> None:
        self._records = 0
        self._bytes = 0
        self._root = hashlib.sha256()
        self._last_hash = ""
        self._fresh_header = None

    def _adopt_or_roll(self, indexes: list[int]) -> int:
        """Adopt the tail segment (quarantining corruption) or roll a new one."""
        self._reset_state()
        if not indexes:
            self._fresh_header = self._header_line(1, _GENESIS_SEGMENT_HASH)
            return 1
        last = indexes[-1]
        seg = audit_segment_path(self._base, last)
        try:
            raw = seg.read_bytes()
        except OSError as exc:
            raise RuntimeError(f"segment {last:04d}: unreadable: {exc}") from exc
        expected_prev = _GENESIS_SEGMENT_HASH if last == 1 else _sha256_file(audit_segment_path(self._base, last - 1))

        def _fresh(index: int, prev: str) -> int:
            self._reset_state()
            self._fresh_header = self._header_line(index, prev)
            return index

        blines = _split_complete_lines(raw)
        if blines is None:
            # Torn tail (crash mid-write): quarantine, reuse the index.
            quarantine_segment(seg)
            return _fresh(last, expected_prev)
        if not blines:
            # Empty file (crash before the header): adopt as fresh.
            return _fresh(last, expected_prev)
        header, _ = _parse_envelope(blines[0], _SEGMENT_HEADER, last)
        if header is None or header.get("previous_segment_hash") != expected_prev:
            quarantine_segment(seg)
            return _fresh(last, expected_prev)
        data = blines[1:]
        if data:
            try:
                maybe_footer = json.loads(data[-1].decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                quarantine_segment(seg)
                return _fresh(last, expected_prev)
            if isinstance(maybe_footer, dict) and maybe_footer.get(_SEGMENT_ENVELOPE_KEY) == _SEGMENT_FOOTER:
                # Sealed but never rolled (crash between seal and roll).
                return _fresh(last + 1, _sha256_file(seg))
        # Adopt the tail: envelope + JSON validity only (cheap); the
        # authoritative record-chain check is verify_segmented_chain at
        # session start. Adoption continues from observed content so new rows
        # can never fork from what is on disk.
        self._root.update(blines[0] + b"\n")
        self._bytes += len(blines[0]) + 1
        for line in data:
            try:
                obj = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                quarantine_segment(seg)
                return _fresh(last, expected_prev)
            if not isinstance(obj, dict):
                quarantine_segment(seg)
                return _fresh(last, expected_prev)
            self._root.update(line + b"\n")
            self._bytes += len(line) + 1
            self._records += 1
            if obj.get("hash"):
                self._last_hash = str(obj["hash"])
        return last

    def _header_line(self, index: int, previous: str) -> str:
        header = {
            _SEGMENT_ENVELOPE_KEY: _SEGMENT_HEADER,
            "segment": index,
            "previous_segment_hash": previous,
            "created": datetime.now(timezone.utc).isoformat(),
        }
        return json.dumps(header, sort_keys=True) + "\n"

    @property
    def active_index(self) -> int:
        return self._active_index

    @property
    def last_hash(self) -> str:
        """Last observed chained ``hash`` (adoption point for new rows)."""
        with self._lock:
            return self._last_hash

    def append(self, line: str) -> None:
        """Append data line(s), rotating first when the segment is full.

        Lines must be JSON objects (the envelope/rescan/chain machinery
        requires it); invalid input raises ``ValueError`` before anything is
        written, so corruption surfaces at the call site instead of as a
        quarantined tail at the next startup.
        """
        if not line.endswith("\n"):
            line += "\n"
        objs: list[dict[str, Any]] = []
        for part in line.split("\n")[:-1]:
            try:
                obj = json.loads(part)
            except ValueError as exc:
                raise ValueError(f"segmented audit log requires JSON object lines: {exc}") from exc
            if not isinstance(obj, dict):
                raise ValueError("segmented audit log requires JSON object lines")
            if obj.get(_SEGMENT_ENVELOPE_KEY) in (_SEGMENT_HEADER, _SEGMENT_FOOTER):
                # Envelope-shaped data would confuse seal detection (only
                # blines[0]/blines[-1] are parsed as envelopes).
                raise ValueError("segmented audit log data lines must not use the 'segment_record' key")
            objs.append(obj)
        if not objs:
            raise ValueError("segmented audit log requires a non-empty line")
        encoded = line.encode("utf-8")
        with self._lock:
            if self._records >= self._max_records or self._bytes + len(encoded) > self._max_bytes:
                self._rotate_locked()
            self._writer.append(line)
            self._root.update(encoded)
            self._bytes += len(encoded)
            self._records += len(objs)
            for obj in objs:
                if obj.get("hash"):
                    self._last_hash = str(obj["hash"])

    def _rotate_locked(self) -> None:
        footer = {
            _SEGMENT_ENVELOPE_KEY: _SEGMENT_FOOTER,
            "segment": self._active_index,
            "segment_root_hash": self._root.hexdigest(),
            "records": self._records,
            "bytes": self._bytes,
            "tail_hash": self._last_hash,
        }
        footer_line = json.dumps(footer, sort_keys=True) + "\n"
        footer_bytes = footer_line.encode("utf-8")
        self._writer.append(footer_line)
        self._writer.checkpoint()
        self._writer.close()
        digest = self._root.copy()
        digest.update(footer_bytes)
        digest_hex = digest.hexdigest()
        stat = audit_segment_path(self._base, self._active_index).stat()
        checkpoint = _load_checkpoint(self._base) or {"version": SEGMENT_CHECKPOINT_VERSION, "segments": {}}
        segments = checkpoint.get("segments")
        if not isinstance(segments, dict):
            segments = {}
            checkpoint["segments"] = segments
        segments[str(self._active_index)] = _SegmentEntry(
            digest=digest_hex,
            root_hash=self._root.hexdigest(),
            records=self._records,
            bytes=self._bytes,
            tail_hash=self._last_hash,
            mtime_ns=stat.st_mtime_ns,
            size=stat.st_size,
        )
        new_index = self._active_index + 1
        checkpoint["active"] = new_index
        writer = AppendLogWriter(audit_segment_path(self._base, new_index), durability=self._durability)
        header_line = self._header_line(new_index, digest_hex)
        writer.append(header_line)
        writer.checkpoint()
        _write_checkpoint_atomically(self._base, checkpoint)
        self._writer = writer
        self._active_index = new_index
        self._root = hashlib.sha256(header_line.encode("utf-8"))
        self._bytes = len(header_line.encode("utf-8"))
        self._records = 0

    def checkpoint(self) -> None:
        """fsync the active tail."""
        with self._lock:
            self._writer.checkpoint()

    def close(self) -> None:
        """fsync the tail, record the checkpoint, close the FD. Idempotent."""
        with self._lock:
            if self._writer.closed:
                return
            self._writer.checkpoint()
            checkpoint = _load_checkpoint(self._base) or {"version": SEGMENT_CHECKPOINT_VERSION, "segments": {}}
            checkpoint["active"] = self._active_index
            _write_checkpoint_atomically(self._base, checkpoint)
            self._writer.close()
