"""Declarative flag-check executors for the graded eval loop (Feature 1).

The graded eval loop (:func:`tools.eval_harness.run_graded_eval`) verifies each
oracle flag **independently of the agent's claims** — the executor is the truth
source. Check specs are declarative dicts stored target-side in
``eval_targets/*.oracle.json`` (schema v2):

- ``http_login``    — ``{type, url, user, password, expect_status?}`` — POST a
  credential pair and judge by HTTP response status.
- ``http_request``  — ``{type, url, expect_status?, expect_body_contains?}`` —
  anonymous probe (juice-shop / k8s anonymous-access style checks).
- ``file_contains`` — ``{type, path, pattern}`` — ``path`` may be
  ``loot://<relative>`` (resolved against the run's loot/exploit workspace) or
  an absolute operator-box path.
- ``shell_command`` — ``{type, exec, expect_stdout}`` — executed through the
  injected MCP session (``run_exploit_terminal`` in production, a scripted fake
  in tests). A missing session degrades to ``UNVERIFIED`` (False), never a pass.

Semantics shared by all types:

- **Loopback-only.** HTTP checks refuse any non-loopback URL — the graded suite
  targets ``eval_targets/docker-compose.yml`` services bound to ``127.0.0.1``.
- **Nonzero-exit-tolerant.** ``shell_command`` judges stdout content only; a
  nonzero exit status alone never fails a check (e.g. ``cat`` on a missing
  flag file yields empty stdout, which *does* fail an any-output expect).
- **Empty ``expect_stdout`` = any output.** A check expecting any output passes
  when the executor produced non-empty text; an explicit ``expect_stdout``
  substring must appear in the output.

This module is deliberately separate from :mod:`tools.eval_harness` to keep the
harness under the CI god-file budget (no new file >1000 LOC / 72kB).
"""

from __future__ import annotations

import asyncio
import base64
import inspect
import ipaddress
import json
from pathlib import Path
from typing import Any, Callable
from urllib import error as _urlerror
from urllib import parse as _urlparse
from urllib import request as _urlrequest

__all__ = [
    "CheckExecutor",
    "default_check_executor",
]

#: A flag-check executor: takes the check spec dict, returns (passed, detail).
CheckExecutor = Callable[[dict[str, Any]], "tuple[bool, str]"]

#: Hosts accepted verbatim as loopback without an ipaddress round-trip.
_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]", "local"}

#: Default timeout for HTTP probes and blocking MCP session calls (seconds).
_DEFAULT_HTTP_TIMEOUT = 10.0

#: Extra headroom on top of the HTTP timeout for a blocking MCP shell call.
_SESSION_CALL_HEADROOM = 30.0


# ---------------------------------------------------------------------------
# HTTP plumbing
# ---------------------------------------------------------------------------


def _is_loopback_url(url: str) -> bool:
    """True when the URL authority is a literal loopback address (or localhost).

    Deliberately does NOT resolve DNS: only literal IPs / ``localhost`` are
    accepted, so a check can never be aimed at a public host by a crafted
    hostname. Non-loopback URLs are refused before any socket is opened.
    """
    try:
        host = (_urlparse.urlsplit(url).hostname or "").lower()
    except ValueError:
        return False
    if not host:
        return False
    if host in _LOOPBACK_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _http_fetch(
    url: str,
    *,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = _DEFAULT_HTTP_TIMEOUT,
) -> "tuple[int, str]":
    """Perform one HTTP request and return ``(status, body_text)``.

    HTTP error statuses (401/403/...) are returned as normal results rather
    than raised — a login probe that gets a 401 is a legitimate observation,
    not an executor failure. Transport-level failures (refused, DNS, timeout)
    raise :class:`OSError` to the caller.
    """
    request = _urlrequest.Request(url, data=data, headers=headers or {}, method="POST" if data else "GET")
    try:
        with _urlrequest.urlopen(request, timeout=timeout) as resp:  # noqa: S310 - loopback-only by design
            return int(resp.status), resp.read().decode("utf-8", errors="replace")
    except _urlerror.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except OSError:
            body = ""
        return int(exc.code), body


# ---------------------------------------------------------------------------
# MCP session plumbing
# ---------------------------------------------------------------------------


def _mcp_result_text(result: Any) -> str:
    """Best-effort text extraction from an MCP ``call_tool`` result shape."""
    if result is None:
        return ""
    if isinstance(result, str):
        return result
    if isinstance(result, dict):
        for key in ("output", "stdout", "text", "result"):
            value = result.get(key)
            if isinstance(value, str):
                return value
        return json.dumps(result, default=str)
    content = getattr(result, "content", None)
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            text = getattr(item, "text", None)
            if isinstance(text, str):
                parts.append(text)
        return "\n".join(parts)
    return str(result)


def _shell_via_session(session: Any, command: str, loop: Any, timeout: float) -> str | None:
    """Run ``command`` through the injected session; ``None`` = UNVERIFIED.

    Accepted session shapes:

    - sync callable ``(tool_name, arguments) -> result`` (the
      ``SwarmMcpBridge.dispatch`` / ``poe_verifier`` executor shape);
    - object exposing a sync ``call_tool(tool_name, arguments)``;
    - object exposing an async ``call_tool`` — bridged onto ``loop`` (the loop
      the session is bound to) via ``run_coroutine_threadsafe``. The graded
      loop calls :func:`tools.eval_harness.verify_flag_check` through
      ``asyncio.to_thread``, so a blocking wait here is safe; calling it
      directly on the event-loop thread with an async session would deadlock,
      and is refused rather than hung.
    """
    try:
        if callable(session) and not callable(getattr(session, "call_tool", None)):
            return _mcp_result_text(session("run_exploit_terminal", {"command": command}))
        call_tool = getattr(session, "call_tool", None)
        if call_tool is None:
            return None
        if inspect.iscoroutinefunction(call_tool):
            if loop is None:
                return None  # async session with no bound loop -> cannot bridge safely
            future = asyncio.run_coroutine_threadsafe(call_tool("run_exploit_terminal", {"command": command}), loop)
            return _mcp_result_text(future.result(timeout=timeout))
        return _mcp_result_text(call_tool("run_exploit_terminal", {"command": command}))
    except Exception:  # noqa: BLE001 -- any executor failure degrades to UNVERIFIED, never raises
        return None


# ---------------------------------------------------------------------------
# Per-check-type implementations
# ---------------------------------------------------------------------------


def _check_http_login(check: dict[str, Any], timeout: float) -> "tuple[bool, str]":
    url = str(check.get("url", "") or "")
    if not url:
        return False, "http_login: missing url"
    if not _is_loopback_url(url):
        return False, f"http_login: refused non-loopback url {url}"
    user = str(check.get("user", "") or "")
    password = str(check.get("password", "") or "")
    try:
        expect_status = int(check.get("expect_status", 200) or 200)
    except (TypeError, ValueError):
        expect_status = 200

    # Two credential-carrying attempts, judged independently: JSON first
    # (REST/JSON login endpoints such as juice-shop /rest/user/login), then a
    # classic urlencoded form POST (PHP logins such as DVWA login.php). A pass
    # on either satisfies the check; the extra keys each style ignores are
    # harmless, which keeps one declarative spec usable across both shapes.
    basic = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    attempts: list[tuple[str, bytes]] = [
        (
            "application/json",
            json.dumps({"user": user, "username": user, "email": user, "password": password}).encode("utf-8"),
        ),
        (
            "application/x-www-form-urlencoded",
            _urlparse.urlencode({"user": user, "username": user, "email": user, "password": password}).encode("utf-8"),
        ),
    ]
    last_status = -1
    for content_type, data in attempts:
        headers = {"Content-Type": content_type, "Authorization": f"Basic {basic}"}
        try:
            status, _body = _http_fetch(url, data=data, headers=headers, timeout=timeout)
        except OSError as exc:
            return False, f"http_login: transport error for {url}: {exc}"
        last_status = status
        if status == expect_status:
            return True, f"http_login: status={status} (expected {expect_status})"
    return False, f"http_login: status={last_status} != expected {expect_status} for {url}"


def _check_http_request(check: dict[str, Any], timeout: float) -> "tuple[bool, str]":
    url = str(check.get("url", "") or "")
    if not url:
        return False, "http_request: missing url"
    if not _is_loopback_url(url):
        return False, f"http_request: refused non-loopback url {url}"
    try:
        expect_status = int(check.get("expect_status", 200) or 200)
    except (TypeError, ValueError):
        expect_status = 200
    try:
        status, body = _http_fetch(url, timeout=timeout)
    except OSError as exc:
        return False, f"http_request: transport error for {url}: {exc}"
    if status != expect_status:
        return False, f"http_request: status={status} != expected {expect_status} for {url}"
    contains = check.get("expect_body_contains")
    if contains is not None and str(contains) not in body:
        return False, f"http_request: body of {url} does not contain {str(contains)!r}"
    return True, f"http_request: status={status} body matched for {url}"


def _resolve_check_path(path: str, workspace: Path | None) -> Path | None:
    """Resolve a ``file_contains`` path: ``loot://<rel>`` against the workspace."""
    if path.startswith("loot://"):
        if workspace is None:
            return None
        return workspace / path[len("loot://") :]
    return Path(path)


def _check_file_contains(check: dict[str, Any], workspace: Path | None) -> "tuple[bool, str]":
    raw_path = str(check.get("path", "") or "")
    if not raw_path:
        return False, "file_contains: missing path"
    pattern = check.get("pattern")
    resolved = _resolve_check_path(raw_path, workspace)
    if resolved is None:
        return False, "file_contains: loot:// path but no workspace provided"
    if not resolved.is_file():
        return False, f"file_contains: file not found: {resolved}"
    try:
        text = resolved.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return False, f"file_contains: read failed for {resolved}: {exc}"
    if pattern is None:
        return True, f"file_contains: {resolved} exists"
    if str(pattern) not in text:
        return False, f"file_contains: pattern {str(pattern)!r} not in {resolved}"
    return True, f"file_contains: pattern matched in {resolved}"


def _check_shell_command(check: dict[str, Any], session: Any, loop: Any, timeout: float) -> "tuple[bool, str]":
    command = str(check.get("exec", "") or "")
    if not command:
        return False, "shell_command: missing exec"
    if session is None:
        return False, "UNVERIFIED: shell_command check with no session executor available"
    output = _shell_via_session(session, command, loop, timeout)
    if output is None:
        return False, "UNVERIFIED: shell_command executor failed (or async session without a bound loop)"
    expect_stdout = check.get("expect_stdout")
    if expect_stdout is None or str(expect_stdout) == "":
        # Empty expect = any output. Nonzero exit is tolerated; only evidence
        # of output counts (a missing flag file cats nothing).
        if output.strip():
            return True, "shell_command: produced output (any-output expect)"
        return False, "shell_command: no output (any-output expect not met)"
    needle = str(expect_stdout)
    if needle in output:
        return True, "shell_command: expect_stdout matched"
    return False, "shell_command: expect_stdout not found in output"


# ---------------------------------------------------------------------------
# Executor factory
# ---------------------------------------------------------------------------


def default_check_executor(
    session: Any = None,
    workspace: str | Path | None = None,
    *,
    loop: Any = None,
    http_timeout: float = _DEFAULT_HTTP_TIMEOUT,
) -> CheckExecutor:
    """Build a sync ``executor(check) -> (passed, detail)`` for flag checks.

    Args:
        session: optional MCP session (or sync ``(tool_name, args) -> result``
            callable) used by ``shell_command`` checks; ``None`` degrades every
            ``shell_command`` check to ``UNVERIFIED`` (False).
        workspace: base directory for ``loot://`` paths in ``file_contains``.
        loop: the event loop an async MCP ``session`` is bound to (captured by
            the graded loop so a blocking shell call can be bridged with
            ``run_coroutine_threadsafe`` from the worker thread).
        http_timeout: timeout for HTTP probes and blocking session calls.
    """

    def _execute(check: dict[str, Any]) -> "tuple[bool, str]":
        if not isinstance(check, dict):
            return False, f"unsupported check spec: {check!r}"
        check_type = str(check.get("type", "") or "")
        if check_type == "http_login":
            return _check_http_login(check, http_timeout)
        if check_type == "http_request":
            return _check_http_request(check, http_timeout)
        if check_type == "file_contains":
            return _check_file_contains(check, Path(workspace) if workspace else None)
        if check_type == "shell_command":
            return _check_shell_command(check, session, loop, http_timeout + _SESSION_CALL_HEADROOM)
        return False, f"unsupported check type: {check_type!r}"

    return _execute
