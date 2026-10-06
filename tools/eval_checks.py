"""Declarative flag-check executors for the graded eval loop (Feature 1).

The graded eval loop (:func:`tools.eval_harness.run_graded_eval`) verifies each
oracle flag **independently of the agent's claims** — the executor is the truth
source. Check specs are declarative dicts stored target-side in
``eval_targets/*.oracle.json`` (schema v2):

- ``http_login``    — ``{type, url, user, password, expect_status?, expect_body_contains?}``
  — POST a credential pair. A 2xx/3xx response needs an explicit success-body
  marker; a status alone is ambiguous on login endpoints.
- ``http_request``  — ``{type, url, expect_status?, expect_body_contains?}`` —
  anonymous probe; 2xx/3xx success requires a body marker.
- ``tcp_connect``  — ``{type, host, port}`` — direct TCP connection to a
  literal loopback host and oracle-declared port; no DNS or proxy lookup.
- ``file_contains`` — ``{type, path, pattern}`` — ``path`` may be
  ``loot://<relative>`` (resolved against the run's loot/exploit workspace) or
  an absolute operator-box path.
- ``shell_command`` — ``{type, exec, expect_stdout}`` — executed only through
  an explicitly supplied target-bound shell verifier. The normal MCP session
  routes ``run_exploit_terminal`` into the sandbox worker and therefore cannot
  verify a command ran on the target. Without the dedicated verifier this check
  is ``UNVERIFIED`` (False).

Semantics shared by all types:

- **Loopback-only.** HTTP checks refuse any non-loopback URL and TCP checks
  accept only a literal loopback address — the graded suite targets
  ``eval_targets/docker-compose.yml`` services bound to ``127.0.0.1``. Graded
  checks are also pinned to the oracle's declared host and ports.
  Proxy environment variables are ignored, and redirects stay on the original
  URL origin.
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
import http.client as _httpclient
import http.cookiejar
import inspect
import ipaddress
import json
import re
import socket
import string
import threading
import time
from collections.abc import Iterable
from html.parser import HTMLParser
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

#: Default timeout for HTTP probes and blocking MCP session calls (seconds).
_DEFAULT_HTTP_TIMEOUT = 10.0

# Oracle responses are text predicates, so retaining a multi-megabyte response
# is unnecessary. Read at most one byte beyond the limit to detect truncation
# and fail closed instead of evaluating a partial body.
_MAX_HTTP_RESPONSE_BYTES = 2 * 1024 * 1024
_HTTP_READ_CHUNK_BYTES = 64 * 1024

#: Extra headroom on top of the HTTP timeout for a blocking MCP shell call.
_SESSION_CALL_HEADROOM = 30.0

_UNRESOLVED_MARKER = re.compile(r"^\{[A-Za-z_][A-Za-z0-9_]*\}$")


# ---------------------------------------------------------------------------
# HTTP plumbing
# ---------------------------------------------------------------------------


def _url_origin(url: str) -> tuple[str, str, int] | None:
    """Return a normalized HTTP origin, rejecting ambiguous authorities."""
    try:
        parsed = _urlparse.urlsplit(url)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"} or parsed.username or parsed.password:
            return None
        host = (parsed.hostname or "").lower()
        if not host:
            return None
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError:
        return None
    return scheme, host, port


def _is_loopback_url(url: str) -> bool:
    """True only when the URL authority is a literal loopback IP address.

    Deliberately does NOT resolve DNS: host aliases such as ``localhost`` are
    refused because local resolver configuration can remap them. Non-loopback
    URLs are refused before any socket is opened.
    """
    origin = _url_origin(url)
    if origin is None:
        return False
    host = origin[1]
    if not host:
        return False
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _loopback_host_identity(host: str) -> str | None:
    """Normalize a literal loopback host without DNS or scoped IPv6 aliases."""
    raw = str(host or "").strip().lower()
    if not raw or "%" in raw:
        return None
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        return None
    return address.compressed if address.is_loopback else None


class _LoopbackRedirectHandler(_urlrequest.HTTPRedirectHandler):
    """Keep redirects pinned to the configured local evaluation origin."""

    def __init__(self, target_url: str) -> None:
        super().__init__()
        origin = _url_origin(target_url)
        if origin is None or not _is_loopback_url(target_url):
            raise ValueError("redirect target must be a loopback HTTP(S) URL")
        self._target_origin = origin

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _is_loopback_url(newurl) or _url_origin(newurl) != self._target_origin:
            raise OSError("http check refused redirect outside configured loopback origin")
        return super().redirect_request(req, fp, code, msg, headers, newurl)

    def http_error_302(self, req, fp, code, msg, headers):
        """Follow a redirect without reading its potentially unbounded body."""
        if "location" in headers:
            newurl = headers["location"]
        elif "uri" in headers:
            newurl = headers["uri"]
        else:
            return

        parts = _urlparse.urlparse(newurl)
        if parts.scheme not in ("http", "https", "ftp", ""):
            raise _urlerror.HTTPError(
                newurl,
                code,
                f"{msg} - Redirection to url {newurl!r} is not allowed",
                headers,
                fp,
            )
        if not parts.path and parts.netloc:
            parts = list(parts)
            parts[2] = "/"
        newurl = _urlparse.urlunparse(parts)
        newurl = _urlparse.quote(newurl, encoding="iso-8859-1", safe=string.punctuation)
        newurl = _urlparse.urljoin(req.full_url, newurl)

        try:
            new = self.redirect_request(req, fp, code, msg, headers, newurl)
            if new is None:
                return

            if hasattr(req, "redirect_dict"):
                visited = new.redirect_dict = req.redirect_dict
                if visited.get(newurl, 0) >= self.max_repeats or len(visited) >= self.max_redirections:
                    raise _urlerror.HTTPError(
                        req.full_url,
                        code,
                        self.inf_msg + msg,
                        headers,
                        fp,
                    )
            else:
                visited = new.redirect_dict = req.redirect_dict = {}
            visited[newurl] = visited.get(newurl, 0) + 1
        except BaseException:
            # In particular, close the redirect response when our scope guard
            # rejects the destination instead of leaving its socket open.
            fp.close()
            raise

        # The body is irrelevant to a followed redirect. Closing the response
        # avoids urllib's unbounded fp.read() while preserving the same-origin
        # follow behavior and the active request deadline.
        fp.close()
        return self.parent.open(new, timeout=req.timeout)

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


class _HTTPDeadline:
    """Interrupt a urllib request when its absolute wall-clock budget expires."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._deadline = 0.0
        self._timer: threading.Timer | None = None
        self._sockets: list[socket.socket] = []
        self._expired = False
        self._finished = True

    def start(self, timeout: float) -> None:
        bounded_timeout = max(0.01, float(timeout))
        with self._lock:
            if not self._finished:
                raise RuntimeError("HTTP deadline controller is already active")
            self._deadline = time.monotonic() + bounded_timeout
            self._sockets = []
            self._expired = False
            self._finished = False
            timer = threading.Timer(bounded_timeout, self._expire)
            timer.daemon = True
            self._timer = timer
            timer.start()

    def remaining(self) -> float:
        with self._lock:
            remaining = self._deadline - time.monotonic()
            expired = self._expired or self._finished or remaining <= 0
        if expired:
            self._expire()
            raise TimeoutError("HTTP check total deadline exceeded")
        return remaining

    def check(self) -> None:
        self.remaining()

    @staticmethod
    def _interrupt(sock: socket.socket) -> None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass

    def register_socket(self, sock: socket.socket | None) -> None:
        if sock is None:
            return
        with self._lock:
            expired = self._expired or self._finished or time.monotonic() >= self._deadline
            if not expired:
                self._sockets.append(sock)
        if expired:
            self._interrupt(sock)
            raise TimeoutError("HTTP check total deadline exceeded")

    def register_response(self, response: Any) -> None:
        """Track the socket backing an HTTPResponse body after urllib opens it."""
        fp = getattr(response, "fp", None)
        raw = getattr(fp, "raw", None)
        self.register_socket(getattr(raw, "_sock", None))

    def _expire(self) -> None:
        with self._lock:
            if self._finished or self._expired:
                return
            self._expired = True
            sockets = list(self._sockets)
        for sock in sockets:
            self._interrupt(sock)

    def finish(self) -> None:
        with self._lock:
            expired = self._expired or time.monotonic() >= self._deadline
            if not expired:
                self._finished = True
                timer = self._timer
                self._timer = None
                if timer is not None:
                    timer.cancel()
        if expired:
            self._expire()
            raise TimeoutError("HTTP check total deadline exceeded")


class _DeadlineHTTPConnection(_httpclient.HTTPConnection):
    """Register urllib's HTTP socket and response with the active deadline."""

    def __init__(self, host: str, *args: Any, deadline: _HTTPDeadline, **kwargs: Any) -> None:
        self._http_deadline = deadline
        super().__init__(host, *args, **kwargs)

    def connect(self) -> None:
        remaining = self._http_deadline.remaining()
        self.timeout = min(self.timeout, remaining) if self.timeout is not None else remaining
        super().connect()
        self._http_deadline.register_socket(self.sock)

    def getresponse(self) -> _httpclient.HTTPResponse:
        self._http_deadline.check()
        response = super().getresponse()
        self._http_deadline.register_response(response)
        return response


class _DeadlineHTTPSConnection(_httpclient.HTTPSConnection):
    def __init__(self, host: str, *args: Any, deadline: _HTTPDeadline, **kwargs: Any) -> None:
        self._http_deadline = deadline
        super().__init__(host, *args, **kwargs)

    def connect(self) -> None:
        # HTTPSConnection performs the TLS handshake inside its own connect()
        # method. Register the connected TCP socket before that handshake so
        # the absolute deadline can interrupt a peer that drip-feeds TLS data.
        remaining = self._http_deadline.remaining()
        self.timeout = min(self.timeout, remaining) if self.timeout is not None else remaining
        _httpclient.HTTPConnection.connect(self)
        self._http_deadline.register_socket(self.sock)
        connected_socket = self.sock
        if connected_socket is None:
            raise OSError("HTTP connection did not create a socket")
        server_hostname = getattr(self, "_tunnel_host", None) or self.host
        context = getattr(self, "_context", None)
        if context is None:
            raise OSError("HTTPS connection has no SSL context")
        self.sock = context.wrap_socket(
            connected_socket,
            server_hostname=server_hostname,
            do_handshake_on_connect=False,
        )
        self._http_deadline.register_socket(self.sock)
        self.sock.do_handshake()

    def getresponse(self) -> _httpclient.HTTPResponse:
        self._http_deadline.check()
        response = super().getresponse()
        self._http_deadline.register_response(response)
        return response


class _DeadlineHTTPHandler(_urlrequest.HTTPHandler):
    def __init__(self, deadline: _HTTPDeadline) -> None:
        super().__init__()
        self._deadline = deadline

    def http_open(self, req: Any) -> Any:
        self._deadline.check()
        return self.do_open(
            lambda host, **kwargs: _DeadlineHTTPConnection(host, deadline=self._deadline, **kwargs), req
        )


class _DeadlineHTTPSHandler(_urlrequest.HTTPSHandler):
    def __init__(self, deadline: _HTTPDeadline) -> None:
        super().__init__()
        self._deadline = deadline

    def https_open(self, req: Any) -> Any:
        self._deadline.check()
        return self.do_open(
            lambda host, **kwargs: _DeadlineHTTPSConnection(host, deadline=self._deadline, **kwargs),
            req,
            context=getattr(self, "_context", None),
        )


class _HiddenInputs(HTMLParser):
    """Collect hidden form fields so local login fixtures can use CSRF tokens."""

    def __init__(self) -> None:
        super().__init__()
        self.fields: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag.lower() != "input" or (values.get("type") or "").lower() != "hidden":
            return
        name, value = values.get("name"), values.get("value")
        if name and value is not None:
            self.fields[name] = value


def _loopback_opener(
    target_url: str,
    cookie_jar: http.cookiejar.CookieJar | None = None,
    *,
    deadline: _HTTPDeadline | None = None,
) -> Any:
    # urllib otherwise imports HTTP_PROXY/HTTPS_PROXY from the process
    # environment, allowing a configured proxy to receive loopback credentials
    # or fabricate an oracle response. Evaluation traffic must stay direct.
    deadline_controller = deadline or _HTTPDeadline()
    handlers: list[Any] = [
        _urlrequest.ProxyHandler({}),
        _LoopbackRedirectHandler(target_url),
        _DeadlineHTTPHandler(deadline_controller),
        _DeadlineHTTPSHandler(deadline_controller),
    ]
    if cookie_jar is not None:
        handlers.append(_urlrequest.HTTPCookieProcessor(cookie_jar))
    opener = _urlrequest.build_opener(*handlers)
    setattr(opener, "_eval_http_deadline", deadline_controller)
    return opener


def _read_bounded_response(response: Any, deadline: _HTTPDeadline) -> str:
    """Read a complete response body with bounded memory and deadline checks."""
    try:
        content_length = response.headers.get("Content-Length")
        if content_length is not None and int(content_length) > _MAX_HTTP_RESPONSE_BYTES:
            raise OSError("http check response exceeds size limit")
    except (TypeError, ValueError):
        # A malformed length is left to the bounded streaming read below.
        pass

    body = bytearray()
    while len(body) <= _MAX_HTTP_RESPONSE_BYTES:
        deadline.check()
        chunk_size = min(_HTTP_READ_CHUNK_BYTES, _MAX_HTTP_RESPONSE_BYTES + 1 - len(body))
        chunk = response.read(chunk_size)
        deadline.check()
        if not chunk:
            return body.decode("utf-8", errors="replace")
        body.extend(chunk)
        if len(body) > _MAX_HTTP_RESPONSE_BYTES:
            raise OSError("http check response exceeds size limit")
    raise OSError("http check response exceeds size limit")


def _http_fetch(
    url: str,
    *,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = _DEFAULT_HTTP_TIMEOUT,
    opener: Any | None = None,
) -> "tuple[int, str]":
    """Perform one HTTP request and return ``(status, body_text)``.

    HTTP error statuses (401/403/...) are returned as normal results rather
    than raised — a login probe that gets a 401 is a legitimate observation,
    not an executor failure. Transport-level failures (refused, DNS, timeout)
    raise :class:`OSError` to the caller.
    """
    if not _is_loopback_url(url):
        raise OSError("http check refused non-loopback URL")
    request = _urlrequest.Request(url, data=data, headers=headers or {}, method="POST" if data else "GET")
    client = opener or _loopback_opener(url)
    deadline = getattr(client, "_eval_http_deadline", None)
    if not isinstance(deadline, _HTTPDeadline):
        raise OSError("http check opener does not enforce a total deadline")
    deadline.start(timeout)
    try:
        try:
            with client.open(request, timeout=deadline.remaining()) as resp:  # noqa: S310 - loopback-only by design
                body = _read_bounded_response(resp, deadline)
                return int(resp.status), body
        except _urlerror.HTTPError as exc:
            try:
                body = _read_bounded_response(exc, deadline)
            finally:
                exc.close()
            return int(exc.code), body
    finally:
        deadline.finish()


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


def _shell_via_target_executor(
    target_shell_executor: Callable[[str], Any] | None,
    command: str,
    loop: Any,
    timeout: float,
) -> str | None:
    """Run via an explicitly target-bound executor; ``None`` = UNVERIFIED."""
    if target_shell_executor is None:
        return None
    try:
        if inspect.iscoroutinefunction(target_shell_executor):
            if loop is None:
                return None  # async target session without bound loop -> UNVERIFIED
            future = asyncio.run_coroutine_threadsafe(target_shell_executor(command), loop)
            return _mcp_result_text(future.result(timeout=timeout))
        result = target_shell_executor(command)
        if inspect.isawaitable(result):
            return None
        return _mcp_result_text(result)
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
    success_body_marker = check.get("expect_body_contains")
    if 200 <= expect_status < 400 and (not isinstance(success_body_marker, str) or not success_body_marker):
        return False, "http_login: successful status requires expect_body_contains"
    if isinstance(success_body_marker, str) and _UNRESOLVED_MARKER.fullmatch(success_body_marker.strip()):
        return False, "http_login: expect_body_contains must be resolved"

    cookie_jar = http.cookiejar.CookieJar()
    opener = _loopback_opener(url, cookie_jar)
    try:
        _, login_page = _http_fetch(url, timeout=timeout, opener=opener)
    except OSError as exc:
        return False, f"http_login: transport error for {url}: {exc}"
    hidden_inputs = _HiddenInputs()
    hidden_inputs.feed(login_page)

    # Two credential-carrying attempts, judged independently: JSON first
    # (REST/JSON login endpoints such as juice-shop /rest/user/login), then a
    # classic urlencoded form POST (PHP logins such as DVWA login.php). A pass
    # on either satisfies the check; the extra keys each style ignores are
    # harmless, which keeps one declarative spec usable across both shapes.
    # Do not attach an HTTP Basic header: it changes the authentication scheme
    # and causes some form handlers to reject otherwise valid credentials.
    attempts: list[tuple[str, bytes]] = [
        (
            "application/json",
            json.dumps({"user": user, "username": user, "email": user, "password": password}).encode("utf-8"),
        ),
        (
            "application/x-www-form-urlencoded",
            _urlparse.urlencode(
                {
                    **hidden_inputs.fields,
                    "user": user,
                    "username": user,
                    "email": user,
                    "password": password,
                    "Login": "Login",
                }
            ).encode("utf-8"),
        ),
    ]
    last_status = -1
    body_marker_mismatch = False
    for content_type, data in attempts:
        if content_type == "application/x-www-form-urlencoded":
            # Some form handlers rotate CSRF tokens after a failed JSON
            # attempt, so fetch the current login form and hidden fields just
            # before posting the form credentials.
            try:
                _, login_page = _http_fetch(url, timeout=timeout, opener=opener)
            except OSError as exc:
                return False, f"http_login: transport error for {url}: {exc}"
            hidden_inputs = _HiddenInputs()
            hidden_inputs.feed(login_page)
            form_values = {
                **hidden_inputs.fields,
                "user": user,
                "username": user,
                "email": user,
                "password": password,
                "Login": "Login",
            }
            data = _urlparse.urlencode(form_values).encode("utf-8")
        headers = {"Content-Type": content_type}
        try:
            status, body = _http_fetch(url, data=data, headers=headers, timeout=timeout, opener=opener)
        except OSError as exc:
            return False, f"http_login: transport error for {url}: {exc}"
        last_status = status
        if status == expect_status:
            if 200 <= status < 400 and (not isinstance(success_body_marker, str) or success_body_marker not in body):
                body_marker_mismatch = True
                continue
            if 200 <= status < 400:
                return True, f"http_login: status={status} and success body marker matched"
            return True, f"http_login: status={status} (expected {expect_status})"
    if body_marker_mismatch:
        return False, "http_login: success body marker not found"
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
    contains = check.get("expect_body_contains")
    if 200 <= expect_status < 400 and (not isinstance(contains, str) or not contains):
        return False, "http_request: successful status requires expect_body_contains"
    if isinstance(contains, str) and _UNRESOLVED_MARKER.fullmatch(contains.strip()):
        return False, "http_request: expect_body_contains must be resolved"
    try:
        status, body = _http_fetch(url, timeout=timeout)
    except OSError as exc:
        return False, f"http_request: transport error for {url}: {exc}"
    if status != expect_status:
        return False, f"http_request: status={status} != expected {expect_status} for {url}"
    if 200 <= status < 400 and (not isinstance(contains, str) or contains not in body):
        return False, f"http_request: success body marker not found for {url}"
    if isinstance(contains, str) and contains and contains not in body:
        return False, f"http_request: body of {url} does not contain {contains!r}"
    return True, f"http_request: status={status} success body marker matched for {url}"


def _check_tcp_connect(
    check: dict[str, Any],
    timeout: float,
    *,
    target_host: str | None,
    allowed_ports: set[int],
) -> "tuple[bool, str]":
    host = str(check.get("host", "") or "").strip()
    port = check.get("port")
    host_identity = _loopback_host_identity(host)
    target_identity = _loopback_host_identity(target_host or "")
    if host_identity is None:
        return False, "tcp_connect: refused non-loopback or non-literal host"
    if target_identity is None:
        return False, "tcp_connect: oracle target host is missing or not loopback"
    if host_identity != target_identity:
        return False, "tcp_connect: refused host outside oracle target scope"
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        return False, "tcp_connect: invalid port"
    if not allowed_ports or port not in allowed_ports:
        return False, "tcp_connect: refused port outside oracle target scope"
    try:
        with socket.create_connection((host, port), timeout=max(0.01, timeout)):
            return True, f"tcp_connect: connected to {host}:{port}"
    except OSError as exc:
        return False, f"tcp_connect: connection failed for {host}:{port}: {exc}"


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


def _check_shell_command(
    check: dict[str, Any],
    target_shell_executor: Callable[[str], Any] | None,
    loop: Any,
    timeout: float,
) -> "tuple[bool, str]":
    command = str(check.get("exec", "") or "")
    if not command:
        return False, "shell_command: missing exec"
    if target_shell_executor is None:
        return False, "UNVERIFIED: no target-bound shell verifier is available"
    output = _shell_via_target_executor(target_shell_executor, command, loop, timeout)
    if output is None:
        return False, "UNVERIFIED: target-bound shell verifier failed"
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
    target_shell_executor: Callable[[str], Any] | None = None,
    target_host: str | None = None,
    target_ports: Iterable[int] | None = None,
) -> CheckExecutor:
    """Build a sync ``executor(check) -> (passed, detail)`` for flag checks.

    Args:
        session: accepted for compatibility, but not used for shell checks.
            MCP ``run_exploit_terminal`` runs in the sandbox worker and is not
            evidence of target-side command execution.
        workspace: base directory for ``loot://`` paths in ``file_contains``.
        loop: the event loop an async MCP ``session`` is bound to (captured by
            the graded loop so a blocking shell call can be bridged with
            ``run_coroutine_threadsafe`` from the worker thread).
        http_timeout: timeout for HTTP probes and blocking session calls.
        target_shell_executor: optional callback bound to an authenticated
            session for the intended target. Only this dedicated callback can
            make ``shell_command`` checks pass; callers must enforce target
            identity and scope before supplying it.
        target_host: optional oracle-declared loopback host. When supplied,
            HTTP and TCP checks must use this exact host.
        target_ports: optional oracle-declared ports. When ``target_host`` is
            supplied, HTTP and TCP checks must use one of these ports; an absent or
            empty port set fails closed.
    """
    allowed_ports = {
        port
        for port in (target_ports or ())
        if isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535
    }

    def _within_oracle_scope(check: dict[str, Any]) -> str | None:
        if target_host is None:
            return None
        url = str(check.get("url", "") or "")
        origin = _url_origin(url)
        try:
            declared_host = _urlparse.urlsplit(f"//{target_host}").hostname
        except ValueError:
            declared_host = None
        is_loopback_target = False
        if declared_host:
            try:
                is_loopback_target = ipaddress.ip_address(declared_host).is_loopback
            except ValueError:
                is_loopback_target = declared_host.lower() == "localhost"
        if not declared_host or not is_loopback_target:
            return "HTTP check refused: oracle target host is not loopback"
        if not allowed_ports:
            return "HTTP check refused: oracle target ports are missing"
        if origin is None or origin[1] != declared_host.lower() or origin[2] not in allowed_ports:
            return "HTTP check refused outside oracle target host/port scope"
        return None

    def _execute(check: dict[str, Any]) -> "tuple[bool, str]":
        if not isinstance(check, dict):
            return False, f"unsupported check spec: {check!r}"
        check_type = str(check.get("type", "") or "")
        if check_type == "http_login":
            scope_error = _within_oracle_scope(check)
            if scope_error:
                return False, scope_error
            return _check_http_login(check, http_timeout)
        if check_type == "http_request":
            scope_error = _within_oracle_scope(check)
            if scope_error:
                return False, scope_error
            return _check_http_request(check, http_timeout)
        if check_type == "tcp_connect":
            return _check_tcp_connect(
                check,
                http_timeout,
                target_host=target_host,
                allowed_ports=allowed_ports,
            )
        if check_type == "file_contains":
            return _check_file_contains(check, Path(workspace) if workspace else None)
        if check_type == "shell_command":
            return _check_shell_command(
                check,
                target_shell_executor,
                loop,
                http_timeout + _SESSION_CALL_HEADROOM,
            )
        return False, f"unsupported check type: {check_type!r}"

    return _execute
