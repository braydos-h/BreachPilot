"""Bounded public-page transport with DNS pinning and validated redirects.

Only the local research fetch fallback uses this transport. It deliberately
does not inherit environment proxies: a proxy would resolve the destination
outside the address validation boundary.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import ssl
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeVar
from urllib.parse import urljoin, urlsplit

from tools.research.text_utils import validate_url

MAX_RESPONSE_BYTES = 2_000_000
MAX_REDIRECTS = 5
_IPV6_TRANSLATION_PREFIXES = tuple(
    ipaddress.ip_network(prefix)
    for prefix in (
        "64:ff9b::/96",  # RFC 6052 well-known NAT64 prefix
        "64:ff9b:1::/48",  # RFC 8215 local-use NAT64 prefix
        "2002::/16",  # 6to4 embeds an IPv4 destination
        "2001::/32",  # Teredo embeds an IPv4 destination
    )
)
_RESOLVE_SCRIPT = (
    "import json,socket,sys;"
    "print(json.dumps([[family,address[0]] for family,_,_,_,address in "
    "socket.getaddrinfo(sys.argv[1],int(sys.argv[2]),type=socket.SOCK_STREAM)]))"
)
_T = TypeVar("_T")


def _interrupt_socket(sock: socket.socket) -> None:
    """Interrupt blocking socket I/O, including buffered header reads."""
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


class _Deadline:
    """One absolute budget shared by DNS and all sockets in a fetch operation.

    Socket timeouts only bound inactivity. A peer can otherwise keep an HTTP
    header read alive by sending bytes just before each timeout. The watchdog
    closes every active socket at the absolute deadline to interrupt those
    reads, TLS handshakes, and request writes.
    """

    def __init__(self, timeout: float, message: str) -> None:
        if timeout <= 0:
            raise TimeoutError(message)
        self._when = time.monotonic() + timeout
        self._message = message
        self._lock = threading.Lock()
        self._sockets: set[socket.socket] = set()
        self._expired = False
        self._closed = False
        self._timer = threading.Timer(timeout, self._expire)
        self._timer.daemon = True
        self._timer.start()

    def _expire(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._expired = True
            sockets = tuple(self._sockets)
        for sock in sockets:
            _interrupt_socket(sock)

    def _is_expired(self) -> bool:
        with self._lock:
            expired = self._expired or time.monotonic() >= self._when
        if expired:
            self._expire()
        return expired

    def check(self, cause: BaseException | None = None) -> None:
        if self._is_expired():
            error = TimeoutError(self._message)
            if cause is not None:
                raise error from cause
            raise error

    def remaining(self) -> float:
        self.check()
        return max(0.0, self._when - time.monotonic())

    def register(self, sock: socket.socket) -> None:
        with self._lock:
            expired = self._expired or self._closed or time.monotonic() >= self._when
            if not expired:
                self._sockets.add(sock)
            else:
                self._expired = True
        if expired:
            _interrupt_socket(sock)
            self.check()

    def replace(self, old: socket.socket, new: socket.socket) -> None:
        with self._lock:
            self._sockets.discard(old)
            expired = self._expired or self._closed or time.monotonic() >= self._when
            if not expired:
                self._sockets.add(new)
            else:
                self._expired = True
        if expired:
            _interrupt_socket(new)
            self.check()

    def unregister(self, sock: socket.socket | None) -> None:
        if sock is not None:
            with self._lock:
                self._sockets.discard(sock)

    def close(self) -> None:
        self._timer.cancel()
        with self._lock:
            if self._closed:
                return
            self._closed = True
            sockets = tuple(self._sockets)
            self._sockets.clear()
        for sock in sockets:
            _interrupt_socket(sock)


def _deadline_call(deadline: _Deadline, operation: Callable[[], _T]) -> _T:
    deadline.check()
    try:
        result = operation()
    except Exception as exc:
        deadline.check(exc)
        raise
    deadline.check()
    return result


def _resolve_addresses(host: str, port: int, timeout: float) -> list[tuple[int, str]]:
    """Resolve in a killable process so a stalled system resolver is bounded.

    Cancelling a thread blocked in ``getaddrinfo`` does not stop the resolver
    call. A short-lived isolated interpreter lets ``subprocess.run`` enforce
    the remaining fetch deadline and terminate a stuck lookup.
    """
    if timeout <= 0:
        raise TimeoutError("research DNS resolution deadline exceeded")
    try:
        completed = subprocess.run(
            [sys.executable, "-I", "-c", _RESOLVE_SCRIPT, host, str(port)],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            close_fds=True,
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError("research DNS resolution deadline exceeded") from exc
    if completed.returncode != 0:
        raise OSError("research hostname resolution failed")
    try:
        rows = json.loads(completed.stdout)
        if not isinstance(rows, list):
            raise ValueError
        result = [(int(row[0]), str(row[1])) for row in rows if isinstance(row, list) and len(row) == 2]
    except (ValueError, TypeError, IndexError, json.JSONDecodeError) as exc:
        raise OSError("research hostname resolution returned invalid data") from exc
    return result


def resolve_addresses_bounded(host: str, port: int, timeout: float) -> list[tuple[int, str]]:
    """Resolve one hostname in a killable process with a strict deadline."""
    return _resolve_addresses(host, port, timeout)


@dataclass(frozen=True)
class FetchPolicy:
    allow_local_fetch: bool = False
    allowed_domains: tuple[str, ...] = ()
    blocked_domains: tuple[str, ...] = ()


def _validated_destination(
    url: str,
    policy: FetchPolicy,
    *,
    timeout: float,
    pin_cache: dict[tuple[str, int], tuple[tuple[int, str], ...]] | None = None,
) -> tuple[str, str, int, tuple[str, ...]]:
    if any(ord(char) <= 32 or ord(char) == 127 for char in url):
        raise ValueError("BLOCKED: URL contains whitespace or control characters.")
    clean = validate_url(
        url,
        allowed_domains=list(policy.allowed_domains),
        blocked_domains=list(policy.blocked_domains),
        allow_local_fetch=policy.allow_local_fetch,
    )
    if clean.startswith("BLOCKED:"):
        raise ValueError(clean)
    parsed = urlsplit(clean)
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("BLOCKED: URL credentials are not supported.")
    host = parsed.hostname or ""
    if not host or "%" in host:
        raise ValueError("BLOCKED: invalid URL hostname.")
    port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
    if not 1 <= port <= 65535:
        raise ValueError("BLOCKED: invalid URL port.")
    cache_key = (host.lower(), port)
    cached = pin_cache.get(cache_key) if pin_cache is not None else None
    if cached is not None:
        addresses = list(cached)
    else:
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            addresses = _resolve_addresses(host, port, timeout)
        else:
            family: int = socket.AF_INET6 if isinstance(literal, ipaddress.IPv6Address) else socket.AF_INET
            addresses = [(family, str(literal))]
    pinned: list[str] = []
    for family, address in addresses:
        if family not in (socket.AF_INET, socket.AF_INET6):
            raise ValueError("BLOCKED: unsupported destination address family.")
        ip = ipaddress.ip_address(address)
        checked = ip.ipv4_mapped if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped else ip
        translated = isinstance(ip, ipaddress.IPv6Address) and any(
            ip in prefix for prefix in _IPV6_TRANSLATION_PREFIXES
        )
        if not policy.allow_local_fetch and (not checked.is_global or checked.is_multicast or translated):
            raise ValueError("BLOCKED: hostname resolves to a private or non-public address.")
        if str(ip) not in pinned:
            pinned.append(str(ip))
    if not pinned:
        raise ValueError("BLOCKED: hostname has no usable addresses.")
    if pin_cache is not None and cached is None:
        pin_cache[cache_key] = tuple(addresses)
    return clean, host, port, tuple(pinned)


def _connect_pinned(addresses: tuple[str, ...], port: int, deadline: _Deadline) -> socket.socket:
    """Try only validated numeric addresses within the operation's deadline."""
    last_error: OSError | None = None
    for address in addresses:
        remaining = deadline.remaining()
        ip = ipaddress.ip_address(address)
        family = socket.AF_INET6 if isinstance(ip, ipaddress.IPv6Address) else socket.AF_INET
        sockaddr: tuple[object, ...] = (str(ip), port, 0, 0) if family == socket.AF_INET6 else (str(ip), port)
        sock = socket.socket(family, socket.SOCK_STREAM)
        deadline.register(sock)
        try:
            sock.settimeout(remaining)
            _deadline_call(deadline, lambda: sock.connect(sockaddr))
            return sock
        except OSError as exc:
            deadline.unregister(sock)
            _interrupt_socket(sock)
            deadline.check(exc)
            last_error = exc
        except Exception:
            deadline.unregister(sock)
            _interrupt_socket(sock)
            raise
    if last_error is not None:
        raise last_error
    raise ValueError("BLOCKED: hostname has no usable addresses.")


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, pinned: tuple[str, ...], deadline: _Deadline) -> None:
        super().__init__(host, port, timeout=deadline.remaining())
        self._pinned = pinned
        self._deadline = deadline

    def connect(self) -> None:
        # Numeric canonical IP only: never re-resolve the untrusted hostname.
        self.sock = _connect_pinned(self._pinned, self.port, self._deadline)

    def close(self) -> None:
        self._deadline.unregister(self.sock)
        super().close()


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, pinned: tuple[str, ...], deadline: _Deadline) -> None:
        self._ssl_context = ssl.create_default_context()
        super().__init__(host, port, timeout=deadline.remaining(), context=self._ssl_context)
        self._pinned = pinned
        self._deadline = deadline

    def connect(self) -> None:
        sock = _connect_pinned(self._pinned, self.port, self._deadline)
        tls_sock: ssl.SSLSocket | None = None
        try:
            # Keep certificate verification and SNI tied to the URL hostname.
            tls_sock = self._ssl_context.wrap_socket(sock, server_hostname=self.host, do_handshake_on_connect=False)
            self._deadline.replace(sock, tls_sock)
            tls_sock.settimeout(self._deadline.remaining())
            _deadline_call(self._deadline, tls_sock.do_handshake)
            self.sock = tls_sock
        except BaseException:
            if tls_sock is not None:
                self._deadline.unregister(tls_sock)
                _interrupt_socket(tls_sock)
            else:
                self._deadline.unregister(sock)
                _interrupt_socket(sock)
            raise

    def close(self) -> None:
        self._deadline.unregister(self.sock)
        super().close()


def _connection(
    host: str, port: int, pinned: tuple[str, ...], deadline: _Deadline, *, secure: bool
) -> http.client.HTTPConnection:
    connection = _PinnedHTTPSConnection if secure else _PinnedHTTPConnection
    return connection(host, port, pinned, deadline)


def fetch_response(
    url: str,
    *,
    policy: FetchPolicy,
    timeout: float,
    user_agent: str,
    max_bytes: int = MAX_RESPONSE_BYTES,
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
    method: str | None = None,
    pin_cache: dict[tuple[str, int], tuple[tuple[int, str], ...]] | None = None,
) -> tuple[int, dict[str, str], bytes, str]:
    """Fetch one HTTP response without following redirects.

    The destination is validated and DNS-pinned exactly as in ``fetch_bytes``.
    Redirect status and Location are returned to the caller so recon tools can
    report them without silently connecting to another host.
    """
    if max_bytes <= 0:
        raise ValueError("response byte limit must be positive")
    deadline = _Deadline(timeout, "HTTP response deadline exceeded")
    try:
        clean, host, port, pinned = _deadline_call(
            deadline,
            lambda: _validated_destination(url, policy, timeout=deadline.remaining(), pin_cache=pin_cache),
        )
        parsed = urlsplit(clean)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        conn = _connection(host, port, pinned, deadline, secure=parsed.scheme == "https")
        response: http.client.HTTPResponse | None = None
        try:
            request_headers = {"User-Agent": user_agent}
            if headers:
                request_headers.update(headers)
            request_method = method or ("POST" if data is not None else "GET")
            if not request_method.isascii() or not request_method.isalpha() or len(request_method) > 16:
                raise ValueError("HTTP method must contain 1–16 ASCII letters.")
            _deadline_call(
                deadline,
                lambda: conn.request(request_method.upper(), path, body=data, headers=request_headers),
            )
            response = _deadline_call(deadline, conn.getresponse)
            response_headers = _deadline_call(deadline, lambda: dict(response.getheaders()))
            content_length = response.getheader("Content-Length")
            if content_length is not None and int(content_length) > max_bytes:
                raise ValueError("BLOCKED: HTTP response exceeds the byte limit.")
            body = bytearray()
            while len(body) <= max_bytes:
                if conn.sock is not None:
                    conn.sock.settimeout(deadline.remaining())
                chunk = _deadline_call(deadline, lambda: response.read1(min(65536, max_bytes + 1 - len(body))))
                if not chunk:
                    break
                body.extend(chunk)
                if len(body) > max_bytes:
                    raise ValueError("BLOCKED: HTTP response exceeds the byte limit.")
            return response.status, response_headers, bytes(body), clean
        finally:
            if response is not None:
                response.close()
            conn.close()
    except Exception as exc:
        deadline.check(exc)
        raise
    finally:
        deadline.close()


def probe_url(
    url: str,
    *,
    policy: FetchPolicy,
    timeout: float,
    user_agent: str,
) -> tuple[int, str]:
    """Check URL availability with bounded HEAD/one-byte GET requests.

    Redirects are followed only after the next URL passes the same domain and
    pinned-address policy. The returned status and URL are from the final hop.
    """
    deadline = _Deadline(timeout, "URL probe deadline exceeded")
    pin_cache: dict[tuple[str, int], tuple[tuple[int, str], ...]] = {}

    def _request(method: str, target: str) -> tuple[int, str, str | None]:
        clean, host, port, pinned = _deadline_call(
            deadline,
            lambda: _validated_destination(target, policy, timeout=deadline.remaining(), pin_cache=pin_cache),
        )
        parsed = urlsplit(clean)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        conn = _connection(host, port, pinned, deadline, secure=parsed.scheme == "https")
        response: http.client.HTTPResponse | None = None
        try:
            request_headers = {"User-Agent": user_agent}
            if method == "GET":
                request_headers["Range"] = "bytes=0-0"
            _deadline_call(deadline, lambda: conn.request(method, path, headers=request_headers))
            if conn.sock is not None:
                conn.sock.settimeout(deadline.remaining())
            response = _deadline_call(deadline, conn.getresponse)
            location = response.getheader("Location")
            if method == "GET" and response.status not in (301, 302, 303, 307, 308):
                # Do not consume an unbounded error page merely to check if the
                # source exists.
                _deadline_call(deadline, lambda: response.read(1))
            return response.status, clean, location
        finally:
            if response is not None:
                response.close()
            conn.close()

    try:
        for method in ("HEAD", "GET"):
            current = url
            for hop in range(MAX_REDIRECTS + 1):
                status, clean, location = _request(method, current)
                if status in (301, 302, 303, 307, 308):
                    if not location or hop == MAX_REDIRECTS:
                        raise ValueError("BLOCKED: missing redirect destination or redirect limit exceeded.")
                    current = urljoin(clean, location)
                    continue
                if method == "HEAD" and status in (405, 501):
                    break
                return status, clean
            else:
                raise ValueError("BLOCKED: redirect limit exceeded.")
        return _request("GET", current)[:2]
    except Exception as exc:
        deadline.check(exc)
        raise
    finally:
        deadline.close()


def fetch_bytes(url: str, *, policy: FetchPolicy, timeout: float, user_agent: str) -> tuple[bytes, str, str]:
    """GET a page; return bounded bytes, content type, and final validated URL.

    Address checks apply to every DNS answer and every redirect. A single
    non-public answer rejects mixed-address responses, preventing rebinding.
    The response byte cap is enforced before HTML parsing or text truncation.
    """
    deadline = _Deadline(timeout, "research fetch deadline exceeded")
    pin_cache: dict[tuple[str, int], tuple[tuple[int, str], ...]] = {}
    try:
        for hop in range(MAX_REDIRECTS + 1):
            clean, host, port, pinned = _deadline_call(
                deadline,
                lambda: _validated_destination(url, policy, timeout=deadline.remaining(), pin_cache=pin_cache),
            )
            parsed = urlsplit(clean)
            conn = _connection(host, port, pinned, deadline, secure=parsed.scheme == "https")
            try:
                path = parsed.path or "/"
                if parsed.query:
                    path += "?" + parsed.query
                _deadline_call(
                    deadline,
                    lambda: conn.request(
                        "GET",
                        path,
                        headers={"User-Agent": user_agent, "Accept": "text/html,text/plain,*/*;q=0.5"},
                    ),
                )
                response = _deadline_call(deadline, conn.getresponse)
                try:
                    if response.status in (301, 302, 303, 307, 308):
                        location = response.getheader("Location")
                        if not location or hop == MAX_REDIRECTS:
                            raise ValueError("BLOCKED: missing redirect destination or redirect limit exceeded.")
                        url = urljoin(clean, location)
                        continue
                    if response.status >= 400:
                        raise ValueError(f"HTTP {response.status} for URL")
                    length = response.getheader("Content-Length")
                    if length is not None and int(length) > MAX_RESPONSE_BYTES:
                        raise ValueError("BLOCKED: research response exceeds the byte limit.")
                    body = bytearray()
                    while True:
                        if conn.sock is not None:
                            conn.sock.settimeout(deadline.remaining())
                        chunk = _deadline_call(
                            deadline,
                            lambda: response.read1(min(65536, MAX_RESPONSE_BYTES + 1 - len(body))),
                        )
                        if not chunk:
                            content_type = response.getheader("Content-Type", "")
                            return bytes(body), content_type, clean
                        body.extend(chunk)
                        if len(body) > MAX_RESPONSE_BYTES:
                            raise ValueError("BLOCKED: research response exceeds the byte limit.")
                finally:
                    response.close()
            finally:
                conn.close()
        raise ValueError("BLOCKED: redirect limit exceeded.")
    except Exception as exc:
        deadline.check(exc)
        raise
    finally:
        deadline.close()
