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
import time
from dataclasses import dataclass
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


def _connect_pinned(addresses: tuple[str, ...], port: int, timeout: float) -> socket.socket:
    """Try only the previously validated addresses within one timeout budget."""
    deadline = time.monotonic() + timeout
    last_error: OSError | None = None
    for address in addresses:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("research connect deadline exceeded")
        try:
            return socket.create_connection((address, port), remaining)
        except OSError as exc:
            last_error = exc
    if last_error is not None:
        raise last_error
    raise ValueError("BLOCKED: hostname has no usable addresses.")


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, pinned: tuple[str, ...], timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._pinned = pinned
        self._connect_timeout = timeout

    def connect(self) -> None:
        # Numeric canonical IP only: never re-resolve the untrusted hostname.
        self.sock = _connect_pinned(self._pinned, self.port, self._connect_timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, pinned: tuple[str, ...], timeout: float) -> None:
        self._ssl_context = ssl.create_default_context()
        super().__init__(host, port, timeout=timeout, context=self._ssl_context)
        self._pinned = pinned
        self._connect_timeout = timeout

    def connect(self) -> None:
        sock = _connect_pinned(self._pinned, self.port, self._connect_timeout)
        try:
            # Keep certificate verification and SNI tied to the URL hostname.
            self.sock = self._ssl_context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


def _connection(
    host: str, port: int, pinned: tuple[str, ...], timeout: float, *, secure: bool
) -> http.client.HTTPConnection:
    connection = _PinnedHTTPSConnection if secure else _PinnedHTTPConnection
    return connection(host, port, pinned, timeout)


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
    if timeout <= 0:
        raise TimeoutError("HTTP response deadline exceeded")
    if max_bytes <= 0:
        raise ValueError("response byte limit must be positive")
    deadline = time.monotonic() + timeout
    remaining = deadline - time.monotonic()
    clean, host, port, pinned = _validated_destination(url, policy, timeout=remaining, pin_cache=pin_cache)
    parsed = urlsplit(clean)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    conn = _connection(host, port, pinned, max(0.001, deadline - time.monotonic()), secure=parsed.scheme == "https")
    response: http.client.HTTPResponse | None = None
    try:
        request_headers = {"User-Agent": user_agent}
        if headers:
            request_headers.update(headers)
        request_method = method or ("POST" if data is not None else "GET")
        if not request_method.isascii() or not request_method.isalpha() or len(request_method) > 16:
            raise ValueError("HTTP method must contain 1–16 ASCII letters.")
        conn.request(request_method.upper(), path, body=data, headers=request_headers)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("HTTP response deadline exceeded")
        if conn.sock is not None:
            conn.sock.settimeout(remaining)
        response = conn.getresponse()
        response_headers = dict(response.getheaders())
        content_length = response.getheader("Content-Length")
        if content_length is not None and int(content_length) > max_bytes:
            raise ValueError("BLOCKED: HTTP response exceeds the byte limit.")
        body = bytearray()
        while len(body) < max_bytes:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("HTTP response deadline exceeded")
            if conn.sock is not None:
                conn.sock.settimeout(remaining)
            chunk = response.read1(min(65536, max_bytes - len(body)))
            if not chunk:
                break
            body.extend(chunk)
        return response.status, response_headers, bytes(body), clean
    finally:
        if response is not None:
            response.close()
        conn.close()


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
    deadline = time.monotonic() + timeout
    pin_cache: dict[tuple[str, int], tuple[tuple[int, str], ...]] = {}

    def _request(method: str, target: str) -> tuple[int, str, str | None]:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("URL probe deadline exceeded")
        clean, host, port, pinned = _validated_destination(target, policy, timeout=remaining, pin_cache=pin_cache)
        parsed = urlsplit(clean)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        conn = _connection(host, port, pinned, max(0.001, deadline - time.monotonic()), secure=parsed.scheme == "https")
        response: http.client.HTTPResponse | None = None
        try:
            request_headers = {"User-Agent": user_agent}
            if method == "GET":
                request_headers["Range"] = "bytes=0-0"
            conn.request(method, path, headers=request_headers)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("URL probe deadline exceeded")
            if conn.sock is not None:
                conn.sock.settimeout(remaining)
            response = conn.getresponse()
            location = response.getheader("Location")
            if method == "GET" and response.status not in (301, 302, 303, 307, 308):
                # Do not consume an unbounded error page merely to check if the
                # source exists.
                response.read(1)
            return response.status, clean, location
        finally:
            if response is not None:
                response.close()
            conn.close()

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


def fetch_bytes(url: str, *, policy: FetchPolicy, timeout: float, user_agent: str) -> tuple[bytes, str, str]:
    """GET a page; return bounded bytes, content type, and final validated URL.

    Address checks apply to every DNS answer and every redirect. A single
    non-public answer rejects mixed-address responses, preventing rebinding.
    The response byte cap is enforced before HTML parsing or text truncation.
    """
    deadline = time.monotonic() + timeout
    pin_cache: dict[tuple[str, int], tuple[tuple[int, str], ...]] = {}
    for hop in range(MAX_REDIRECTS + 1):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("research fetch deadline exceeded")
        clean, host, port, pinned = _validated_destination(url, policy, timeout=remaining, pin_cache=pin_cache)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("research fetch deadline exceeded")
        parsed = urlsplit(clean)
        conn = _connection(host, port, pinned, remaining, secure=parsed.scheme == "https")
        try:
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            conn.request(
                "GET",
                path,
                headers={"User-Agent": user_agent, "Accept": "text/html,text/plain,*/*;q=0.5"},
            )
            response = conn.getresponse()
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
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("research fetch deadline exceeded")
                    if conn.sock is not None:
                        conn.sock.settimeout(remaining)
                    chunk = response.read1(min(65536, MAX_RESPONSE_BYTES + 1 - len(body)))
                    if not chunk:
                        return bytes(body), response.getheader("Content-Type", ""), clean
                    body.extend(chunk)
                    if len(body) > MAX_RESPONSE_BYTES:
                        raise ValueError("BLOCKED: research response exceeds the byte limit.")
            finally:
                response.close()
        finally:
            conn.close()
    raise ValueError("BLOCKED: redirect limit exceeded.")
