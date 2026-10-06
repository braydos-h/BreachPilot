"""Public research fetching regressions; all DNS and transports are mocked."""

from __future__ import annotations

import io
import socket
import ssl
from collections import deque

import pytest

from tools.research import http_fetch
from tools.research.facade import WebResearcher
from tools.research.models import WebResearcherSettings
from tools.research.providers import StdlibFetchProvider


class FakeResponse:
    def __init__(self, body: bytes = b"advisory", status: int = 200, **headers: str) -> None:
        self.status = status
        self.headers = headers
        self.stream = io.BytesIO(body)
        self.closed = False
        self.read_sizes: list[int] = []

    def getheader(self, name: str, default: str | None = None) -> str | None:
        return self.headers.get(name, default)

    def getheaders(self) -> list[tuple[str, str]]:
        return list(self.headers.items())

    def read1(self, size: int) -> bytes:
        self.read_sizes.append(size)
        return self.stream.read(size)

    def close(self) -> None:
        self.closed = True
        self.stream.close()


class FakeConnection:
    sock = None

    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.closed = False
        self.path = ""

    def request(self, method: str, path: str, *, headers: dict[str, str], body=None) -> None:
        assert method in {"GET", "HEAD"}
        assert "Authorization" not in headers
        self.path = path

    def getresponse(self) -> FakeResponse:
        return self.response

    def close(self) -> None:
        self.closed = True


@pytest.fixture(autouse=True)
def prohibit_real_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("unexpected real DNS or socket operation")

    monkeypatch.setattr(socket, "create_connection", forbidden)


def configure(
    monkeypatch: pytest.MonkeyPatch,
    answers: dict[str, list[str]],
    responses: list[FakeResponse],
) -> tuple[list[tuple[str, int, tuple[str, ...], bool]], list[FakeConnection]]:
    calls: list[tuple[str, int, tuple[str, ...], bool]] = []
    connections: list[FakeConnection] = []
    pending = deque(responses)

    def resolve(host: str, port: int, timeout: float) -> list[tuple[int, str]]:
        assert timeout > 0
        return [(socket.AF_INET6 if ":" in ip else socket.AF_INET, ip) for ip in answers[host]]

    def connect(host: str, port: int, pinned: tuple[str, ...], timeout: float, *, secure: bool) -> FakeConnection:
        assert timeout > 0
        calls.append((host, port, pinned, secure))
        conn = FakeConnection(pending.popleft())
        connections.append(conn)
        return conn

    monkeypatch.setattr(http_fetch, "_resolve_addresses", resolve)
    monkeypatch.setattr(http_fetch, "_connection", connect)
    return calls, connections


def fetch(url: str, policy: http_fetch.FetchPolicy | None = None) -> tuple[bytes, str, str]:
    return http_fetch.fetch_bytes(url, policy=policy or http_fetch.FetchPolicy(), timeout=5, user_agent="test-agent")


def test_single_response_transport_pins_destination_and_does_not_follow_redirect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    redirect = FakeResponse(status=302, Location="http://127.0.0.1/admin")
    calls, conns = configure(monkeypatch, {"source.example": ["93.184.216.34"]}, [redirect])

    status, headers, body, final_url = http_fetch.fetch_response(
        "https://source.example/start",
        policy=http_fetch.FetchPolicy(allowed_domains=("source.example",)),
        timeout=5,
        user_agent="test-agent",
    )

    assert status == 302
    assert headers["Location"] == "http://127.0.0.1/admin"
    assert body == b"advisory"
    assert final_url == "https://source.example/start"
    assert len(calls) == 1
    assert redirect.closed and conns[0].closed


def test_url_probe_revalidates_each_redirect_destination(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = [FakeResponse(status=302, Location="https://www.source.example/advisory"), FakeResponse(status=200)]
    calls, conns = configure(
        monkeypatch,
        {"source.example": ["93.184.216.34"], "www.source.example": ["93.184.216.35"]},
        responses,
    )

    status, final_url = http_fetch.probe_url(
        "https://source.example/start",
        policy=http_fetch.FetchPolicy(allowed_domains=("source.example",)),
        timeout=5,
        user_agent="test-agent",
    )

    assert status == 200
    assert final_url == "https://www.source.example/advisory"
    assert [call[0] for call in calls] == ["source.example", "www.source.example"]
    assert all(connection.closed for connection in conns)


def test_url_probe_rejects_private_redirect_before_connect(monkeypatch: pytest.MonkeyPatch) -> None:
    calls, conns = configure(
        monkeypatch,
        {"source.example": ["93.184.216.34"], "private.example": ["10.0.0.1"]},
        [FakeResponse(status=302, Location="https://private.example/admin")],
    )

    with pytest.raises(ValueError, match="BLOCKED"):
        http_fetch.probe_url(
            "https://source.example/start",
            policy=http_fetch.FetchPolicy(),
            timeout=5,
            user_agent="test-agent",
        )
    assert len(calls) == 1
    assert conns[0].closed


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "::1",
        "::ffff:127.0.0.1",
        "64:ff9b::a9fe:a9fe",  # NAT64 embedding of 169.254.169.254
    ],
)
def test_private_dns_answer_never_connects(monkeypatch: pytest.MonkeyPatch, ip: str) -> None:
    calls, _ = configure(monkeypatch, {"source.example": [ip]}, [])
    with pytest.raises(ValueError, match="non-public"):
        fetch("https://source.example/advisory")
    assert calls == []


def test_mixed_dns_answers_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    calls, _ = configure(monkeypatch, {"source.example": ["93.184.216.34", "127.0.0.1"]}, [])
    with pytest.raises(ValueError, match="non-public"):
        fetch("https://source.example/")
    assert calls == []


@pytest.mark.parametrize("location", ["http://127.0.0.1/admin", "http://169.254.169.254/", "https://private.example/"])
def test_redirect_cannot_reach_private_destination(monkeypatch: pytest.MonkeyPatch, location: str) -> None:
    redirect = FakeResponse(status=302, Location=location)
    calls, conns = configure(
        monkeypatch, {"source.example": ["93.184.216.34"], "private.example": ["10.0.0.1"]}, [redirect]
    )
    with pytest.raises(ValueError, match="BLOCKED"):
        fetch("https://source.example/")
    assert len(calls) == 1
    assert redirect.closed and conns[0].closed


@pytest.mark.parametrize(
    "policy",
    [
        http_fetch.FetchPolicy(allowed_domains=("source.example",)),
        http_fetch.FetchPolicy(blocked_domains=("evil.example",)),
    ],
)
def test_redirect_retains_domain_policy(monkeypatch: pytest.MonkeyPatch, policy: http_fetch.FetchPolicy) -> None:
    calls, _ = configure(
        monkeypatch, {"source.example": ["93.184.216.34"]}, [FakeResponse(status=302, Location="https://evil.example/")]
    )
    with pytest.raises(ValueError, match="BLOCKED"):
        fetch("https://source.example/", policy)
    assert len(calls) == 1


def test_public_relative_redirect_and_query_preserved(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = [FakeResponse(status=302, Location="/advisory?q=cve#fragment"), FakeResponse(b"source-backed evidence")]
    calls, conns = configure(monkeypatch, {"source.example": ["93.184.216.34"]}, responses)
    assert fetch("https://source.example/start") == (
        b"source-backed evidence",
        "",
        "https://source.example/advisory?q=cve",
    )
    assert calls == [("source.example", 443, ("93.184.216.34",), True)] * 2
    assert conns[1].path == "/advisory?q=cve"
    assert all(conn.closed for conn in conns)


@pytest.mark.parametrize(
    "url,host,port,address",
    [
        ("https://93.184.216.34/advisory", "93.184.216.34", 443, "93.184.216.34"),
        ("https://[2606:4700:4700::1111]/advisory", "2606:4700:4700::1111", 443, "2606:4700:4700::1111"),
    ],
)
def test_literal_public_ip_skips_dns_subprocess_and_connects_only_to_literal(
    monkeypatch: pytest.MonkeyPatch, url: str, host: str, port: int, address: str
) -> None:
    calls, _ = configure(monkeypatch, {}, [FakeResponse(b"advisory")])
    response = fetch(url)
    assert response == (b"advisory", "", url.rstrip("/"))
    assert calls == [(host, port, (address,), True)]


def test_fetch_reuses_validated_pin_for_same_host_redirect(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = [FakeResponse(status=302, Location="/next"), FakeResponse(b"source-backed evidence")]
    configure(monkeypatch, {"source.example": ["93.184.216.34"]}, responses)
    resolver = http_fetch._resolve_addresses
    resolved: list[tuple[str, int]] = []

    def count_resolution(host: str, port: int, timeout: float) -> list[tuple[int, str]]:
        resolved.append((host, port))
        return resolver(host, port, timeout)

    monkeypatch.setattr(http_fetch, "_resolve_addresses", count_resolution)
    result = fetch("https://source.example/start")
    assert result[0] == b"source-backed evidence"
    assert resolved == [("source.example", 443)]


def test_local_fetch_explicit_optin(monkeypatch: pytest.MonkeyPatch) -> None:
    calls, _ = configure(monkeypatch, {"localhost": ["127.0.0.1"]}, [FakeResponse(b"local advisory")])
    assert fetch("http://localhost:8080/", http_fetch.FetchPolicy(allow_local_fetch=True))[0] == b"local advisory"
    assert calls == [("localhost", 8080, ("127.0.0.1",), False)]


@pytest.mark.parametrize("advertised", [True, False])
def test_large_response_rejected_before_parsing(monkeypatch: pytest.MonkeyPatch, advertised: bool) -> None:
    monkeypatch.setattr(http_fetch, "MAX_RESPONSE_BYTES", 16)
    headers = {"Content-Length": "1000"} if advertised else {}
    response = FakeResponse(b"x" * 1000, **headers)
    _, conns = configure(monkeypatch, {"source.example": ["93.184.216.34"]}, [response])
    with pytest.raises(ValueError, match="byte limit"):
        fetch("https://source.example/")
    assert response.read_sizes == ([] if advertised else [17])
    assert response.closed and conns[0].closed


def test_redirect_loop_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    calls, conns = configure(
        monkeypatch,
        {"source.example": ["93.184.216.34"]},
        [FakeResponse(status=302, Location="/") for _ in range(http_fetch.MAX_REDIRECTS + 1)],
    )
    with pytest.raises(ValueError, match="redirect limit"):
        fetch("https://source.example/")
    assert len(calls) == http_fetch.MAX_REDIRECTS + 1
    assert all(conn.closed for conn in conns)


@pytest.mark.parametrize(
    "url",
    ["https://user:secret@source.example/", "https://source.example:70000/", "https://source.example/\r\nHost:bad"],
)
def test_malformed_authority_or_headers_rejected_without_network(url: str) -> None:
    with pytest.raises(ValueError):
        fetch(url)


def test_canonical_pinned_address_preserves_host_and_tls_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    connections: list[tuple[tuple[str, int], object]] = []
    identities: list[str] = []

    class FakeSocket:
        closed = False

        def close(self) -> None:
            self.closed = True

    raw = FakeSocket()

    def connect(address: tuple[str, int], timeout: object) -> FakeSocket:
        connections.append((address, timeout))
        return raw

    class FakeContext:
        def wrap_socket(self, sock: FakeSocket, *, server_hostname: str) -> FakeSocket:
            assert sock is raw
            identities.append(server_hostname)
            return sock

    monkeypatch.setattr(socket, "create_connection", connect)
    monkeypatch.setattr(ssl, "create_default_context", FakeContext)
    conn = http_fetch._PinnedHTTPSConnection("source.example", 443, ("93.184.216.34",), 5)
    conn.connect()
    assert conn.host == "source.example"
    assert [address for address, _timeout in connections] == [("93.184.216.34", 443)]
    assert 0 < float(connections[0][1]) <= 5
    assert identities == ["source.example"]


def test_tls_verification_failure_closes_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeSocket:
        closed = False

        def close(self) -> None:
            self.closed = True

    raw = FakeSocket()

    class RejectContext:
        def wrap_socket(self, sock: FakeSocket, *, server_hostname: str) -> None:
            raise ssl.SSLCertVerificationError("bad certificate")

    monkeypatch.setattr(socket, "create_connection", lambda *args: raw)
    monkeypatch.setattr(ssl, "create_default_context", RejectContext)
    conn = http_fetch._PinnedHTTPSConnection("source.example", 443, ("93.184.216.34",), 5)
    with pytest.raises(ssl.SSLCertVerificationError):
        conn.connect()
    assert raw.closed


def test_default_provider_receives_facade_fetch_policy() -> None:
    researcher = WebResearcher(
        WebResearcherSettings(allow_local_fetch=True, allowed_domains=["localhost"], blocked_domains=["evil.example"])
    )
    provider = researcher.providers["stdlib"]
    assert isinstance(provider, StdlibFetchProvider)
    assert provider.fetch_policy == http_fetch.FetchPolicy(True, ("localhost",), ("evil.example",))


def test_provider_returns_structured_failure_without_private_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    calls, _ = configure(monkeypatch, {"source.example": ["127.0.0.1"]}, [])
    provider = StdlibFetchProvider(timeout_seconds=5, max_content_chars=100, user_agent="test")
    result = provider._fetch_sync("https://source.example/")
    assert not result.ok
    assert "BLOCKED" in result.error
    assert calls == []


def test_stalled_system_resolver_is_terminated_at_fetch_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[object, ...]] = []

    def stalled(command: list[str], **kwargs: object) -> None:
        calls.append((command, kwargs))
        raise http_fetch.subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(http_fetch.subprocess, "run", stalled)
    with pytest.raises(TimeoutError, match="DNS resolution deadline"):
        http_fetch._resolve_addresses("source.example", 443, 0.25)
    assert calls[0][1]["timeout"] == 0.25


def test_legacy_numeric_host_form_cannot_bypass_address_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    calls, _ = configure(monkeypatch, {"127.1": ["127.0.0.1"]}, [])
    with pytest.raises(ValueError, match="non-public"):
        fetch("http://127.1/admin")
    assert calls == []


def test_valid_public_page_preserves_html_extraction(monkeypatch: pytest.MonkeyPatch) -> None:
    response = FakeResponse(
        b'<html><title>Vendor advisory</title><p>Evidence and mitigation.</p><a href="/fix">Patch</a></html>',
        **{"Content-Type": "text/html"},
    )
    configure(monkeypatch, {"source.example": ["93.184.216.34"]}, [response])
    provider = StdlibFetchProvider(timeout_seconds=5, max_content_chars=1000, user_agent="test")
    result = provider._fetch_sync("https://source.example/advisory")
    assert result.ok
    assert result.title == "Vendor advisory"
    assert "Evidence and mitigation." in result.content
    assert "https://source.example/fix" in result.links
