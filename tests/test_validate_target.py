"""Tests for domain-target validation and resolution helpers.

Covers ``validate_target``, ``validate_target_or_ip``, ``is_fqdn``,
``resolve_target_to_ip``, and ``resolve_target`` -- the helpers added in
Phase 1 of the domain-targeting feature so the agent accepts a DNS name
alongside an IP at the entry point and per-MCP-tool gates.
"""

from __future__ import annotations

import socket
from unittest.mock import patch

# ── is_fqdn ──────────────────────────────────────────────────────────────────


def test_fqdn_accepts_simple_domain():
    from tools.validation_utils import is_fqdn

    assert is_fqdn("example.com") is True
    assert is_fqdn("sub.example.com") is True


def test_fqdn_accepts_wildcard():
    from tools.validation_utils import is_fqdn

    assert is_fqdn("*.example.com") is True


def test_fqdn_rejects_ip():
    from tools.validation_utils import is_fqdn

    assert is_fqdn("10.0.0.5") is False
    assert is_fqdn("::1") is False


def test_fqdn_rejects_garbage():
    from tools.validation_utils import is_fqdn

    assert is_fqdn("") is False
    assert is_fqdn("not a domain") is False
    assert is_fqdn("no-tld") is False
    assert is_fqdn(None) is False  # type: ignore[arg-type]


# ── validate_target / validate_target_or_ip ──────────────────────────────────


def test_validate_target_accepts_ipv4():
    from tools.validation_utils import validate_target

    assert validate_target("10.0.0.5") is True
    assert validate_target("192.168.1.1") is True


def test_validate_target_accepts_ipv6():
    from tools.validation_utils import validate_target

    assert validate_target("::1") is True
    assert validate_target("2001:db8::1") is True


def test_validate_target_accepts_domain():
    from tools.validation_utils import validate_target

    assert validate_target("example.com") is True
    assert validate_target("sub.example.com") is True


def test_validate_target_rejects_garbage():
    from tools.validation_utils import validate_target

    assert validate_target("") is False
    assert validate_target("not a target") is False
    assert validate_target(None) is False  # type: ignore[arg-type]


def test_validate_target_or_ip_is_alias():
    from tools.validation_utils import validate_target, validate_target_or_ip

    for t in ("10.0.0.5", "::1", "example.com", "garbage"):
        assert validate_target(t) == validate_target_or_ip(t)


# ── resolve_target_to_ip ─────────────────────────────────────────────────────


def test_resolve_ip_literal_returns_itself():
    from tools.validation_utils import resolve_target_to_ip

    assert resolve_target_to_ip("10.0.0.5") == "10.0.0.5"
    assert resolve_target_to_ip("::1") == "::1"


def test_resolve_domain_with_injected_resolver():
    from tools.validation_utils import resolve_target_to_ip

    fake = lambda host: ["93.184.216.34"]  # noqa: E731
    assert resolve_target_to_ip("example.com", resolver_fn=fake) == "93.184.216.34"


def test_resolve_domain_resolver_returns_empty():
    from tools.validation_utils import resolve_target_to_ip

    fake = lambda host: []  # noqa: E731
    assert resolve_target_to_ip("example.com", resolver_fn=fake) is None


def test_resolve_domain_resolver_raises_returns_none():
    from tools.validation_utils import resolve_target_to_ip

    def boom(host):
        raise OSError("dns fail")

    assert resolve_target_to_ip("example.com", resolver_fn=boom) is None


def test_resolve_garbage_returns_none():
    from tools.validation_utils import resolve_target_to_ip

    assert resolve_target_to_ip("") is None
    assert resolve_target_to_ip("not a domain") is None
    assert resolve_target_to_ip(None) is None  # type: ignore[arg-type]


def test_resolve_uses_system_resolver_when_no_fn():
    """When resolver_fn is None, the system resolver is used. Mock it."""
    from tools.validation_utils import resolve_target_to_ip

    fake_info = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
    with patch("socket.getaddrinfo", return_value=fake_info):
        assert resolve_target_to_ip("example.com") == "93.184.216.34"


def test_resolve_system_resolver_fails_returns_none():
    from tools.validation_utils import resolve_target_to_ip

    with patch("socket.getaddrinfo", side_effect=socket.gaierror("no dns")):
        assert resolve_target_to_ip("nonexistent.invalid") is None


# ── resolve_target ───────────────────────────────────────────────────────────


def test_resolve_target_ip_literal():
    from tools.validation_utils import resolve_target

    ip, domain = resolve_target("10.0.0.5")
    assert ip == "10.0.0.5"
    assert domain is None


def test_resolve_target_domain_resolved():
    from tools.validation_utils import resolve_target

    fake = lambda host: ["93.184.216.34"]  # noqa: E731
    ip, domain = resolve_target("example.com", resolver_fn=fake)
    assert ip == "93.184.216.34"
    assert domain == "example.com"


def test_resolve_target_domain_unresolvable():
    from tools.validation_utils import resolve_target

    fake = lambda host: []  # noqa: E731
    ip, domain = resolve_target("example.com", resolver_fn=fake)
    assert ip is None
    assert domain == "example.com"  # domain preserved even on failure


def test_resolve_target_garbage():
    from tools.validation_utils import resolve_target

    ip, domain = resolve_target("not a target")
    assert ip is None
    assert domain is None


# ── is_local_target / is_private_or_local_target with domains ────────────────


def test_is_local_target_resolves_domain_to_loopback():
    from tools.validation_utils import is_local_target

    fake_info = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]
    with patch("socket.getaddrinfo", return_value=fake_info):
        assert is_local_target("localhost.example.com") is True


def test_is_local_target_domain_resolves_to_remote():
    # Mock getaddrinfo to return 8.8.8.8 only for the domain; return [] for
    # the operator's own hostname so the local-interface check doesn't match.
    import socket as _sock

    from tools.validation_utils import is_local_target

    def fake_getaddrinfo(host, *a, **k):
        if host == "remote.example.com":
            return [(_sock.AF_INET, _sock.SOCK_STREAM, 6, "", ("8.8.8.8", 0))]
        return []

    with (
        patch("socket.getaddrinfo", side_effect=fake_getaddrinfo),
        patch("socket.gethostbyname", return_value="192.168.1.1"),
    ):
        assert is_local_target("remote.example.com") is False


def test_is_private_or_local_target_resolves_domain_to_private():
    from tools.validation_utils import is_private_or_local_target

    fake_info = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0))]
    with patch("socket.getaddrinfo", return_value=fake_info):
        assert is_private_or_local_target("internal.example.com") is True


def test_is_private_or_local_target_domain_unresolvable_returns_false():
    from tools.validation_utils import is_private_or_local_target

    with patch("socket.getaddrinfo", side_effect=socket.gaierror("no dns")):
        assert is_private_or_local_target("nonexistent.invalid") is False
