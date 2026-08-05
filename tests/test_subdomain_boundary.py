"""Tests for the boundary-aware subdomain check.

Regression: ``endswith(dom)`` accepted ``badexample.com`` as a subdomain of
``example.com``, after which it could be auto-authorized via
``add_discovered_target`` -- widening the target-IP allowlist (the one
attack-mode safety) to an out-of-parent asset. ``is_subdomain_of`` is the
boundary-aware replacement reused by every subdomain-enumeration path.
"""

from __future__ import annotations

from tools.validation_utils import is_subdomain_of


def test_exact_match_is_subdomain_of_itself():
    assert is_subdomain_of("example.com", "example.com") is True


def test_real_subdomain_accepted():
    assert is_subdomain_of("a.example.com", "example.com") is True
    assert is_subdomain_of("www.sub.example.com", "example.com") is True


def test_suffix_collision_rejected():
    """badexample.com must NOT be treated as a child of example.com."""
    assert is_subdomain_of("badexample.com", "example.com") is False
    assert is_subdomain_of("notexample.com", "example.com") is False
    assert is_subdomain_of("example.com.evil.com", "example.com") is False


def test_case_insensitive():
    assert is_subdomain_of("A.Example.COM", "EXAMPLE.com") is True
    assert is_subdomain_of("BADEXAMPLE.COM", "example.com") is False


def test_wildcard_and_trailing_dot_stripped():
    assert is_subdomain_of("*.example.com", "example.com") is True
    assert is_subdomain_of("a.example.com.", "example.com.") is True
    assert is_subdomain_of("*.example.com", "example.com.") is True


def test_empty_inputs_safe():
    assert is_subdomain_of("", "example.com") is False
    assert is_subdomain_of("a.example.com", "") is False
    assert is_subdomain_of(None, "example.com") is False  # type: ignore[arg-type]


def test_parent_must_be_full_suffix():
    """``xample.com`` is a suffix of ``example.com`` but not a parent domain."""
    assert is_subdomain_of("example.com", "xample.com") is False
    assert is_subdomain_of("sub.example.com", "xample.com") is False
