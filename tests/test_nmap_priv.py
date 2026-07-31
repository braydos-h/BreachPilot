"""Tests for ``tools/nmap_priv.py`` — privilege-aware nmap argv handling.

Covers ``_is_privileged``, ``_downgrade_unprivileged_args``,
``apply_nmap_privilege``, and ``is_privilege_error``. Platform-dependent
branches are forced via monkeypatching ``os.name``/``os.geteuid`` so tests are
deterministic on Windows hosts.
"""

from __future__ import annotations

import os

import pytest

import tools.nmap_priv as nmap_priv
from tools.nmap_priv import (
    _downgrade_unprivileged_args,
    _is_privileged,
    apply_nmap_privilege,
    is_privilege_error,
)

# ── _is_privileged ──────────────────────────────────────────────────────────


def test_is_privileged_windows():
    # On Windows nmap has its own socket handling and is treated as privileged.
    # Force the nt branch regardless of host OS.
    orig_name = os.name
    try:
        os.name = "nt"
        assert _is_privileged() is True
    finally:
        os.name = orig_name


def test_is_privileged_linux_nonroot(monkeypatch):
    monkeypatch.setattr(os, "name", "posix", raising=False)
    monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
    assert _is_privileged() is False


def test_is_privileged_linux_root(monkeypatch):
    monkeypatch.setattr(os, "name", "posix", raising=False)
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    assert _is_privileged() is True


def test_is_privileged_no_geteuid_attr(monkeypatch):
    # Some platforms lack geteuid (e.g. Windows); treat as privileged.
    monkeypatch.setattr(os, "name", "posix", raising=False)
    monkeypatch.delattr(os, "geteuid", raising=False)
    assert _is_privileged() is True


# ── _downgrade_unprivileged_args ────────────────────────────────────────────


def test_downgrade_no_root_flags_returns_unchanged():
    args = ["nmap", "-sT", "-p", "80", "10.0.0.5"]
    out, note = _downgrade_unprivileged_args(args)
    assert out == args
    assert note == ""


def test_downgrade_replaces_syn_with_connect_scan():
    args = ["-sS", "-p", "80", "10.0.0.5"]
    out, note = _downgrade_unprivileged_args(args)
    assert "-sS" not in out
    assert "-sT" in out
    assert "removed root-requiring flags -sS" in note
    assert "replaced with -sT" in note


def test_downgrade_removes_os_detection():
    args = ["-O", "10.0.0.5"]
    out, note = _downgrade_unprivileged_args(args)
    assert "-O" not in out
    assert "-sT" not in out  # no SYN, so no replacement
    assert "-O" in note


def test_downgrade_removes_multiple_root_flags_keeps_syn_replacement():
    args = ["-sS", "-O", "-sX", "10.0.0.5"]
    out, note = _downgrade_unprivileged_args(args)
    assert "-sS" not in out
    assert "-O" not in out
    assert "-sX" not in out
    assert "-sT" in out  # SYN replaced
    # all removed flags are mentioned in the note
    for tok in ("-sS", "-O", "-sX"):
        assert tok in note


def test_downgrade_preserves_non_root_flags():
    args = ["-sS", "-sV", "-p", "1-1000", "--top-ports", "50", "10.0.0.5"]
    out, _ = _downgrade_unprivileged_args(args)
    assert "-sV" in out
    assert "-p" in out
    assert "1-1000" in out
    assert "--top-ports" in out
    assert "50" in out
    assert "10.0.0.5" in out


def test_downgrade_empty_args():
    out, note = _downgrade_unprivileged_args([])
    assert out == []
    assert note == ""


def test_downgrade_only_nonroot_flags():
    args = ["-sT", "-p", "80"]
    out, note = _downgrade_unprivileged_args(args)
    assert out == args
    assert note == ""


# ── apply_nmap_privilege ────────────────────────────────────────────────────


def test_apply_privileged_returns_unchanged(monkeypatch):
    monkeypatch.setattr(nmap_priv, "_is_privileged", lambda: True)
    argv = ["nmap", "-sS", "-O", "10.0.0.5"]
    out, note = apply_nmap_privilege(argv, sudo=True, priv_fallback=True)
    assert out == argv
    assert note == ""


def test_apply_unprivileged_sudo_prepends_sudo_n(monkeypatch):
    monkeypatch.setattr(nmap_priv, "_is_privileged", lambda: False)
    monkeypatch.setattr(os, "name", "posix", raising=False)
    argv = ["nmap", "-sS", "10.0.0.5"]
    out, note = apply_nmap_privilege(argv, sudo=True, priv_fallback=False)
    assert out == ["sudo", "-n", "nmap", "-sS", "10.0.0.5"]
    assert note == ""


def test_apply_unprivileged_no_sudo_with_fallback_downgrades(monkeypatch):
    monkeypatch.setattr(nmap_priv, "_is_privileged", lambda: False)
    monkeypatch.setattr(os, "name", "posix", raising=False)
    argv = ["nmap", "-sS", "-O", "10.0.0.5"]
    out, note = apply_nmap_privilege(argv, sudo=False, priv_fallback=True)
    # -O removed, -sS -> -sT (which is appended after the non-root tokens)
    assert out[0] == "nmap"
    assert "-sS" not in out
    assert "-O" not in out
    assert "-sT" in out
    assert "10.0.0.5" in out
    assert "-sS" in note
    assert "-O" in note


def test_apply_unprivileged_no_sudo_no_fallback_returns_unchanged(monkeypatch):
    monkeypatch.setattr(nmap_priv, "_is_privileged", lambda: False)
    monkeypatch.setattr(os, "name", "posix", raising=False)
    argv = ["nmap", "-sS", "10.0.0.5"]
    out, note = apply_nmap_privilege(argv, sudo=False, priv_fallback=False)
    assert out == argv
    assert note == ""


def test_apply_sudo_disabled_on_windows(monkeypatch):
    # On Windows (nt), sudo is never used; priv_fallback is also a no-op on nt.
    monkeypatch.setattr(nmap_priv, "_is_privileged", lambda: False)
    monkeypatch.setattr(os, "name", "nt", raising=False)
    argv = ["nmap", "-sS", "10.0.0.5"]
    out, note = apply_nmap_privilege(argv, sudo=True, priv_fallback=True)
    assert out == argv
    assert note == ""


def test_apply_sudo_preferred_over_fallback(monkeypatch):
    # When both sudo and priv_fallback are set and we're unprivileged+posix,
    # sudo wins (no downgrade note).
    monkeypatch.setattr(nmap_priv, "_is_privileged", lambda: False)
    monkeypatch.setattr(os, "name", "posix", raising=False)
    argv = ["nmap", "-sS", "10.0.0.5"]
    out, note = apply_nmap_privilege(argv, sudo=True, priv_fallback=True)
    assert out == ["sudo", "-n", "nmap", "-sS", "10.0.0.5"]
    assert note == ""


# ── is_privilege_error ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "stderr",
    [
        "requires root privileges",
        "raw socket permission denied",
        "You requested a scan type which requires root privileges.",
        "must be run as root",
        "Operation not permitted: cap_net_raw",
    ],
)
def test_is_privilege_error_true(stderr):
    assert is_privilege_error(stderr) is True


@pytest.mark.parametrize(
    "stderr",
    [
        "",
        None,
        "Nmap scan complete, 1 host up",
        "connection refused",
        "host unreachable",
    ],
)
def test_is_privilege_error_false(stderr):
    assert is_privilege_error(stderr) is False


def test_is_privilege_error_case_insensitive():
    assert is_privilege_error("REQUIRES ROOT") is True
    assert is_privilege_error("Permission Denied") is True
