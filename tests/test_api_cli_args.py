"""Tests for the --demon / --daemon CLI flag and parse_args wiring."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


def test_demon_flag_alias(monkeypatch):
    """Both --demon and --daemon should set args.daemon = True."""
    from main import parse_args
    args = parse_args(["--demon"])
    assert args.daemon is True
    args2 = parse_args(["--daemon"])
    assert args2.daemon is True


def test_demon_default_host_port():
    """--api-host / --api-port default to None (filled from config at runtime)."""
    from main import parse_args
    args = parse_args(["--demon"])
    assert args.api_host is None
    assert args.api_port is None


def test_demon_mutually_exclusive_with_target():
    """--demon + --target should return exit code 2 (conflict)."""
    from main import main
    code = main(["--demon", "--target", "10.0.0.50"])
    assert code == 2


def test_demon_mutually_exclusive_with_doctor():
    """--demon + --doctor should return exit code 2."""
    from main import main
    code = main(["--demon", "--doctor"])
    assert code == 2


def test_demon_mutually_exclusive_with_menu():
    """--demon + --menu should return exit code 2."""
    from main import main
    code = main(["--demon", "--menu"])
    assert code == 2


def test_no_daemon_flag_preserves_existing_behavior():
    """Without --demon, args.daemon is False."""
    from main import parse_args
    args = parse_args(["--target", "10.0.0.50", "--mode", "recon"])
    assert args.daemon is False