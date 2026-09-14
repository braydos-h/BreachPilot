"""Property-based scope/target-normalization tests (#47).

Stdlib-only (seeded ``random`` — no hypothesis dependency): each test
generates hundreds of cases from a fixed seed, so failures reproduce
exactly. Properties hold over the whole input space, not just hand-picked
examples:

- CIDR containment: an address inside an allowed network always matches;
  an address outside a private-only allowlist never matches.
- Normalization: case/whitespace/trailing-dot variants decide identically.
- Wildcard boundary: ``*.example.com`` matches any depth below the parent
  but never a suffix-collision like ``badexample.com``.
- Deny precedence + hard-forbidden actions hold across generated assets.
"""

from __future__ import annotations

import ipaddress
import random
import string

import pytest

from db import DatabaseManager, _new_id
from scope_gate import _HARD_FORBIDDEN_ACTIONS, ScopeGate
from tools.validation_utils import is_subdomain_of, is_target_in_allowlist

_SEED = 20260914


def _rng(tag: str) -> random.Random:
    return random.Random(f"{_SEED}:{tag}")


def _rand_label(rng: random.Random, max_len: int = 10) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(rng.choice(alphabet) for _ in range(rng.randint(1, max_len)))


def _rand_ip_in(rng: random.Random, network: str) -> str:
    net = ipaddress.ip_network(network)
    return str(net[rng.randrange(net.num_addresses)])


def _rand_public_ip(rng: random.Random) -> str:
    while True:
        ip = ipaddress.ip_address(rng.randrange(2**32))
        if ip.is_global and not ip.is_multicast and not ip.is_reserved:
            return str(ip)


@pytest.fixture
def temp_db(tmp_path):
    path = tmp_path / "test.db"
    db = DatabaseManager(path)
    with db.connection(write=True) as conn:
        db.ensure_schema(conn)
    return db


def test_property_cidr_containment():
    rng = _rng("cidr")
    for network in ("10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12", "127.0.0.0/8"):
        allow = [network]
        for _ in range(100):
            assert is_target_in_allowlist(_rand_ip_in(rng, network), allow) is True


def test_property_private_allowlist_rejects_public():
    rng = _rng("public-reject")
    allow = ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"]
    for _ in range(300):
        assert is_target_in_allowlist(_rand_public_ip(rng), allow) is False


def test_property_normalization_variants_decide_identically():
    rng = _rng("normalize")
    allow = ["Example.COM", "10.0.0.0/8", "*.Example.com"]
    for _ in range(200):
        kind = rng.randrange(3)
        if kind == 0:
            base = f"{_rand_label(rng)}.example.com"
        elif kind == 1:
            base = _rand_ip_in(rng, "10.0.0.0/8")
        else:
            base = "example.com"
        expected = is_target_in_allowlist(base, allow)
        for variant in (
            base.upper(),
            f"  {base}  ",
            base + ".",
            base.upper() + ".",
        ):
            assert is_target_in_allowlist(variant, allow) is expected, base


def test_property_wildcard_boundary():
    rng = _rng("wildcard")
    allow = ["*.example.com"]
    for _ in range(200):
        depth = rng.randint(1, 3)
        host = ".".join(_rand_label(rng) for _ in range(depth)) + ".example.com"
        assert is_target_in_allowlist(host, allow) is True
        assert is_subdomain_of(host, "example.com") is True
    # Suffix collisions must NEVER match, however generated.
    for _ in range(200):
        evil = f"{_rand_label(rng)}example.com"
        assert evil != "example.com"
        assert is_target_in_allowlist(evil, allow) is False
        assert is_subdomain_of(evil, "example.com") is False


def test_property_empty_inputs_deny():
    rng = _rng("empty")
    for _ in range(50):
        assert is_target_in_allowlist(_rand_public_ip(rng), []) is False
        assert is_target_in_allowlist("", ["10.0.0.0/8"]) is False
        assert is_target_in_allowlist("   ", ["example.com"]) is False


def test_property_deny_precedence_across_assets(temp_db):
    rng = _rng("deny")
    denied_ip = "10.0.0.99"
    gate = ScopeGate(
        temp_db,
        _new_id("M"),
        allowed_assets=["10.0.0.0/8"],
        disallowed_assets=[denied_ip],
        risk_profile="standard_authorized",
    )
    for _ in range(50):
        inside = _rand_ip_in(rng, "10.0.0.0/8")
        if inside == denied_ip:
            continue
        assert gate.check_scope(inside, "recon", enforce_rate_limit=False).allowed is True
    for action in ("recon", "test", "exploit", "report"):
        result = gate.check_scope(denied_ip, action, enforce_rate_limit=False)
        assert result.allowed is False, action


def test_property_hard_forbidden_actions_always_denied(temp_db):
    rng = _rng("forbidden")
    gate = ScopeGate(
        temp_db,
        _new_id("M"),
        allowed_assets=["10.0.0.0/8", "example.com"],
        risk_profile="high_authorized_testing",
    )
    actions = sorted(_HARD_FORBIDDEN_ACTIONS)
    assert actions, "hard-forbidden set must be non-empty for this property to mean anything"
    for _ in range(len(actions)):
        action = actions[rng.randrange(len(actions))]
        asset = rng.choice(["10.1.2.3", "example.com"])
        result = gate.check_scope(asset, action, enforce_rate_limit=False)
        assert result.allowed is False, (asset, action)
