"""Unit tests for sandbox network-authorization policy (tools/sandbox/policy.py).

Security invariants covered:
- Empty allowlist yields an EMPTY authorized set (default-DROP containment).
- ``0.0.0.0/0`` / ``*`` targets are REFUSED (never authorize the internet).
- Metadata endpoints are always in the explicit block list.
- IPs / CIDRs are authorized; wildcard domains authorize nothing statically.
- FQDNs resolve HOST-SIDE and only allowlist-validated IPs are authorized.
- Host loopback mapping is explicit-only (map_host_loopback), never silent.
- Resolution validation: a domain resolving outside the allowlist adds nothing.
"""

from __future__ import annotations

import ipaddress

import pytest

from tools.sandbox import policy as sandbox_policy
from tools.sandbox.policy import METADATA_DESTINATIONS, audit_policy_payload, build_network_policy

_CLEAR_ENV = {
    k: None
    for k in (
        "EXPLOIT_TARGET",
        "EXPLOIT_TARGET_IP",
        "EXPLOIT_TARGET_DOMAIN",
        "EXPLOIT_DISCOVERED_TARGETS",
        "EXPLOIT_ALLOWED_TARGETS",
    )
}


def _cfg(allowed_targets: list[str], **network) -> dict:
    exploit = {"allowed_targets": allowed_targets}
    return {
        "exploit": exploit,
        "sandbox": {"enabled": True, "network": {"allow_research_hosts": False, **network}},
    }


@pytest.fixture(autouse=True)
def _no_env_targets(monkeypatch):
    for key, val in _CLEAR_ENV.items():
        monkeypatch.delenv(key, raising=val is not None)


@pytest.fixture(autouse=True)
def _no_research_resolution(monkeypatch):
    """Keep tests hermetic: pinned research hosts resolve to nothing.

    Only RESEARCH_HOSTS are stubbed; other domains keep the real (monkeypatched
    per-test) host-side resolver so FQDN authorization stays testable.
    """
    real = sandbox_policy._resolve_authorized

    def fake(domain: str, config, **kwargs):
        if domain in sandbox_policy.RESEARCH_HOSTS:
            return []
        return real(domain, config, **kwargs)

    monkeypatch.setattr(sandbox_policy, "_resolve_authorized", fake)


class TestBuildNetworkPolicy:
    def test_empty_allowlist_authorizes_nothing(self):
        pol = build_network_policy(_cfg([]))
        assert pol.authorized_destinations == []
        assert pol.enforced is True

    def test_no_config_authorizes_nothing(self):
        pol = build_network_policy({"sandbox": {"enabled": True, "network": {"allow_research_hosts": False}}})
        assert pol.authorized_destinations == []

    def test_metadata_always_blocked(self):
        pol = build_network_policy(_cfg(["10.0.0.5"]))
        assert "169.254.169.254" in pol.explicitly_blocked
        assert "169.254.0.0/16" in pol.explicitly_blocked

    def test_authorize_all_refused(self):
        for token in ("0.0.0.0/0", "*", "any", "all"):
            with pytest.raises(ValueError, match="refuses"):
                build_network_policy(_cfg([token]))

    def test_bare_ip_authorized(self):
        pol = build_network_policy(_cfg(["192.0.2.10"]))
        # Bare IPs are normalized to /32 CIDRs (iptables-equivalent).
        assert any(
            ipaddress.ip_network(d) == ipaddress.ip_network("192.0.2.10/32") for d in pol.authorized_destinations
        )

    def test_cidr_authorized(self):
        pol = build_network_policy(_cfg(["10.0.0.0/24"]))
        assert "10.0.0.0/24" in pol.authorized_destinations

    def test_wildcard_domain_authorizes_nothing_statically(self):
        pol = build_network_policy(_cfg(["*.example.com"]))
        assert pol.authorized_destinations == []
        assert any("*.example.com" in u for u in pol.unresolved_targets)

    def test_fqdn_resolved_host_side_and_validated(self):
        # Production seam: inject via resolver_fn (threaded to
        # resolve_all_addresses), not by mocking resolve_target_to_ip which
        # this path no longer calls.
        pol = build_network_policy(_cfg(["example.com"]), resolver_fn=lambda h: ["192.0.2.77"])
        assert "192.0.2.77" in pol.authorized_destinations
        assert pol.resolved_domains.get("example.com") == "192.0.2.77"

    def test_mixed_scope_ip_and_domain_both_authorized(self):
        # Mixed-scope allowlist (bare IP + domain) resolves through the same
        # production seam: the IP normalizes to /32, the domain contributes
        # its injected addresses.
        pol = build_network_policy(_cfg(["192.0.2.5", "example.com"]), resolver_fn=lambda h: ["192.0.2.77"])
        assert "192.0.2.5/32" in pol.authorized_destinations
        assert "192.0.2.77" in pol.authorized_destinations
        assert pol.resolved_domains.get("example.com") == "192.0.2.77"

    def test_resolution_validation_rejects_unallowlisted_domain(self):
        # An unlisted domain contributes nothing via the production path:
        # build_network_policy only resolves tokens in the effective
        # allowlist, so even a resolver that would return an IP for the evil
        # host cannot widen the lock.
        pol = build_network_policy(_cfg(["192.0.2.5"]), resolver_fn=lambda h: ["198.51.100.9"])
        assert "198.51.100.9" not in pol.authorized_destinations
        assert pol.resolved_domains.get("evil.example.net") is None

    def test_localhost_does_not_authorize_host_loopback(self):
        pol = build_network_policy(_cfg(["127.0.0.1"]))
        # Sandbox loopback is allowed via the lo interface, never via an
        # authorized gateway destination (no map_host_loopback here).
        assert pol.authorized_destinations == []

    def test_map_host_loopback_requires_explicit_optin_and_loopback_target(self):
        # gateway present + loopback in allowlist + explicit opt-in => gateway authorized
        pol = build_network_policy(_cfg(["127.0.0.1"], map_host_loopback=True), gateway="172.30.0.1")
        assert "172.30.0.1" in pol.authorized_destinations
        # WITHOUT the opt-in the gateway is never authorized
        pol2 = build_network_policy(_cfg(["127.0.0.1"]), gateway="172.30.0.1")
        assert "172.30.0.1" not in pol2.authorized_destinations

    def test_extra_cidrs_added_when_valid(self):
        pol = build_network_policy(_cfg(["10.0.0.5"], extra_allow_cidrs=["10.99.0.0/16", "not-a-cidr"]))
        assert "10.99.0.0/16" in pol.authorized_destinations
        assert "not-a-cidr" not in pol.authorized_destinations

    def test_allow_dns_controlled_uses_embedded_resolver(self):
        pol = build_network_policy(_cfg(["10.0.0.5"]))
        assert pol.allow_dns == "controlled"
        assert pol.dns_servers == ["127.0.0.11"]

    def test_allow_dns_none_recorded(self):
        pol = build_network_policy(_cfg(["10.0.0.5"], allow_dns="none"))
        assert pol.allow_dns == "none"
        assert pol.dns_servers == []

    def test_research_hosts_denied_by_default(self, monkeypatch):
        # Default-deny: no explicit flag => research hosts add nothing, and
        # target-only traffic still works. Overrides the file's autouse
        # no-resolution stub so the deny is proven against resolving hosts.
        monkeypatch.setattr(
            sandbox_policy,
            "_resolve_authorized",
            lambda domain, config, **kwargs: ["203.0.113.9"] if domain in sandbox_policy.RESEARCH_HOSTS else [],
        )
        pol = build_network_policy(
            {
                "exploit": {"allowed_targets": ["192.0.2.5"]},
                "sandbox": {"enabled": True, "network": {}},
            }
        )
        assert pol.authorized_destinations == ["192.0.2.5/32"]
        assert "203.0.113.9" not in pol.authorized_destinations

    def test_research_hosts_authorized_only_on_explicit_opt_in(self, monkeypatch):
        monkeypatch.setattr(
            sandbox_policy,
            "_resolve_authorized",
            lambda domain, config, **kwargs: ["203.0.113.9"] if domain in sandbox_policy.RESEARCH_HOSTS else [],
        )
        pol = build_network_policy(
            {
                "exploit": {"allowed_targets": ["192.0.2.5"]},
                "sandbox": {"enabled": True, "network": {"allow_research_hosts": True}},
            }
        )
        assert "203.0.113.9" in pol.authorized_destinations
        assert "192.0.2.5/32" in pol.authorized_destinations


class TestAuditPolicyPayload:
    def test_payload_is_secret_free_and_fingerprinted(self):
        pol = build_network_policy(_cfg(["192.0.2.5"]))
        payload = audit_policy_payload(pol)
        assert payload["authorized_destinations"] == ["192.0.2.5/32"]
        assert "169.254.169.254" in payload["explicitly_blocked"]
        assert len(payload["fingerprint"]) == 16

    def test_fingerprint_changes_with_authorization(self):
        p1 = build_network_policy(_cfg(["192.0.2.5"]))
        p2 = build_network_policy(_cfg(["192.0.2.6"]))
        assert p1.fingerprint() != p2.fingerprint()


class TestAuthorizeDestinations:
    def test_empty_allowlist_deny_when_required(self):
        ok, reason = sandbox_policy.authorize_destinations(
            ["192.0.2.5"], {"exploit": {"require_explicit_allowlist": True}}
        )
        assert ok is False
        assert "empty" in reason.lower()

    def test_authorized_ip_passes(self):
        cfg = {
            "exploit": {"require_explicit_allowlist": True, "allowed_targets": ["192.0.2.5"]},
        }
        ok, _reason = sandbox_policy.authorize_destinations(["192.0.2.5"], cfg)
        assert ok is True

    def test_unauthorized_ip_denied(self):
        cfg = {
            "exploit": {"require_explicit_allowlist": True, "allowed_targets": ["192.0.2.5"]},
        }
        ok, reason = sandbox_policy.authorize_destinations(["203.0.113.9"], cfg)
        assert ok is False
        assert "203.0.113.9" in reason


class TestPureLocalComputation:
    @pytest.mark.parametrize(
        "command",
        [
            "python -c 'print(1)'",
            'python3 -c "print(1)"',
            "true",
            "id",
            "id -u",
            "echo hello",
            "touch /workspace/ok.txt",
            "ls /workspace",
            "cat /workspace/out.txt",
            "python --version",
        ],
    )
    def test_allowed_local_computation(self, command):
        assert sandbox_policy.is_pure_local_computation(command) is True

    @pytest.mark.parametrize(
        "command",
        [
            "python3 -c \"import socket;socket.create_connection(('192.0.2.9',80),3)\"",
            "python3 /workspace/egress.py",
            "curl http://203.0.113.9/",
            "nmap -sV 192.0.2.9",
            "echo hi && echo bye",
            "bash script.sh",
            "./exploit",
            "",
            "python script.py",
            "timeout 8 bash -c 'echo > /dev/tcp/192.0.2.9/80'",
        ],
    )
    def test_blocked_network_or_compound(self, command):
        assert sandbox_policy.is_pure_local_computation(command) is False
