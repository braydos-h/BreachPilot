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

import pytest

from tools.sandbox import policy as sandbox_policy
from tools.sandbox.policy import METADATA_DESTINATIONS, audit_policy_payload, build_network_policy

_CLEAR_ENV = {k: None for k in ("EXPLOIT_TARGET", "EXPLOIT_TARGET_IP", "EXPLOIT_TARGET_DOMAIN", "EXPLOIT_DISCOVERED_TARGETS", "EXPLOIT_ALLOWED_TARGETS")}


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
    """Keep tests hermetic: pinned research hosts resolve to nothing."""
    monkeypatch.setattr(sandbox_policy, "_resolve_authorized", lambda *a, **k: [])


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
        assert "192.0.2.10" in pol.authorized_destinations

    def test_cidr_authorized(self):
        pol = build_network_policy(_cfg(["10.0.0.0/24"]))
        assert "10.0.0.0/24" in pol.authorized_destinations

    def test_wildcard_domain_authorizes_nothing_statically(self):
        pol = build_network_policy(_cfg(["*.example.com"]))
        assert pol.authorized_destinations == []
        assert any("*.example.com" in u for u in pol.unresolved_targets)

    def test_fqdn_resolved_host_side_and_validated(self, monkeypatch):
        monkeypatch.setattr("tools.validation_utils.resolve_target_to_ip", lambda d: "192.0.2.77")
        pol = build_network_policy(_cfg(["example.com"]))
        assert "192.0.2.77" in pol.authorized_destinations
        assert pol.resolved_domains.get("example.com") == "192.0.2.77"

    def test_fqdn_resolving_outside_allowlist_adds_nothing(self, monkeypatch):
        # The domain IS allowed, but its resolution lands on an unauthorized
        # IP => the resolved IP must NOT enter the firewall authorization.
        monkeypatch.setattr("tools.validation_utils.resolve_target_to_ip", lambda d: "198.51.100.9")
        pol = build_network_policy(_cfg(["example.com"]))
        assert "198.51.100.9" not in pol.authorized_destinations
        assert "example.com" in " ".join(pol.unresolved_targets) or not pol.resolved_domains

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


class TestAuditPolicyPayload:
    def test_payload_is_secret_free_and_fingerprinted(self):
        pol = build_network_policy(_cfg(["192.0.2.5"]))
        payload = audit_policy_payload(pol)
        assert payload["authorized_destinations"] == ["192.0.2.5"]
        assert "169.254.169.254" in payload["explicitly_blocked"]
        assert len(payload["fingerprint"]) == 16

    def test_fingerprint_changes_with_authorization(self):
        p1 = build_network_policy(_cfg(["192.0.2.5"]))
        p2 = build_network_policy(_cfg(["192.0.2.6"]))
        assert p1.fingerprint() != p2.fingerprint()


class TestAuthorizeDestinations:
    def test_empty_allowlist_deny_when_required(self):
        ok, reason = sandbox_policy.authorize_destinations(["192.0.2.5"], {"exploit": {"require_explicit_allowlist": True}})
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
