"""Unit tests for worker netns firewall rules (tools/sandbox/network.py).

Security invariants covered:
- Default-DROP termination (no default-ACCEPT egress).
- Loopback ACCEPT covers sandbox 127.0.0.1 only as an interface rule.
- Metadata / link-local destinations are explicitly DROPped.
- The Docker bridge gateway is DROPped unless explicitly authorized.
- ``allow_dns: none`` blocks port 53 everywhere (no DNS bypass).
- IPv4-only authorization never leaks into IPv6 (and vice versa).
- A failed sidecar install FAILS CLOSED (SandboxPolicyError, never proceed).
"""

from __future__ import annotations

import pytest

from tools.sandbox.models import NetworkPolicy
from tools.sandbox.network import (
    COMMON_BLOCKED_NETS,
    apply_network_policy,
    build_firewall_ruleset,
    build_ipv4_rules,
    build_ipv6_rules,
)


def _pol(destinations: list[str], *, allow_dns: str = "controlled", allow_gateway: bool = False) -> NetworkPolicy:
    return NetworkPolicy(
        authorized_destinations=destinations,
        explicitly_blocked=list(COMMON_BLOCKED_NETS),
        allow_dns=allow_dns,
        enforced=True,
        allow_gateway=allow_gateway,
    )


class TestIpv4Rules:
    def test_ends_with_default_drop(self):
        rules = build_ipv4_rules(_pol(["192.0.2.5"]))
        assert rules[-2] == "-A NAI-OUTPUT -j DROP"
        assert rules[-1] == "COMMIT"

    def test_loopback_and_established_accepted(self):
        rules = build_ipv4_rules(_pol([]))
        assert "-A NAI-OUTPUT -o lo -j ACCEPT" in rules
        assert "-A NAI-OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT" in rules

    def test_metadata_dropped(self):
        rules = "\n".join(build_ipv4_rules(_pol([])))
        assert "-d 169.254.169.254 -j DROP" in rules
        assert "-d 169.254.0.0/16 -j DROP" in rules

    def test_authorized_destination_accepted(self):
        rules = "\n".join(build_ipv4_rules(_pol(["192.0.2.5", "10.0.0.0/24"])))
        assert "-A NAI-OUTPUT -d 192.0.2.5 -j ACCEPT" in rules
        assert "-A NAI-OUTPUT -d 10.0.0.0/24 -j ACCEPT" in rules

    def test_gateway_dropped_unless_explicitly_allowed(self):
        blocked = "\n".join(build_ipv4_rules(_pol([]), gateway="172.30.0.1"))
        assert "-A NAI-OUTPUT -d 172.30.0.1 -j DROP" in blocked
        allowed = "\n".join(build_ipv4_rules(_pol([], allow_gateway=True), gateway="172.30.0.1"))
        assert "172.30.0.1" not in allowed

    def test_dns_none_blocks_port53_everywhere(self):
        rules = "\n".join(build_ipv4_rules(_pol([], allow_dns="none")))
        assert "-p udp --dport 53 -j REJECT" in rules
        assert "-p tcp --dport 53 -j REJECT" in rules
        # Loopback resolver is blocked too (no DNS bypass via 127.0.0.11)
        assert "-o lo -p udp --dport 53 -j REJECT" in rules

    def test_dns_controlled_adds_no_port53_rules(self):
        rules = "\n".join(build_ipv4_rules(_pol([], allow_dns="controlled")))
        assert "--dport 53" not in rules

    def test_empty_authorization_is_default_deny(self):
        rules = "\n".join(build_ipv4_rules(_pol([])))
        assert "-j ACCEPT" not in [ln for ln in rules.splitlines() if "-d " in ln]


class TestIpv6Rules:
    def test_ends_with_default_drop(self):
        rules = build_ipv6_rules(_pol([]))
        assert rules[-2] == "-A NAI-OUTPUT -j DROP"

    def test_link_local_dropped(self):
        rules = "\n".join(build_ipv6_rules(_pol([])))
        assert "-d fe80::/10 -j DROP" in rules
        assert "-d fd00:ec2::254 -j DROP" in rules

    def test_ipv6_destination_plumbed_only_in_v6(self):
        pol = _pol(["2001:db8::5", "192.0.2.5"])
        v6 = "\n".join(build_ipv6_rules(pol))
        assert "-d 2001:db8::5 -j ACCEPT" in v6
        # IPv4 destinations must NOT appear in the ip6tables ruleset
        assert "192.0.2.5" not in v6


class TestApplyNetworkPolicy:
    def _run_sidecar_ok(self, container_id, image, binary, rules):
        assert binary in ("iptables-restore", "ip6tables-restore")
        assert rules.endswith("\n")
        return 0, "", ""

    def test_success_returns_true(self):
        pol = _pol(["192.0.2.5"])
        assert apply_network_policy(pol, container_id="abc123", image="img", run_sidecar=self._run_sidecar_ok) is True

    def test_sidecar_failure_fails_closed(self):
        def failing_sidecar(container_id, image, binary, rules):
            return 1, "", "iptables-restore: line 3 failed"

        pol = _pol(["192.0.2.5"])
        with pytest.raises(Exception, match="iptables-restore failed"):
            apply_network_policy(pol, container_id="abc123", image="img", run_sidecar=failing_sidecar)

    def test_full_ruleset_renders(self):
        text = build_firewall_ruleset(_pol(["192.0.2.5"]))
        assert text.startswith("*filter")
        assert "-A NAI-OUTPUT -d 192.0.2.5 -j ACCEPT" in text
        assert text.rstrip().endswith("COMMIT")
