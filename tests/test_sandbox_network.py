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
    def test_output_jump_hooks_chain(self):
        # BP-01: without the OUTPUT -> NAI-OUTPUT jump the ruleset never
        # evaluates (egress falls through to default ACCEPT). The jump must
        # be the ONLY OUTPUT rule and precede all NAI-OUTPUT appends.
        rules = build_ipv4_rules(_pol(["192.0.2.5"]))
        output_rules = [r for r in rules if r.startswith("-A OUTPUT")]
        assert output_rules == ["-A OUTPUT -j NAI-OUTPUT"]
        assert rules.index("-A OUTPUT -j NAI-OUTPUT") < rules.index("-A NAI-OUTPUT -o lo -j ACCEPT")

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
        rules = build_ipv4_rules(_pol([], allow_dns="none"))
        # REJECTs must PRECEDE the blanket lo ACCEPT (first-match-wins would
        # otherwise shadow them and leave a lo DNS bypass).
        lo_idx = rules.index("-A NAI-OUTPUT -o lo -j ACCEPT")
        for rej in ("-A NAI-OUTPUT -p udp --dport 53 -j REJECT", "-A NAI-OUTPUT -p tcp --dport 53 -j REJECT"):
            assert rej in rules
            assert rules.index(rej) < lo_idx

    def test_dns_controlled_scopes_port53_to_embedded_resolver(self):
        from tools.sandbox.models import NetworkPolicy

        pol = _pol([], allow_dns="controlled")
        pol = NetworkPolicy(
            authorized_destinations=pol.authorized_destinations,
            explicitly_blocked=pol.explicitly_blocked,
            allow_dns=pol.allow_dns,
            enforced=pol.enforced,
            allow_gateway=pol.allow_gateway,
            resolved_domains={"example.com": "93.184.216.34"},
            resolved_domain_addresses={"example.com": ["93.184.216.34"]},
        )
        rules = build_ipv4_rules(pol)
        # :53 ACCEPT only to 127.0.0.11; everything else :53 REJECTed —
        # including the lo bypass (rogue in-worker resolver, direct 8.8.8.8).
        assert "-A NAI-OUTPUT -d 127.0.0.11 -p udp --dport 53 -j ACCEPT" in rules
        assert "-A NAI-OUTPUT -d 127.0.0.11 -p tcp --dport 53 -j ACCEPT" in rules
        assert "-A NAI-OUTPUT -p udp --dport 53 -j REJECT" in rules
        assert "-A NAI-OUTPUT -p tcp --dport 53 -j REJECT" in rules
        lo_idx = rules.index("-A NAI-OUTPUT -o lo -j ACCEPT")
        for r in rules:
            if "--dport 53" in r:
                assert rules.index(r) < lo_idx

    def test_dns_controlled_rejects_direct_and_loopback_resolvers(self):
        from tools.sandbox.models import NetworkPolicy

        pol = NetworkPolicy(
            authorized_destinations=["192.0.2.5"],
            explicitly_blocked=list(COMMON_BLOCKED_NETS),
            allow_dns="controlled",
            enforced=True,
            resolved_domains={"example.com": "93.184.216.34"},
            resolved_domain_addresses={"example.com": ["93.184.216.34"]},
        )
        rules = build_ipv4_rules(pol)
        port53 = [r for r in rules if "--dport 53" in r]
        assert port53, "controlled mode must emit explicit :53 rules"
        # Every :53 ACCEPT is scoped to the embedded resolver ONLY: no direct
        # 8.8.8.8:53, no rogue loopback-resolver (127.0.0.1:53) bypass.
        for rule in port53:
            if "-j ACCEPT" in rule:
                assert "-d 127.0.0.11" in rule, f"unexpected :53 ACCEPT: {rule}"
        joined = "\n".join(rules)
        assert "-d 8.8.8.8" not in joined
        assert "-d 127.0.0.1 " not in joined and "-d 127.0.0.1 -p" not in joined
        # Blanket :53 REJECTs precede the lo ACCEPT (first-match-wins).
        lo_idx = rules.index("-A NAI-OUTPUT -o lo -j ACCEPT")
        for rej in ("-A NAI-OUTPUT -p udp --dport 53 -j REJECT", "-A NAI-OUTPUT -p tcp --dport 53 -j REJECT"):
            assert rej in rules
            assert rules.index(rej) < lo_idx

    def test_dns_controlled_with_no_names_fails_closed_to_none(self):
        # IP-only allowlist: DNS serves no authorized purpose → none-style REJECTs.
        rules = "\n".join(build_ipv4_rules(_pol(["192.0.2.5"], allow_dns="controlled")))
        assert "127.0.0.11" not in rules
        assert "-p udp --dport 53 -j REJECT" in rules
        assert "-p tcp --dport 53 -j REJECT" in rules

    def test_dns_v6_always_rejected(self):
        # The embedded resolver is IPv4-only: no legitimate v6 :53 path exists.
        for mode in ("controlled", "none"):
            rules = "\n".join(build_ipv6_rules(_pol([], allow_dns=mode)))
            assert "-p udp --dport 53 -j REJECT" in rules
            assert "-p tcp --dport 53 -j REJECT" in rules
            assert "127.0.0.11" not in rules

    def test_empty_authorization_is_default_deny(self):
        rules = "\n".join(build_ipv4_rules(_pol([])))
        assert "-j ACCEPT" not in [ln for ln in rules.splitlines() if "-d " in ln]

    def test_no_ipv6_literals_in_ipv4_ruleset(self):
        # Regression: fd00:ec2::254 (COMMON_BLOCKED_NETS) was emitted into
        # iptables-restore, which rejects IPv6 and aborted the whole install
        # (every sandbox bring-up failed closed downstream).
        rules = "\n".join(build_ipv4_rules(_pol(["2001:db8::5", "192.0.2.5", "not-an-ip"])))
        assert "fd00:ec2::254" not in rules
        assert "fe80::" not in rules
        assert "2001:db8::5" not in rules
        assert "not-an-ip" not in rules
        # IPv4 authorization still flows.
        assert "-A NAI-OUTPUT -d 192.0.2.5 -j ACCEPT" in rules

    def test_ipv6_gateway_never_in_ipv4_ruleset(self):
        rules = "\n".join(build_ipv4_rules(_pol([]), gateway="fd00::1"))
        assert "fd00::1" not in rules
        assert rules.rstrip().endswith("COMMIT")

    def test_ipv6_cidr_authorization_stays_in_v6_only(self):
        pol = _pol(["2001:db8::/32", "10.0.0.0/24"])
        v4 = "\n".join(build_ipv4_rules(pol))
        v6 = "\n".join(build_ipv6_rules(pol))
        assert "2001:db8::/32" not in v4
        assert "-d 2001:db8::/32 -j ACCEPT" in v6
        assert "10.0.0.0/24" not in v6
        assert "-d 10.0.0.0/24 -j ACCEPT" in v4


class TestIpv6Rules:
    def test_output_jump_hooks_chain(self):
        rules = build_ipv6_rules(_pol([]))
        output_rules = [r for r in rules if r.startswith("-A OUTPUT")]
        assert output_rules == ["-A OUTPUT -j NAI-OUTPUT"]
        assert rules.index("-A OUTPUT -j NAI-OUTPUT") < rules.index("-A NAI-OUTPUT -o lo -j ACCEPT")

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

    def test_no_ipv4_literals_in_ipv6_ruleset(self):
        # Strict separation, both directions: ip6tables-restore rejects IPv4.
        rules = "\n".join(build_ipv6_rules(_pol(["192.0.2.5", "10.0.0.0/24"])))
        assert "169.254.169.254" not in rules
        assert "169.254.0.0/16" not in rules
        assert "100.100.100.200" not in rules
        assert "192.0.2.5" not in rules
        assert "10.0.0.0/24" not in rules
        # v6 explicit DROPs still present.
        assert "-d fe80::/10 -j DROP" in rules
        assert "-d fd00:ec2::254 -j DROP" in rules

    def test_ip_version_helper(self):
        from tools.sandbox.network import _ip_version

        assert _ip_version("192.0.2.5") == 4
        assert _ip_version("10.0.0.0/24") == 4
        assert _ip_version("2001:db8::5") == 6
        assert _ip_version("fd00:ec2::254") == 6
        assert _ip_version("fe80::/10") == 6
        assert _ip_version("not-an-ip") is None
        assert _ip_version("") is None


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

    def test_full_ruleset_has_no_ipv6_literals(self):
        # build_firewall_ruleset feeds iptables-restore: any IPv6 literal
        # aborts the install, so assert none can arrive here.
        text = build_firewall_ruleset(_pol(["192.0.2.5", "2001:db8::5"]))
        assert "fd00:ec2::254" not in text
        assert "2001:db8::5" not in text
        assert "::" not in text

    def test_sidecar_receives_family_clean_rulesets(self):
        # End-to-end at the seam: neither binary may receive a foreign-family
        # literal, or the sidecar install fails and the run fails closed.
        seen: dict[str, str] = {}

        def recording_sidecar(container_id, image, binary, rules):
            seen[binary] = rules
            return 0, "", ""

        pol = _pol(["192.0.2.5", "2001:db8::5"])
        assert apply_network_policy(pol, container_id="abc123", image="img", run_sidecar=recording_sidecar) is True
        assert "fd00:ec2::254" not in seen["iptables-restore"]
        assert "2001:db8::5" not in seen["iptables-restore"]
        assert "192.0.2.5" not in seen["ip6tables-restore"]
        assert "169.254.169.254" not in seen["ip6tables-restore"]

    def test_sidecar_receives_output_jump(self):
        # BP-01: both families delivered to the sidecar must hook OUTPUT to
        # NAI-OUTPUT, or the installed ruleset never evaluates.
        seen: dict[str, str] = {}

        def recording_sidecar(container_id, image, binary, rules):
            seen[binary] = rules
            return 0, "", ""

        pol = _pol(["192.0.2.5"])
        assert apply_network_policy(pol, container_id="abc123", image="img", run_sidecar=recording_sidecar) is True
        for binary in ("iptables-restore", "ip6tables-restore"):
            assert "-A OUTPUT -j NAI-OUTPUT" in seen[binary]
