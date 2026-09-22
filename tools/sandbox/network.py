"""Worker network-namespace firewall: the actual containment boundary.

Two halves:

1. Pure rule builders (``build_firewall_ruleset``) -- unit-testable, no Docker.
2. The installer (``apply_network_policy``) -- runs an ephemeral sidecar
   container that SHARES the worker's network namespace and holds the ONLY
   ``NET_ADMIN`` grant. The sidecar installs a default-DROP iptables/ip6tables
   ruleset and exits before the first agent command. The worker itself gets
   ``--cap-drop ALL`` (optionally ``NET_RAW`` for raw packet scanning) and
   therefore CANNOT loosen, remove, or enumerate the rules even when running
   tools as root inside the container.

Fail closed: any install failure raises ``SandboxPolicyError``; the caller
destroys the partial sandbox rather than proceeding with an uncontained worker.
Rules are (re-)applied before each command when the authorization fingerprint
changes, so dynamically discovered (allowlist-validated) targets are picked up
deliberately.

Resolver-layer name enforcement (deliberate subset, no in-container dnsmasq):
in-container name blocking is enforced via IP authorization plus
``127.0.0.11``-only ``:53`` — the host resolves ONLY allowlisted names
(``NetworkPolicy.allowed_dns_names``), so an unauthorized name can resolve at
best to an unauthorized IP, which the default-DROP ruleset denies. The
``:53`` ACCEPTs are scoped to the embedded resolver and every other ``:53``
(direct ``8.8.8.8:53``, rogue loopback resolvers) is REJECTed ahead of the
blanket ``lo`` ACCEPT, so DNS-protocol exfil/tunneling/oracle paths gain
nothing beyond what the IP authorization already permits.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any

from tools.sandbox.exceptions import SandboxPolicyError
from tools.sandbox.models import NetworkPolicy

logger = logging.getLogger(__name__)

__all__ = [
    "build_ipv4_rules",
    "build_ipv6_rules",
    "build_firewall_ruleset",
    "apply_network_policy",
    "COMMON_BLOCKED_NETS",
]

# Explicitly dropped (redundant with default-DROP, but the DROP appears in
# audits and survives rule-order mistakes). Mixed families by design: each
# builder filters to its own family (iptables-restore rejects IPv6 literals
# and vice versa -- see _ip_version).
COMMON_BLOCKED_NETS = ["169.254.169.254", "169.254.0.0/16", "fd00:ec2::254", "100.100.100.200"]

# IPv6 link-local always denied in the v6 ruleset (not in COMMON_BLOCKED_NETS,
# which policy.py also surfaces for v4-side audits).
_IPV6_EXTRA_BLOCKED = ("fe80::/10",)


def _ip_version(token: str) -> int | None:
    """4 / 6 for an IP or CIDR literal, None when unparsable.

    Unparsable tokens are fail-closed: callers skip them instead of emitting
    them into a ruleset (an invalid ACCEPT would be a hole; an invalid DROP
    would break iptables-restore and fail the whole install).
    """
    try:
        return ipaddress.ip_network(token, strict=False).version
    except ValueError:
        return None


# The single hook that makes the ruleset effective: without this jump,
# packets traverse OUTPUT's default ACCEPT and never see NAI-OUTPUT.
_OUTPUT_JUMP = "-A OUTPUT -j NAI-OUTPUT"

# Docker's embedded resolver (the ONLY resolver the worker may use in
# "controlled" mode). :53 ACCEPTs are scoped to this destination; every other
# :53 is REJECTed — including via loopback, so a rogue in-worker resolver on
# 127.0.0.1:53 or direct 8.8.8.8:53 gains nothing.
_EMBEDDED_RESOLVER = "127.0.0.11"


def _accept_rule(destination: str) -> str:
    return f"-A NAI-OUTPUT -d {destination} -j ACCEPT"


def _effective_dns(policy: NetworkPolicy) -> str:
    """Effective DNS posture for the :53 rules.

    ``controlled`` with ZERO authorized names (no resolved domains — IP-only
    allowlists, no research hosts) degrades to ``none``: DNS would only serve
    names the worker cannot talk to, so fail closed instead of leaving a
    DNS-protocol exfil/oracle path open for no authorized purpose.
    """
    if policy.allow_dns == "controlled" and not policy.resolved_domains and not policy.resolved_domain_addresses:
        return "none"
    return policy.allow_dns


def _dns_v4_rules(policy: NetworkPolicy) -> list[str]:
    """Port-53 rules for the v4 chain. MUST precede the blanket lo ACCEPT
    (iptables first-match-wins: a later :53 REJECT would be shadowed)."""
    if _effective_dns(policy) == "none":
        # No DNS bypass: block resolver ports everywhere, loopback included.
        return [
            "-A NAI-OUTPUT -p udp --dport 53 -j REJECT",
            "-A NAI-OUTPUT -p tcp --dport 53 -j REJECT",
        ]
    # controlled: the embedded resolver ONLY (udp+tcp); everything else :53
    # is rejected, loopback-bypass included.
    return [
        f"-A NAI-OUTPUT -d {_EMBEDDED_RESOLVER} -p udp --dport 53 -j ACCEPT",
        f"-A NAI-OUTPUT -d {_EMBEDDED_RESOLVER} -p tcp --dport 53 -j ACCEPT",
        "-A NAI-OUTPUT -p udp --dport 53 -j REJECT",
        "-A NAI-OUTPUT -p tcp --dport 53 -j REJECT",
    ]


def _dns_v6_rules(policy: NetworkPolicy) -> list[str]:
    """Port-53 rules for the v6 chain. The embedded resolver is IPv4-only, so
    v6 :53 is rejected in every mode (no legitimate v6 DNS path exists)."""
    return [
        "-A NAI-OUTPUT -p udp --dport 53 -j REJECT",
        "-A NAI-OUTPUT -p tcp --dport 53 -j REJECT",
    ]


def build_ipv4_rules(policy: NetworkPolicy, *, gateway: str = "") -> list[str]:
    """iptables-restore lines for the worker netns (IPv4).

    Semantics:
    - OUTPUT jumps to NAI-OUTPUT (the ONLY OUTPUT rule emitted; the chain
      would otherwise never evaluate and egress would fall through to the
      default ACCEPT policy)
    - port-53 rules FIRST (scoped resolver ACCEPT / blanket REJECT precede the
      lo ACCEPT, which would otherwise shadow them — first-match-wins)
    - loopback ACCEPT: sandbox-internal 127.0.0.1 (NOT operator-host 127.0.0.1;
      dev host-loopback mapping is an explicit config decision in policy.py)
    - ESTABLISHED/RELATED ACCEPT (replies to authorized connections)
    - metadata / bridge-gateway explicit DROPs
    - authorized IPs/CIDRs ACCEPT
    - terminate with policy DROP (default-deny egress)
    """
    lines = [
        "*filter",
        ":NAI-OUTPUT - [0:0]",
        _OUTPUT_JUMP,
        *_dns_v4_rules(policy),
        "-A NAI-OUTPUT -o lo -j ACCEPT",
        "-A NAI-OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
    ]
    for blocked in COMMON_BLOCKED_NETS:
        if _ip_version(blocked) != 4:
            continue
        lines.append(f"-A NAI-OUTPUT -d {blocked} -j DROP")
    if not policy.allow_gateway and gateway and _ip_version(gateway) == 4:
        # Block the Docker bridge gateway (a path to host-published services
        # and to the Docker daemon). The rest of the bridge subnet is handled
        # by the terminating default-DROP.
        lines.append(f"-A NAI-OUTPUT -d {gateway} -j DROP")
    # RFC1918 is NOT blanket-blocked: lab targets are usually RFC1918, so the
    # authorization set (which may contain private CIDRs) is the boundary.
    # Family-filtered: an IPv6 authorized destination must never reach
    # iptables-restore (it would abort the whole install); v6 ACCEPTs live
    # in build_ipv6_rules. Unparsable entries are skipped (fail closed).
    for dest in policy.authorized_destinations:
        if _ip_version(dest) != 4:
            continue
        lines.append(_accept_rule(dest))
    lines.append("-A NAI-OUTPUT -j DROP")
    lines.append("COMMIT")
    return [ln for ln in lines if ln]


def build_ipv6_rules(policy: NetworkPolicy, *, gateway: str = "") -> list[str]:
    """ip6tables-restore lines: loopback + established only, then DROP.

    IPv6 egress stays denied unless an explicitly authorized destination is an
    IPv6 address/CIDR (those get ACCEPT plumbed through here). v6 :53 is
    always REJECTed (the embedded resolver is IPv4-only).
    """
    lines = [
        "*filter",
        ":NAI-OUTPUT - [0:0]",
        _OUTPUT_JUMP,
        *_dns_v6_rules(policy),
        "-A NAI-OUTPUT -o lo -j ACCEPT",
        "-A NAI-OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
    ]
    for blocked in (*_IPV6_EXTRA_BLOCKED, *(b for b in COMMON_BLOCKED_NETS if _ip_version(b) == 6)):
        lines.append(f"-A NAI-OUTPUT -d {blocked} -j DROP")

    for dest in policy.authorized_destinations:
        if _ip_version(dest) != 6:
            continue
        lines.append(_accept_rule(dest))
    lines.append("-A NAI-OUTPUT -j DROP")
    lines.append("COMMIT")
    return lines


def build_firewall_ruleset(policy: NetworkPolicy, *, gateway: str = "") -> str:
    """IPv4-only convenience wrapper (feeds ``iptables-restore``).

    IPv6 coverage is NOT included here -- apply ``build_ipv6_rules`` via
    ``ip6tables-restore`` (as ``apply_network_policy`` does). Callers that
    install only this string leave v6 egress unfiltered.
    """
    return "\n".join(build_ipv4_rules(policy, gateway=gateway)) + "\n"


def apply_network_policy(
    policy: NetworkPolicy,
    *,
    container_id: str,
    image: str,
    gateway: str = "",
    run_sidecar: Any = None,
) -> bool:
    """Install the ruleset in the worker netns via a NET_ADMIN sidecar.

    ``run_sidecar`` is the seam tests monkeypatch (default: the
    docker_backend wrapper). Returns True on success; ANY failure raises
    ``SandboxPolicyError`` (never silently proceeds uncontained).
    """
    if run_sidecar is None:
        from tools.sandbox.docker_backend import run_netns_sidecar as run_sidecar
    rules_v4 = build_ipv4_rules(policy, gateway=gateway)
    rules_v6 = build_ipv6_rules(policy, gateway=gateway)
    for proto, rules in (
        ("iptables-restore", "\n".join(rules_v4) + "\n"),
        ("ip6tables-restore", "\n".join(rules_v6) + "\n"),
    ):
        rc, out, err = run_sidecar(container_id, image, proto, rules)
        if rc != 0:
            raise SandboxPolicyError(f"{proto} failed in sandbox netns (rc={rc}): {(err or out).strip()[:300]}")
    logger.info(
        "sandbox network policy installed: %d authorized destinations, dns=%s",
        len(policy.authorized_destinations),
        policy.allow_dns,
    )
    return True
