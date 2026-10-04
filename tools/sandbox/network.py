"""Worker network-namespace firewall: the actual containment boundary.

Two halves:

1. Pure rule builders (``build_firewall_ruleset``) -- unit-testable, no Docker.
2. The installer (``apply_network_policy``) -- runs an ephemeral sidecar
   container that SHARES the worker's network namespace and holds the ONLY
   ``NET_ADMIN`` grant. The sidecar installs a default-DROP iptables/ip6tables
   ruleset and exits before the first agent command. The worker itself gets
   ``--cap-drop ALL`` and
   therefore CANNOT loosen, remove, or enumerate the rules even when running
   tools as root inside the container.

Fail closed: any install failure raises ``SandboxPolicyError``; the caller
destroys the partial sandbox rather than proceeding with an uncontained worker.
Rules are (re-)applied before each command when the authorization fingerprint
changes, so dynamically discovered (allowlist-validated) targets are picked up
deliberately.

Resolver containment: only the host resolves authorized names and supplies
pinned worker hosts mappings. Worker DNS traffic is denied, including the
entire Docker embedded resolver address before loopback ACCEPT. This closes
DNS query exfiltration even when Docker NAT rewrites the resolver's port.
Workers also have no ``NET_RAW``, so packet sockets cannot bypass these IP
firewall rules.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any

from tools.kernel.target_network import translated_metadata_networks
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
# IPv4-mapped IPv6 addresses have no legitimate distinct egress use and are
# blocked as a whole so they cannot bypass IPv4 metadata CIDR drops. Teredo is
# likewise denied whole because its embedded IPv4 client bits are noncontiguous.
_IPV6_EXTRA_BLOCKED = ("fe80::/10", "::ffff:0:0/96", "2001::/32")


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

# Docker embedded resolver: its whole address is denied because NAT can
# rewrite port 53 to a high port before the filter chain sees the packet.
_EMBEDDED_RESOLVER = "127.0.0.11"


def _accept_rule(destination: str) -> str:
    return f"-A NAI-OUTPUT -d {destination} -j ACCEPT"


def _dns_v4_rules(policy: NetworkPolicy) -> list[str]:
    """No worker DNS egress, even for domain-authorized missions.

    Host-side resolution supplies pinned hosts mappings. Docker rewrites its
    embedded resolver's port in NAT, so block the complete resolver address
    before loopback ACCEPT rather than relying only on destination port 53.
    """
    return [
        f"-A NAI-OUTPUT -d {_EMBEDDED_RESOLVER} -j DROP",
        "-A NAI-OUTPUT -p udp --dport 53 -j DROP",
        "-A NAI-OUTPUT -p tcp --dport 53 -j DROP",
    ]


def _dns_v6_rules(policy: NetworkPolicy) -> list[str]:
    """Port-53 rules for the v6 chain. The embedded resolver is IPv4-only, so
    v6 :53 is dropped in every mode (no legitimate v6 DNS path exists)."""
    return [
        "-A NAI-OUTPUT -p udp --dport 53 -j DROP",
        "-A NAI-OUTPUT -p tcp --dport 53 -j DROP",
    ]


def build_ipv4_rules(policy: NetworkPolicy, *, gateway: str = "") -> list[str]:
    """iptables-restore lines for the worker netns (IPv4).

    Semantics:
    - OUTPUT jumps to NAI-OUTPUT (the ONLY OUTPUT rule emitted; the chain
      would otherwise never evaluate and egress would fall through to the
      default ACCEPT policy)
    - DNS rules FIRST (embedded resolver DROP and blanket port-53 DROP
      precede lo ACCEPT, which would otherwise shadow them)
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
    for blocked in dict.fromkeys((*COMMON_BLOCKED_NETS, *policy.explicitly_blocked)):
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
    always DROPped (the embedded resolver is IPv4-only).
    """
    lines = [
        "*filter",
        ":NAI-OUTPUT - [0:0]",
        _OUTPUT_JUMP,
        *_dns_v6_rules(policy),
        "-A NAI-OUTPUT -o lo -j ACCEPT",
        "-A NAI-OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
    ]
    translated_metadata = tuple(str(network) for network in translated_metadata_networks())
    for blocked in dict.fromkeys(
        (
            *_IPV6_EXTRA_BLOCKED,
            *(b for b in COMMON_BLOCKED_NETS if _ip_version(b) == 6),
            *policy.explicitly_blocked,
            *translated_metadata,
        )
    ):
        if _ip_version(blocked) != 6:
            continue
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
        "sandbox network policy installed: %d authorized destinations, worker DNS packets blocked",
        len(policy.authorized_destinations),
    )
    return True
