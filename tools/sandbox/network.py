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
import re
from collections.abc import Callable
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
    "parse_drop_packet_count",
    "read_drop_packet_count",
    "read_netns_drop_packet_count",
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
_DROP_CHAIN = "NAI-DROP"
_COUNTER_LINE = re.compile(r"^\[(\d+):(\d+)\]\s+(.+)$")


def _accept_rule(destination: str) -> str:
    return f"-A NAI-OUTPUT -d {destination} -j ACCEPT"


def _dns_v4_rules(policy: NetworkPolicy, *, drop_target: str = "DROP") -> list[str]:
    """No worker DNS egress, even for domain-authorized missions.

    Host-side resolution supplies pinned hosts mappings. Docker rewrites its
    embedded resolver's port in NAT, so block the complete resolver address
    before loopback ACCEPT rather than relying only on destination port 53.
    """
    return [
        f"-A NAI-OUTPUT -d {_EMBEDDED_RESOLVER} -j {drop_target}",
        f"-A NAI-OUTPUT -p udp --dport 53 -j {drop_target}",
        f"-A NAI-OUTPUT -p tcp --dport 53 -j {drop_target}",
    ]


def _dns_v6_rules(policy: NetworkPolicy, *, drop_target: str = "DROP") -> list[str]:
    """Port-53 rules for the v6 chain. The embedded resolver is IPv4-only, so
    v6 :53 is dropped in every mode (no legitimate v6 DNS path exists)."""
    return [
        f"-A NAI-OUTPUT -p udp --dport 53 -j {drop_target}",
        f"-A NAI-OUTPUT -p tcp --dport 53 -j {drop_target}",
    ]


def build_ipv4_rules(policy: NetworkPolicy, *, gateway: str = "", preserve_drop_counters: bool = False) -> list[str]:
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
    drop_target = _DROP_CHAIN
    lines = ["*filter"]
    if preserve_drop_counters:
        # Policy refreshes are applied with iptables-restore --noflush. Flush
        # only the policy chain; the separate NAI-DROP chain and its kernel
        # packet counter survive every allowlist refresh.
        lines.append("-F NAI-OUTPUT")
    else:
        lines.extend([":NAI-OUTPUT - [0:0]", f":{_DROP_CHAIN} - [0:0]", _OUTPUT_JUMP])
    lines.extend(
        [
            *_dns_v4_rules(policy, drop_target=drop_target),
            "-A NAI-OUTPUT -o lo -j ACCEPT",
            "-A NAI-OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
        ]
    )
    for blocked in dict.fromkeys((*COMMON_BLOCKED_NETS, *policy.explicitly_blocked)):
        if _ip_version(blocked) != 4:
            continue
        lines.append(f"-A NAI-OUTPUT -d {blocked} -j {drop_target}")
    if not policy.allow_gateway and gateway and _ip_version(gateway) == 4:
        # Block the Docker bridge gateway (a path to host-published services
        # and to the Docker daemon). The rest of the bridge subnet is handled
        # by the terminating default-DROP.
        lines.append(f"-A NAI-OUTPUT -d {gateway} -j {drop_target}")
    # RFC1918 is NOT blanket-blocked: lab targets are usually RFC1918, so the
    # authorization set (which may contain private CIDRs) is the boundary.
    # Family-filtered: an IPv6 authorized destination must never reach
    # iptables-restore (it would abort the whole install); v6 ACCEPTs live
    # in build_ipv6_rules. Unparsable entries are skipped (fail closed).
    for dest in policy.authorized_destinations:
        if _ip_version(dest) != 4:
            continue
        lines.append(_accept_rule(dest))
    lines.append(f"-A NAI-OUTPUT -j {drop_target}")
    if not preserve_drop_counters:
        lines.append(f"-A {_DROP_CHAIN} -j DROP")
    lines.append("COMMIT")
    return [ln for ln in lines if ln]


def build_ipv6_rules(policy: NetworkPolicy, *, gateway: str = "", preserve_drop_counters: bool = False) -> list[str]:
    """ip6tables-restore lines: loopback + established only, then DROP.

    IPv6 egress stays denied unless an explicitly authorized destination is an
    IPv6 address/CIDR (those get ACCEPT plumbed through here). v6 :53 is
    always DROPped (the embedded resolver is IPv4-only).
    """
    drop_target = _DROP_CHAIN
    lines = ["*filter"]
    if preserve_drop_counters:
        lines.append("-F NAI-OUTPUT")
    else:
        lines.extend([":NAI-OUTPUT - [0:0]", f":{_DROP_CHAIN} - [0:0]", _OUTPUT_JUMP])
    lines.extend(
        [
            *_dns_v6_rules(policy, drop_target=drop_target),
            "-A NAI-OUTPUT -o lo -j ACCEPT",
            "-A NAI-OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
        ]
    )
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
        lines.append(f"-A NAI-OUTPUT -d {blocked} -j {drop_target}")

    for dest in policy.authorized_destinations:
        if _ip_version(dest) != 6:
            continue
        lines.append(_accept_rule(dest))
    lines.append(f"-A NAI-OUTPUT -j {drop_target}")
    if not preserve_drop_counters:
        lines.append(f"-A {_DROP_CHAIN} -j DROP")
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
    preserve_drop_counters: bool = False,
) -> bool:
    """Install the ruleset in the worker netns via a NET_ADMIN sidecar.

    ``run_sidecar`` is the seam tests monkeypatch (default: the
    docker_backend wrapper). Returns True on success; ANY failure raises
    ``SandboxPolicyError`` (never silently proceeds uncontained).
    """
    if run_sidecar is None:
        from tools.sandbox.docker_backend import run_netns_sidecar as run_sidecar
    rules_v4 = build_ipv4_rules(policy, gateway=gateway, preserve_drop_counters=preserve_drop_counters)
    rules_v6 = build_ipv6_rules(policy, gateway=gateway, preserve_drop_counters=preserve_drop_counters)
    for proto, rules in (
        ("iptables-restore", "\n".join(rules_v4) + "\n"),
        ("ip6tables-restore", "\n".join(rules_v6) + "\n"),
    ):
        if preserve_drop_counters:
            rc, out, err = run_sidecar(container_id, image, proto, rules, ("--noflush",))
        else:
            rc, out, err = run_sidecar(container_id, image, proto, rules)
        if rc != 0:
            raise SandboxPolicyError(f"{proto} failed in sandbox netns (rc={rc}): {(err or out).strip()[:300]}")
    logger.info(
        "sandbox network policy installed: %d authorized destinations, worker DNS packets blocked",
        len(policy.authorized_destinations),
    )
    return True


def parse_drop_packet_count(ruleset: str) -> int:
    """Read our tagged terminal DROP rule's packet count from ``*-save -c``.

    The parser deliberately requires the installed OUTPUT hook, both private
    chains, and the single terminal DROP rule. Missing/truncated/uninstrumented
    output is an unavailable measurement, never a clean zero.
    """
    if not isinstance(ruleset, str) or not ruleset:
        raise ValueError("empty firewall counter output")

    chain_names: set[str] = set()
    parsed_rules: list[tuple[str, str, int]] = []
    for raw_line in ruleset.splitlines():
        line = raw_line.strip()
        if line.startswith(":"):
            name = line[1:].split(None, 1)[0]
            chain_names.add(name)
            continue
        if not line.startswith("["):
            continue
        match = _COUNTER_LINE.fullmatch(line)
        if match is None:
            raise ValueError("malformed firewall counter line")
        packets = int(match.group(1))
        rule = match.group(3)
        if rule.startswith("-A OUTPUT "):
            parsed_rules.append(("OUTPUT", rule, packets))
        elif rule.startswith("-A NAI-OUTPUT "):
            parsed_rules.append(("NAI-OUTPUT", rule, packets))
        elif rule.startswith(f"-A {_DROP_CHAIN} "):
            parsed_rules.append((_DROP_CHAIN, rule, packets))

    if not {"NAI-OUTPUT", _DROP_CHAIN}.issubset(chain_names):
        raise ValueError("firewall counter chains are missing")
    output_rules = [rule for chain, rule, _ in parsed_rules if chain == "NAI-OUTPUT"]
    hook = [rule for rule in output_rules if rule == "-A NAI-OUTPUT -j NAI-DROP"]
    if not any(chain == "OUTPUT" and rule == "-A OUTPUT -j NAI-OUTPUT" for chain, rule, _ in parsed_rules):
        raise ValueError("worker OUTPUT firewall hook is missing")
    if not hook:
        raise ValueError("policy does not route blocked egress through the counter chain")
    terminal = [(rule, packets) for chain, rule, packets in parsed_rules if chain == _DROP_CHAIN]
    if len(terminal) != 1 or terminal[0][0] != f"-A {_DROP_CHAIN} -j DROP":
        raise ValueError("firewall DROP counter chain is malformed")
    return terminal[0][1]


def read_drop_packet_count(
    query: Callable[[str], tuple[int, str, str]],
) -> int:
    """Query both address families through a trusted NET_ADMIN sidecar."""
    total = 0
    for family in ("iptables-save", "ip6tables-save"):
        rc, output, error = query(family)
        if rc != 0:
            raise ValueError(f"{family} counter read failed: {(error or output).strip()[:200]}")
        total += parse_drop_packet_count(output)
    return total


def read_netns_drop_packet_count(container_id: str, image: str) -> int:
    """Read both packet counters using only short-lived trusted sidecars."""
    from tools.sandbox.docker_backend import read_netns_firewall_counter

    return read_drop_packet_count(lambda binary: read_netns_firewall_counter(container_id, image, binary))
