"""Address classification shared by host recon and sandbox egress policy."""

from __future__ import annotations

import ipaddress

# Cloud metadata and link-local destinations are always denied, including
# known IPv6 transition forms that embed their IPv4 destination.
METADATA_DESTINATIONS = [
    "169.254.169.254",
    "169.254.0.0/16",
    "fd00:ec2::254",
    "100.100.100.200",
    "fe80::/10",
    "64:ff9b::a9fe:a9fe",
    "64:ff9b:1:a9fe:a9:fe00::",
    "2002:a9fe:a9fe::",
    "2001::5601:5601",
]

_IPV4_METADATA_NETWORKS = tuple(ipaddress.ip_network(value) for value in METADATA_DESTINATIONS if ":" not in value)
_IPV6_METADATA_NETWORKS = tuple(ipaddress.ip_network(value) for value in METADATA_DESTINATIONS if ":" in value)
_NAT64_WELL_KNOWN = ipaddress.ip_network("64:ff9b::/96")
_NAT64_LOCAL_USE = ipaddress.ip_network("64:ff9b:1::/48")
_SIX_TO_FOUR = ipaddress.ip_network("2002::/16")
_TEREDO = ipaddress.ip_network("2001::/32")


def translated_metadata_networks() -> tuple[ipaddress.IPv6Network, ...]:
    """Return IPv6 ranges whose embedded IPv4 address is protected metadata.

    Firewall rules are first-match-wins. Dropping only known translated
    metadata *addresses* is insufficient when a user explicitly authorizes a
    containing IPv6 CIDR such as the NAT64 /96. Synthesize the corresponding
    ranges for formats where the embedded IPv4 prefix is contiguous; Teredo
    is blocked as a whole by the firewall because its client address is
    separated from the prefix by server/port fields.
    """
    result: list[ipaddress.IPv6Network] = []
    for v4_network in _IPV4_METADATA_NETWORKS:
        prefix = int(v4_network.network_address)
        base_nets = (
            (ipaddress.IPv6Address("64:ff9b::"), 96),
            (ipaddress.IPv6Address("2002::"), 16),
        )
        for base, base_prefix in base_nets:
            shift = 128 - base_prefix - 32
            network_address = ipaddress.IPv6Address(int(base) | (prefix << shift))
            result.append(ipaddress.IPv6Network((network_address, base_prefix + v4_network.prefixlen), strict=False))

        # RFC 8215 local-use NAT64 (RFC 6052 /48 layout) supports the full
        # protected IPv4 set, including Alibaba's 100.100.100.200 metadata
        # address. For prefixes through /16, IPv4 bits follow the /48
        # immediately. Longer IPv4 prefixes cross the reserved u octet, so
        # the resulting IPv6 prefix length includes that eight-bit gap.
        v4_bytes = v4_network.network_address.packed
        translated_bytes = (
            ipaddress.IPv6Network("64:ff9b:1::/48").network_address.packed[:6]
            + v4_bytes[:2]
            + b"\x00"
            + v4_bytes[2:]
            + (b"\x00" * 5)
        )
        translated_prefix = 48 + v4_network.prefixlen + (8 if v4_network.prefixlen > 16 else 0)
        result.append(
            ipaddress.IPv6Network(
                (ipaddress.IPv6Address(translated_bytes), translated_prefix),
                strict=False,
            )
        )

    return tuple(dict.fromkeys(result))


def embedded_ipv4_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """Extract IPv4 from mapped, NAT64, 6to4, and Teredo IPv6 addresses."""
    if isinstance(address, ipaddress.IPv4Address):
        return address
    if address.ipv4_mapped is not None:
        return address.ipv4_mapped
    packed = address.packed
    if address in _NAT64_WELL_KNOWN:
        return ipaddress.IPv4Address(packed[-4:])
    if address in _NAT64_LOCAL_USE:
        # RFC 6052 /48 layout reserves the first byte after the prefix as the
        # u octet; the IPv4 bytes straddle that octet.
        return ipaddress.IPv4Address(packed[6:8] + packed[9:11])
    if address in _SIX_TO_FOUR:
        return ipaddress.IPv4Address(packed[2:6])
    if address in _TEREDO:
        return ipaddress.IPv4Address(bytes(byte ^ 0xFF for byte in packed[-4:]))
    return None


def is_metadata_destination(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Whether an address or its embedded IPv4 destination is protected."""
    blocked_networks = _IPV4_METADATA_NETWORKS if address.version == 4 else _IPV6_METADATA_NETWORKS
    if any(address in network for network in blocked_networks):
        return True
    embedded = embedded_ipv4_address(address)
    return embedded is not None and any(embedded in network for network in _IPV4_METADATA_NETWORKS)


def is_public_destination(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True only if the outer address and any embedded IPv4 are globally routable."""
    embedded = embedded_ipv4_address(address)
    return address.is_global and (embedded is None or embedded.is_global)
