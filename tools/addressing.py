"""IP/DNS identities and explicit-family transport resolution.

Certificate identities never come from DNS answers. Resolution is an operation,
not configuration normalization: callers keep the hostname and TLS identity.
"""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
import socket
from typing import Callable


FAMILIES = {"ipv4": socket.AF_INET, "ipv6": socket.AF_INET6}
OUTBOUND_FLAGS = {"ipv4": "-4", "ipv6": "-6", "prefer_ipv4": "-46", "prefer_ipv6": "-64"}


@dataclass(frozen=True, order=True)
class Identity:
    kind: str
    value: str

    @property
    def family(self) -> str | None:
        if self.kind == "dns":
            return None
        return "ipv4" if ipaddress.ip_address(self.value).version == 4 else "ipv6"

    def acme_args(self) -> list[str]:
        return ["-d" if self.kind == "dns" else "--ip-address", self.value]

    def verify_args(self) -> list[str]:
        return ["-verify_hostname" if self.kind == "dns" else "-verify_ip", self.value]


def identity(value: object) -> Identity:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("identity must be a nonempty IP or DNS name without surrounding whitespace")
    if any(c in value for c in "%/\\[]@*?#") or any(ord(c) < 33 or ord(c) == 127 for c in value):
        raise ValueError("identity must not contain URL syntax, brackets, wildcard or zone ID")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        if ":" in value or re.fullmatch(r"[0-9.]+", value):
            raise ValueError("invalid IP identity; ports are not allowed") from None
        try:
            name = value.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("invalid DNS identity") from exc
        if value.endswith("..") or len(name) > 253 or not name:
            raise ValueError("invalid DNS identity")
        if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in name.split(".")):
            raise ValueError("invalid DNS identity")
        return Identity("dns", name)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        raise ValueError("use native IPv4 instead of a mapped IPv6 identity")
    return Identity("ip", str(address))


def identities(values: object) -> tuple[Identity, ...]:
    if not isinstance(values, list) or not values:
        raise ValueError("identifiers must be a nonempty list of IP/DNS names")
    result = tuple(sorted({identity(value) for value in values}))
    if len(result) > 25:
        raise ValueError("at most 25 distinct certificate identifiers are supported")
    return result


def families(values: object) -> tuple[str, ...]:
    if (not isinstance(values, list) or not values
            or any(not isinstance(v, str) or v not in FAMILIES for v in values)
            or len(set(values)) != len(values)):
        raise ValueError("families must be a nonempty unique list of ipv4/ipv6")
    return tuple(v for v in FAMILIES if v in values)


def literal(value: object) -> str:
    parsed = identity(value)
    if parsed.kind != "ip":
        raise ValueError("bind address must be a literal IP, not DNS")
    return parsed.value


def authority(host: str, port: int) -> str:
    parsed = identity(host)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("port must be 1..65535")
    formatted = f"[{parsed.value}]" if parsed.family == "ipv6" else parsed.value
    return f"{formatted}:{port}"


@dataclass(frozen=True)
class ResolvedAddress:
    family: str
    ip: str


def resolve(host: str, port: int, required: list[str] | tuple[str, ...], *,
            resolver: Callable | None = None) -> tuple[ResolvedAddress, ...]:
    """Require each requested family. Never hide broken AAAA with successful A."""
    parsed = identity(host)
    selected = families(list(required))
    authority(parsed.value, port)
    if parsed.kind == "ip":
        if selected != (parsed.family,):
            raise ValueError("literal endpoint does not provide all required address families")
        return (ResolvedAddress(parsed.family, parsed.value),)
    lookup = resolver or socket.getaddrinfo
    result = []
    for family in selected:
        try:
            rows = lookup(parsed.value, port, FAMILIES[family], socket.SOCK_STREAM, socket.IPPROTO_TCP)
        except OSError as exc:
            raise ValueError(f"DNS {family} lookup failed for {parsed.value}: {exc}") from exc
        addresses = set()
        for af, _, _, _, sockaddr in rows:
            candidate = identity(sockaddr[0])
            if af != FAMILIES[family] or candidate.family != family:
                raise ValueError("resolver returned an address outside the requested family")
            addresses.add(candidate.value)
        if not addresses:
            raise ValueError(f"DNS has no {family} addresses for {parsed.value}")
        result.extend(ResolvedAddress(family, ip) for ip in sorted(addresses, key=ipaddress.ip_address))
    return tuple(result)


def overlaps(left: str, right: str, *, ipv6_dualstack: bool = True) -> bool:
    """Conservative socket overlap, including Linux's IPv4-mapped wildcard."""
    a, b = ipaddress.ip_address(literal(left)), ipaddress.ip_address(literal(right))
    if a.version == b.version:
        return a == b or a.is_unspecified or b.is_unspecified
    return ipv6_dualstack and any(ip.version == 6 and ip.is_unspecified for ip in (a, b))


def normalized_sans(entries: tuple | list) -> set[Identity]:
    result = set()
    for kind, value in entries:
        if kind not in {"DNS", "IP Address"}:
            continue
        parsed = identity(value)
        if parsed.kind != ("dns" if kind == "DNS" else "ip"):
            raise ValueError("certificate SAN has the wrong identifier type")
        result.add(parsed)
    return result


def client_network(value: str):
    if "%" in value:
        raise ValueError("client CIDR must not contain a zone ID")
    network = ipaddress.ip_network(value, strict=False)
    if network.version == 6 and network.prefixlen >= 96 and network.network_address.ipv4_mapped is not None:
        return ipaddress.IPv4Network((network.network_address.ipv4_mapped, network.prefixlen - 96), strict=False)
    return network


def mapped_client_network(network: ipaddress.IPv4Network) -> str:
    address = (0xffff << 32) | int(network.network_address)
    return str(ipaddress.IPv6Network((address, 96 + network.prefixlen)))
