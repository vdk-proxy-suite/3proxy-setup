"""Resolve parent transports before stopping an instance; retain TLS names in YAML."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import addressing


def policy_key(data: dict) -> str:
    # Only route identity belongs in this snapshot, never passwords or auth hashes.
    routes = {name: {key: upstream.get(key) for key in ("host", "port", "resolve_family", "tls_server_name")}
              for name, upstream in data.get("upstreams", {}).items()}
    return hashlib.sha256(json.dumps(routes, sort_keys=True).encode()).hexdigest()


def resolve_parent(upstream: dict) -> str:
    host = addressing.identity(upstream["host"])
    family = upstream.get("resolve_family", host.family or "prefer_ipv4")
    if host.kind == "ip":
        if family in addressing.FAMILIES and family != host.family:
            raise ValueError("upstream resolve_family conflicts with its literal host")
        return host.value
    sequence = {"ipv4": ["ipv4"], "ipv6": ["ipv6"], "prefer_ipv4": ["ipv4", "ipv6"],
                "prefer_ipv6": ["ipv6", "ipv4"]}[family]
    errors = []
    for selected in sequence:
        try:
            return addressing.resolve(host.value, upstream["port"], [selected])[0].ip
        except ValueError as exc:
            errors.append(str(exc))
    raise ValueError("cannot resolve configured upstream: " + "; ".join(errors))


def create(data: dict) -> dict:
    return dict(schema=1, policy_key=policy_key(data),
                addresses={name: resolve_parent(upstream) for name, upstream in data.get("upstreams", {}).items()})


def validate(data: dict, snapshot: dict) -> dict[str, str]:
    if not isinstance(snapshot, dict) or set(snapshot) != {"schema", "policy_key", "addresses"}:
        raise ValueError("invalid upstream resolution snapshot")
    if snapshot["schema"] != 1 or snapshot["policy_key"] != policy_key(data):
        raise ValueError("upstream resolution snapshot belongs to a different routing policy")
    addresses = snapshot["addresses"]
    if not isinstance(addresses, dict) or set(addresses) != set(data.get("upstreams", {})):
        raise ValueError("upstream resolution snapshot has missing or extra routes")
    for name, ip in addresses.items():
        selected = addressing.identity(ip)
        if selected.kind != "ip":
            raise ValueError("upstream resolution snapshot must contain literal IPs")
        upstream = data["upstreams"][name]
        supplied = addressing.identity(upstream["host"])
        family = upstream.get("resolve_family", supplied.family or "prefer_ipv4")
        if family in addressing.FAMILIES and selected.family != family:
            raise ValueError("upstream snapshot has wrong address family")
        if supplied.kind == "ip" and supplied != selected:
            raise ValueError("upstream snapshot changed a literal host")
    return addresses


def load(path: Path, data: dict) -> dict[str, str]:
    from instance import guard
    guard(path)
    if not path.is_file() or path.stat().st_nlink != 1:
        raise ValueError("upstream resolution snapshot must be an owned regular file")
    return validate(data, json.loads(path.read_text()))
