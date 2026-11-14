#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ssl
from pathlib import Path

import config as config_tool
import addressing
import schema_v2


def certificate_sans(path: Path) -> tuple[set[str], set[str]]:
    decoded = ssl._ssl._test_decode_cert(str(path))  # type: ignore[attr-defined]
    entries = decoded.get("subjectAltName", ())
    normalized = addressing.normalized_sans(entries)
    ip_addresses = {item.value for item in normalized if item.kind == "ip"}
    dns_names = {item.value for item in normalized if item.kind == "dns"}
    return ip_addresses, dns_names


def sans_match(certificate: Path, data: dict, certificate_id: str | None = None) -> bool:
    if schema_v2.enabled(data):
        certs = schema_v2.certificates(data)
        if certificate_id is None and len(certs) == 1:
            certificate_id = next(iter(certs))
        if certificate_id not in certs:
            raise ValueError("select a known --certificate-id")
        expected = schema_v2.certificate_identities(data, certificate_id)
        actual_ips, actual_dns = certificate_sans(certificate)
        return (actual_ips == {i.value for i in expected if i.kind == "ip"}
                and actual_dns == {i.value for i in expected if i.kind == "dns"})
    server_tls = config_tool.tls_server_config(data)
    if server_tls is None:
        raise ValueError("tls.server is required for managed certificate validation")
    actual_ips, actual_dns = certificate_sans(certificate)
    expected_ips = {addressing.identity(data["server"]["public_ip"]).value}
    expected_dns = {addressing.identity(name).value for name in server_tls["dns_names"]}
    return actual_ips == expected_ips and actual_dns == expected_dns


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--certificate-id")
    args = parser.parse_args()
    data = config_tool.load_config(args.config)
    config_tool.validate(data)
    if not args.certificate.is_file():
        raise ValueError(f"certificate not found: {args.certificate}")
    if not sans_match(args.certificate, data, args.certificate_id):
        raise ValueError("managed certificate SAN set does not exactly match server.public_ip and tls.server.dns_names")
    print("managed certificate SANs match")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, ssl.SSLError) as exc:
        raise SystemExit(f"certificate error: {exc}")
