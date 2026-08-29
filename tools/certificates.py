#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ssl
from pathlib import Path

import config as config_tool


def certificate_sans(path: Path) -> tuple[set[str], set[str]]:
    decoded = ssl._ssl._test_decode_cert(str(path))  # type: ignore[attr-defined]
    entries = decoded.get("subjectAltName", ())
    ip_addresses = {value for kind, value in entries if kind == "IP Address"}
    dns_names = {value.lower() for kind, value in entries if kind == "DNS"}
    return ip_addresses, dns_names


def sans_match(certificate: Path, data: dict) -> bool:
    server_tls = config_tool.tls_server_config(data)
    if server_tls is None:
        raise ValueError("tls.server is required for managed certificate validation")
    actual_ips, actual_dns = certificate_sans(certificate)
    expected_ips = {str(data["server"]["public_ip"])}
    expected_dns = {name.lower() for name in server_tls["dns_names"]}
    return actual_ips == expected_ips and actual_dns == expected_dns


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--certificate", type=Path, required=True)
    args = parser.parse_args()
    data = config_tool.load_config(args.config)
    config_tool.validate(data)
    if not args.certificate.is_file():
        raise ValueError(f"certificate not found: {args.certificate}")
    if not sans_match(args.certificate, data):
        raise ValueError("managed certificate SAN set does not exactly match server.public_ip and tls.server.dns_names")
    print("managed certificate SANs match")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, ssl.SSLError) as exc:
        raise SystemExit(f"certificate error: {exc}")
