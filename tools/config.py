#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
from pathlib import Path
from typing import Any

import yaml


EXPECTED_LISTENERS = {
    "socks_direct": ("socks5", "direct", {"tcp", "udp"}),
    "socks_via_socks": ("socks5", "socks_primary", {"tcp", "udp"}),
    "socks_via_http": ("socks5", "http_primary", {"tcp"}),
    "http_direct": ("http", "direct", {"tcp"}),
    "http_via_socks": ("http", "socks_primary", {"tcp"}),
    "http_via_http": ("http", "http_primary", {"tcp"}),
}


def load_config(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as stream:
        data = yaml.safe_load(stream)
    if not isinstance(data, dict):
        raise ValueError("YAML root must be a mapping")
    return data


def scalar(data: dict[str, Any], dotted: str) -> Any:
    current: Any = data
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            raise ValueError(f"missing configuration key: {dotted}")
        current = current[part]
    if isinstance(current, (dict, list)):
        raise ValueError(f"configuration value is not scalar: {dotted}")
    return current


def safe_token(value: Any, name: str, *, colon: bool = True) -> str:
    if not isinstance(value, str) or not value or len(value.encode()) > 255:
        raise ValueError(f"{name} must be a non-empty string up to 255 bytes")
    if re.search(r"[\s\x00-\x1f\x7f]", value) or (colon and ":" in value):
        raise ValueError(f"{name} contains characters unsafe for 3proxy configuration")
    return value


def validate(data: dict[str, Any]) -> None:
    install = data.get("install")
    if not isinstance(install, dict):
        raise ValueError("install must be a mapping")
    if install.get("version") != "0.9.7":
        raise ValueError("this patch-set is pinned to 3proxy 0.9.7")
    if not re.fullmatch(r"[0-9a-f]{64}", str(install.get("sha256", ""))):
        raise ValueError("install.sha256 must be a lowercase SHA-256")
    if not str(install.get("source_url", "")).startswith("https://github.com/3proxy/3proxy/"):
        raise ValueError("install.source_url must use the official 3proxy GitHub repository")

    server = data.get("server")
    if not isinstance(server, dict):
        raise ValueError("server must be a mapping")
    ipaddress.ip_address(str(server.get("public_ip")))
    ipaddress.ip_address(str(server.get("listen_ip")))
    ipaddress.ip_network(str(server.get("udp_client_cidr")), strict=False)
    if not isinstance(server.get("manage_ufw"), bool):
        raise ValueError("server.manage_ufw must be boolean")

    logging = data.get("logging", {})
    if not isinstance(logging, dict):
        raise ValueError("logging must be a mapping")
    if logging.get("format", "monitor_v1") != "monitor_v1":
        raise ValueError("logging.format must be monitor_v1")
    if logging.get("rotation", "daily") != "daily":
        raise ValueError("logging.rotation must be daily")
    keep_files = logging.get("keep_files", 14)
    if not isinstance(keep_files, int) or not 1 <= keep_files <= 365:
        raise ValueError("logging.keep_files must be between 1 and 365")
    if not isinstance(logging.get("compress", True), bool):
        raise ValueError("logging.compress must be boolean")

    local = data.get("local_auth")
    if not isinstance(local, dict):
        raise ValueError("local_auth must be a mapping")
    safe_token(local.get("username"), "local_auth.username")
    safe_token(local.get("password"), "local_auth.password")

    upstreams = data.get("upstreams")
    if not isinstance(upstreams, dict) or set(upstreams) != {"socks_primary", "http_primary"}:
        raise ValueError("upstreams must define socks_primary and http_primary")
    for name, upstream in upstreams.items():
        if not isinstance(upstream, dict):
            raise ValueError(f"upstreams.{name} must be a mapping")
        expected_type = "socks5" if name == "socks_primary" else "http"
        if upstream.get("type") != expected_type:
            raise ValueError(f"upstreams.{name}.type must be {expected_type}")
        safe_token(upstream.get("host"), f"upstreams.{name}.host", colon=False)
        safe_token(upstream.get("username"), f"upstreams.{name}.username")
        safe_token(upstream.get("password"), f"upstreams.{name}.password")
        port = upstream.get("port")
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError(f"upstreams.{name}.port is invalid")
        ipaddress.ip_address(str(upstream.get("expected_egress_ip")))
        capabilities = set(upstream.get("capabilities", []))
        expected_caps = {"tcp", "udp"} if expected_type == "socks5" else {"tcp"}
        if capabilities != expected_caps:
            raise ValueError(f"upstreams.{name}.capabilities must be {sorted(expected_caps)}")

    listeners = data.get("listeners")
    if not isinstance(listeners, list) or len(listeners) != 6:
        raise ValueError("listeners must contain exactly six entries")
    by_id: dict[str, dict[str, Any]] = {}
    ports: set[int] = set()
    for item in listeners:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            raise ValueError("each listener must be a mapping with id")
        listener_id = item["id"]
        if listener_id in by_id:
            raise ValueError(f"duplicate listener id: {listener_id}")
        by_id[listener_id] = item
        port = item.get("port")
        if not isinstance(port, int) or not 1 <= port <= 65535 or port in ports:
            raise ValueError(f"invalid or duplicate listener port: {port}")
        ports.add(port)
    if set(by_id) != set(EXPECTED_LISTENERS):
        raise ValueError("listener ids do not match the supported six-endpoint topology")
    for listener_id, (protocol, parent, capabilities) in EXPECTED_LISTENERS.items():
        item = by_id[listener_id]
        if item.get("protocol") != protocol or item.get("parent") != parent:
            raise ValueError(f"listener {listener_id} has an invalid protocol/parent mapping")
        if set(item.get("capabilities", [])) != capabilities:
            raise ValueError(f"listener {listener_id} has invalid capabilities")

    probes = data.get("probes")
    if not isinstance(probes, dict):
        raise ValueError("probes must be a mapping")
    timeout = probes.get("timeout_seconds")
    if not isinstance(timeout, (int, float)) or not 1 <= timeout <= 60:
        raise ValueError("probes.timeout_seconds must be between 1 and 60")
    if not isinstance(probes.get("stun_servers"), list) or not probes["stun_servers"]:
        raise ValueError("at least one STUN server is required")


def parent_line(data: dict[str, Any], name: str) -> str:
    upstream = data["upstreams"][name]
    parent_type = "socks5" if upstream["type"] == "socks5" else "connect+"
    return "parent 1000 {} {} {} {} {}".format(
        parent_type, upstream["host"], upstream["port"], upstream["username"], upstream["password"]
    )


def render_3proxy(data: dict[str, Any]) -> str:
    user = data["local_auth"]["username"]
    password = data["local_auth"]["password"]
    listen_ip = data["server"]["listen_ip"]
    public_ip = data["server"]["public_ip"]
    logging = data.get("logging", {})
    keep_files = logging.get("keep_files", 14)
    lines = [
        "# Generated by 3proxy-setup; do not edit manually",
        "nserver 8.8.8.8",
        "nserver 8.8.4.4",
        "nscache 65536",
        "log /var/log/3proxy/3proxy.log D",
        f"rotate {keep_files}",
        *(["archiver gz /usr/bin/gzip %F"] if logging.get("compress", True) else []),
        'logformat "-|+_Gv1|%t|%.|%D|%N|%p|%E|%U|%C|%c|%R|%r|%Q|%q|%n|%O|%I|%h|%T"',
        "timeouts 1 5 30 60 180 1800 15 60 15 5",
        "maxconn 1000",
        f"users {user}:CL:{password}",
        "",
    ]
    for listener in sorted(data["listeners"], key=lambda item: item["port"]):
        lines.extend([f"# {listener['id']}", "auth strong", f"allow {user}"])
        if listener["parent"] != "direct":
            lines.append(parent_line(data, listener["parent"]))
        if listener["protocol"] == "socks5":
            nat = f" -Ni{public_ip}" if "udp" in listener["capabilities"] else ""
            lines.append(f"socks -i{listen_ip} -p{listener['port']}{nat}")
        else:
            lines.append(f"proxy -i{listen_ip} -p{listener['port']}")
        lines.extend(["flush", ""])
    return "\n".join(lines)


def render_systemd() -> str:
    return """[Unit]
Description=3proxy - patched modular installation
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/3proxy /etc/3proxy/3proxy.cfg
Restart=always
RestartSec=3
LimitNOFILE=65536
NoNewPrivileges=true
UMask=0027

[Install]
WantedBy=multi-user.target
"""


def write_text(path: Path, value: str) -> None:
    path.write_text(value, encoding="utf-8", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("validate", "get", "render-3proxy", "ports"):
        item = sub.add_parser(name)
        item.add_argument("--config", type=Path, required=True)
        if name == "get":
            item.add_argument("--path", required=True)
        if name == "render-3proxy":
            item.add_argument("--output", type=Path, required=True)
    systemd = sub.add_parser("render-systemd")
    systemd.add_argument("--output", type=Path, required=True)
    matches = sub.add_parser("manifest-matches")
    matches.add_argument("--manifest", type=Path, required=True)
    manifest = sub.add_parser("write-manifest")
    manifest.add_argument("--output", type=Path, required=True)
    for item in (matches, manifest):
        item.add_argument("--version", required=True)
        item.add_argument("--source-sha", required=True)
        item.add_argument("--patch-sha", required=True)
    manifest.add_argument("--binary-sha", required=True)
    args = parser.parse_args()

    if args.command in {"validate", "get", "render-3proxy", "ports"}:
        data = load_config(args.config)
        validate(data)
    if args.command == "validate":
        print("configuration valid")
    elif args.command == "get":
        value = scalar(data, args.path)
        print(str(value).lower() if isinstance(value, bool) else value)
    elif args.command == "render-3proxy":
        write_text(args.output, render_3proxy(data))
    elif args.command == "render-systemd":
        write_text(args.output, render_systemd())
    elif args.command == "ports":
        for item in sorted(data["listeners"], key=lambda value: value["port"]):
            print(item["port"])
    elif args.command == "manifest-matches":
        try:
            current = json.loads(args.manifest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return 1
        return 0 if all(current.get(key) == value for key, value in {
            "version": args.version, "source_sha256": args.source_sha, "patchset_sha256": args.patch_sha
        }.items()) else 1
    elif args.command == "write-manifest":
        payload = {
            "version": args.version,
            "source_sha256": args.source_sha,
            "patchset_sha256": args.patch_sha,
            "binary_sha256": args.binary_sha,
        }
        write_text(args.output, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, KeyError, TypeError) as exc:
        raise SystemExit(f"configuration error: {exc}")
