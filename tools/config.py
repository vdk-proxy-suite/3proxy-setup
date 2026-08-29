#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import posixpath
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
    "socks_via_https": ("socks5", "https_primary", {"tcp"}),
    "http_via_https": ("http", "https_primary", {"tcp"}),
}

SUPPORTED_UPSTREAMS = {
    "socks_primary": ("socks5", {"tcp", "udp"}),
    "http_primary": ("http", {"tcp"}),
    "https_primary": ("https", {"tcp"}),
}

DEFAULT_CLIENT_CA_FILE = "/etc/ssl/certs/ca-certificates.crt"
BUILD_PROFILE = "cmake-openssl"
INSTALL_VERSION = "1.0.0"
INSTALL_SOURCE_URL = "https://github.com/3proxy/3proxy/archive/refs/tags/1.0.0.tar.gz"
INSTALL_SHA256 = "35b07de1046f3aaeac4a7085101b7e5c453efa3527cbdc42a84690366c7ecfa8"


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


def dns_hostname(value: Any, name: str) -> str:
    hostname = safe_token(value, name, colon=False)
    if len(hostname) > 253 or hostname.endswith("."):
        raise ValueError(f"{name} must be an unambiguous DNS hostname")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ValueError(f"{name} must be a DNS hostname, not an IP address")
    labels = hostname.split(".")
    if any(
        not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
        for label in labels
    ):
        raise ValueError(f"{name} must be a valid DNS hostname")
    return hostname


def client_ca_file(data: dict[str, Any]) -> str:
    return data.get("tls", {}).get("client_ca_file", DEFAULT_CLIENT_CA_FILE)


def listener_ip(data: dict[str, Any], listener: dict[str, Any]) -> str:
    return str(listener.get("listen_ip", data["server"]["listen_ip"]))


def upstream_credentials(upstream: dict[str, Any], name: str) -> tuple[str | None, str | None]:
    username = upstream.get("username")
    password = upstream.get("password")
    if (username is None) != (password is None):
        raise ValueError(f"upstreams.{name}.username and password must be provided together")
    if username is None:
        return None, None
    return (
        safe_token(username, f"upstreams.{name}.username"),
        safe_token(password, f"upstreams.{name}.password"),
    )


def validate(data: dict[str, Any]) -> None:
    install = data.get("install")
    if not isinstance(install, dict):
        raise ValueError("install must be a mapping")
    if install.get("version") != INSTALL_VERSION:
        raise ValueError("this release is pinned to 3proxy 1.0.0")
    if install.get("source_url") != INSTALL_SOURCE_URL:
        raise ValueError("install.source_url must be the pinned official 3proxy 1.0.0 tag archive")
    if install.get("sha256") != INSTALL_SHA256:
        raise ValueError("install.sha256 must match the pinned official 3proxy 1.0.0 tag archive")

    server = data.get("server")
    if not isinstance(server, dict):
        raise ValueError("server must be a mapping")
    ipaddress.ip_address(str(server.get("public_ip")))
    ipaddress.ip_address(str(server.get("listen_ip")))
    ipaddress.ip_network(str(server.get("udp_client_cidr")), strict=False)
    if not isinstance(server.get("manage_ufw"), bool):
        raise ValueError("server.manage_ufw must be boolean")

    tls = data.get("tls", {})
    if not isinstance(tls, dict):
        raise ValueError("tls must be a mapping")
    unknown_tls = set(tls) - {"client_ca_file"}
    if unknown_tls:
        raise ValueError(f"unsupported tls settings: {sorted(unknown_tls)}")
    ca_file = client_ca_file(data)
    safe_token(ca_file, "tls.client_ca_file", colon=False)
    if (
        not ca_file.startswith("/")
        or ca_file == "/"
        or "//" in ca_file
        or posixpath.normpath(ca_file) != ca_file
    ):
        raise ValueError("tls.client_ca_file must be an absolute normalized POSIX path")

    logging = data.get("logging", {})
    if not isinstance(logging, dict):
        raise ValueError("logging must be a mapping")
    if logging.get("format", "monitor_v1") != "monitor_v1":
        raise ValueError("logging.format must be monitor_v1")
    if logging.get("rotation", "daily") != "daily":
        raise ValueError("logging.rotation must be daily")
    keep_files = logging.get("keep_files", 14)
    if isinstance(keep_files, bool) or not isinstance(keep_files, int) or not 1 <= keep_files <= 365:
        raise ValueError("logging.keep_files must be between 1 and 365")
    if not isinstance(logging.get("compress", True), bool):
        raise ValueError("logging.compress must be boolean")

    access = data.get("access", {})
    if not isinstance(access, dict):
        raise ValueError("access must be a mapping")
    mode = access.get("mode", "strong")
    if mode not in {"strong", "iponly"}:
        raise ValueError("access.mode must be strong or iponly")
    allowed_client_cidrs = access.get("allowed_client_cidrs", [])
    if not isinstance(allowed_client_cidrs, list):
        raise ValueError("access.allowed_client_cidrs must be a list")
    if mode == "iponly" and not allowed_client_cidrs:
        raise ValueError("iponly access requires at least one allowed client CIDR")
    for index, value in enumerate(allowed_client_cidrs):
        network = ipaddress.ip_network(str(value), strict=False)
        if network.version != 4:
            raise ValueError(f"access.allowed_client_cidrs[{index}] must be IPv4")
        if network.prefixlen == 0:
            raise ValueError("iponly access must not allow an open /0 network")

    local = data.get("local_auth")
    if mode == "strong":
        if not isinstance(local, dict):
            raise ValueError("local_auth must be a mapping in strong mode")
        safe_token(local.get("username"), "local_auth.username")
        safe_token(local.get("password"), "local_auth.password")
    elif local is not None and not isinstance(local, dict):
        raise ValueError("local_auth must be a mapping when provided")

    upstreams = data.get("upstreams", {})
    if not isinstance(upstreams, dict):
        raise ValueError("upstreams must be a mapping")
    unknown_upstreams = set(upstreams) - set(SUPPORTED_UPSTREAMS)
    if unknown_upstreams:
        raise ValueError(f"unsupported upstreams: {sorted(unknown_upstreams)}")
    for name, upstream in upstreams.items():
        if not isinstance(upstream, dict):
            raise ValueError(f"upstreams.{name} must be a mapping")
        expected_type, expected_caps = SUPPORTED_UPSTREAMS[name]
        allowed_keys = {
            "type", "host", "port", "username", "password", "expected_egress_ip", "capabilities"
        }
        if expected_type == "https":
            allowed_keys.add("tls_server_name")
        unknown_keys = set(upstream) - allowed_keys
        if unknown_keys:
            raise ValueError(f"unsupported settings in upstreams.{name}: {sorted(unknown_keys)}")
        if upstream.get("type") != expected_type:
            raise ValueError(f"upstreams.{name}.type must be {expected_type}")
        safe_token(upstream.get("host"), f"upstreams.{name}.host", colon=False)
        username, password = upstream_credentials(upstream, name)
        if expected_type == "https":
            dns_hostname(upstream.get("tls_server_name"), f"upstreams.{name}.tls_server_name")
            if username is not None and (len(username.encode()) > 128 or len(password.encode()) > 128):
                raise ValueError(f"upstreams.{name} HTTPS credentials must be at most 128 bytes")
        elif "tls_server_name" in upstream:
            raise ValueError(f"upstreams.{name}.tls_server_name is only valid for HTTPS upstreams")
        port = upstream.get("port")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError(f"upstreams.{name}.port is invalid")
        ipaddress.ip_address(str(upstream.get("expected_egress_ip")))
        capabilities = set(upstream.get("capabilities", []))
        if capabilities != expected_caps:
            raise ValueError(f"upstreams.{name}.capabilities must be {sorted(expected_caps)}")

    listeners = data.get("listeners")
    if not isinstance(listeners, list) or not listeners:
        raise ValueError("listeners must contain at least one entry")
    if len(listeners) > len(EXPECTED_LISTENERS):
        raise ValueError("listeners contains more entries than the supported topology")
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
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535 or port in ports:
            raise ValueError(f"invalid or duplicate listener port: {port}")
        ports.add(port)
        ipaddress.ip_address(listener_ip(data, item))
    unknown_listeners = set(by_id) - set(EXPECTED_LISTENERS)
    if unknown_listeners:
        raise ValueError(f"unsupported listener ids: {sorted(unknown_listeners)}")
    for listener_id, item in by_id.items():
        protocol, parent, capabilities = EXPECTED_LISTENERS[listener_id]
        if item.get("protocol") != protocol or item.get("parent") != parent:
            raise ValueError(f"listener {listener_id} has an invalid protocol/parent mapping")
        if set(item.get("capabilities", [])) != capabilities:
            raise ValueError(f"listener {listener_id} has invalid capabilities")
        if parent != "direct" and parent not in upstreams:
            raise ValueError(f"listener {listener_id} references undefined upstream {parent}")

    probes = data.get("probes")
    if not isinstance(probes, dict):
        raise ValueError("probes must be a mapping")
    timeout = probes.get("timeout_seconds")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 1 <= timeout <= 60:
        raise ValueError("probes.timeout_seconds must be between 1 and 60")
    if not isinstance(probes.get("stun_servers"), list) or not probes["stun_servers"]:
        raise ValueError("at least one STUN server is required")


def parent_line(data: dict[str, Any], name: str) -> str:
    upstream = data["upstreams"][name]
    parent_type = {"socks5": "socks5", "http": "connect+", "https": "connect+s"}[upstream["type"]]
    username, password = upstream_credentials(upstream, name)
    fields: list[Any] = ["parent", 1000, parent_type, upstream["host"], upstream["port"]]
    if username is not None:
        fields.extend([username, password])
    return " ".join(str(field) for field in fields)


def render_3proxy(data: dict[str, Any]) -> str:
    access = data.get("access", {})
    mode = access.get("mode", "strong")
    local_auth = data.get("local_auth", {})
    user = local_auth.get("username")
    password = local_auth.get("password")
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
        *([f"users {user}:CL:{password}"] if mode == "strong" else []),
        "",
    ]
    https_upstream = data.get("upstreams", {}).get("https_primary")
    if https_upstream is not None:
        lines.extend([
            "# Verified TLS client settings for HTTPS parent",
            "ssl_client_mode 3",
            "ssl_client_verify",
            f"ssl_client_ca_file {client_ca_file(data)}",
            f"ssl_client_sni {https_upstream['tls_server_name']}",
            "ssl_client_min_proto_version TLSv1.2",
            "",
        ])
    for listener in sorted(data["listeners"], key=lambda item: item["port"]):
        lines.append(f"# {listener['id']}")
        secure_parent = listener["parent"] == "https_primary"
        if secure_parent:
            lines.append("ssl_cli")
        if mode == "strong":
            lines.extend(["auth strong", f"allow {user}"])
        else:
            lines.append("auth iponly")
            lines.extend(f"allow * {cidr}" for cidr in access["allowed_client_cidrs"])
            lines.append("deny *")
        if listener["parent"] != "direct":
            lines.append(parent_line(data, listener["parent"]))
        bind_ip = listener_ip(data, listener)
        if listener["protocol"] == "socks5":
            nat = f" -Ni{public_ip}" if "udp" in listener["capabilities"] else ""
            lines.append(f"socks -i{bind_ip} -p{listener['port']}{nat}")
        else:
            lines.append(f"proxy -i{bind_ip} -p{listener['port']}")
        if secure_parent:
            lines.append("ssl_nocli")
        lines.extend(["flush", ""])
    return "\n".join(lines)


def render_systemd() -> str:
    return """[Unit]
Description=3proxy - modular installation
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
    for name in ("validate", "get", "render-3proxy", "ports", "firewall-ports", "external-udp"):
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
        item.add_argument("--build-profile", required=True)
    manifest.add_argument("--binary-sha", required=True)
    args = parser.parse_args()

    if args.command in {"validate", "get", "render-3proxy", "ports", "firewall-ports", "external-udp"}:
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
    elif args.command == "firewall-ports":
        for item in sorted(data["listeners"], key=lambda value: value["port"]):
            if not ipaddress.ip_address(listener_ip(data, item)).is_loopback:
                print(item["port"])
    elif args.command == "external-udp":
        print(str(any(
            "udp" in item["capabilities"]
            and not ipaddress.ip_address(listener_ip(data, item)).is_loopback
            for item in data["listeners"]
        )).lower())
    elif args.command == "manifest-matches":
        try:
            current = json.loads(args.manifest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return 1
        return 0 if all(current.get(key) == value for key, value in {
            "version": args.version, "source_sha256": args.source_sha,
            "patchset_sha256": args.patch_sha, "build_profile": args.build_profile
        }.items()) else 1
    elif args.command == "write-manifest":
        payload = {
            "version": args.version,
            "source_sha256": args.source_sha,
            "patchset_sha256": args.patch_sha,
            "build_profile": args.build_profile,
            "binary_sha256": args.binary_sha,
        }
        write_text(args.output, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, KeyError, TypeError) as exc:
        raise SystemExit(f"configuration error: {exc}")
