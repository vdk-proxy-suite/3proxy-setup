#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import posixpath
import re
from pathlib import Path
from typing import Any

import yaml

from instance import identity, paths


SUPPORTED_UPSTREAMS = {
    "socks_primary": "socks5",
    "http_primary": "http",
    "https_primary": "https",
}

SUPPORTED_LISTENER_PROTOCOLS = {"socks5", "http", "https"}
LISTENER_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
DEFAULT_CLIENT_CA_FILE = "/etc/ssl/certs/ca-certificates.crt"
MANAGED_TLS_DIR = "/etc/3proxy/tls"
MANAGED_TLS_CA_FILE = f"{MANAGED_TLS_DIR}/ca.crt"
MANAGED_TLS_SERVER_CERT_FILE = f"{MANAGED_TLS_DIR}/server.crt"
MANAGED_TLS_SERVER_KEY_FILE = f"{MANAGED_TLS_DIR}/server.key"
BUILD_PROFILE = "cmake-openssl"
INSTALL_VERSION = "1.0.0"
INSTALL_SOURCE_URL = "https://github.com/3proxy/3proxy/archive/refs/tags/1.0.0.tar.gz"
INSTALL_SHA256 = "35b07de1046f3aaeac4a7085101b7e5c453efa3527cbdc42a84690366c7ecfa8"


def load_config(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as stream:
        data = yaml.safe_load(stream)
    if not isinstance(data, dict):
        raise ValueError("YAML root must be a mapping")
    tls = data.get("tls")
    if isinstance(tls, dict) and isinstance(tls.get("client_ca_file"), str):
        supplied = Path(tls["client_ca_file"])
        if not supplied.is_absolute() and not tls["client_ca_file"].startswith("/") :
            tls["client_ca_file"] = (path.resolve().parent / supplied).resolve().as_posix()
    server = tls.get("server") if isinstance(tls, dict) else None
    if isinstance(server, dict):
        for key in ("fullchain_file", "private_key_file", "ca_file"):
            value = server.get(key)
            if isinstance(value, str) and value and not value.startswith("/") and not Path(value).is_absolute():
                server[key] = Path(os.path.abspath(path.parent / value)).as_posix()
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


def tls_server_config(data: dict[str, Any]) -> dict[str, Any] | None:
    tls = data.get("tls", {})
    server = tls.get("server") if isinstance(tls, dict) else None
    return server if isinstance(server, dict) else None



def tls_server_mode(data: dict[str, Any]) -> str:
    return (tls_server_config(data) or {}).get("mode", "managed")


def server_ca_file(data: dict[str, Any]) -> str:
    if tls_server_mode(data) == "external":
        return data["tls"]["server"].get("ca_file", DEFAULT_CLIENT_CA_FILE)
    return f"{paths(data.get('instance', {}).get('id'))['CONFIG_DIR']}/tls/ca.crt"


def validate_tls_server(server: dict[str, Any]) -> None:
    mode = server.get("mode", "managed")
    if mode == "acme_ip":
        from acme_config import validate as validate_acme
        validate_acme(server)
        return
    if not isinstance(mode, str) or mode not in {"managed", "external"}:
        raise ValueError("tls.server.mode must be managed, external or acme_ip")
    if mode == "external":
        unknown = set(server) - {"mode", "fullchain_file", "private_key_file", "ca_file"}
        if unknown:
            raise ValueError(f"unsupported external tls.server settings: {sorted(unknown)}")
        for key in ("fullchain_file", "private_key_file", "ca_file"):
            value = server.get(key, DEFAULT_CLIENT_CA_FILE if key == "ca_file" else None)
            safe_token(value, f"tls.server.{key}", colon=False)
            if not (value.startswith("/") or Path(value).is_absolute()) or value == "/" or posixpath.normpath(value) != value or "//" in value:
                raise ValueError(f"tls.server.{key} must be an absolute normalized path")
        return
    validate_managed_tls_server(server)



def validate_managed_tls_server(tls_server: dict[str, Any]) -> None:
    unknown_server_tls = set(tls_server) - {
        "mode", "dns_names", "validity_days", "ca_validity_days", "regenerate_on_setup"
    }
    if unknown_server_tls:
        raise ValueError(f"unsupported tls.server settings: {sorted(unknown_server_tls)}")
    dns_names = tls_server.get("dns_names")
    if not isinstance(dns_names, list) or any(not isinstance(name, str) for name in dns_names):
        raise ValueError("tls.server.dns_names must be a list of DNS hostnames")
    normalized_dns_names: set[str] = set()
    for index, value in enumerate(dns_names):
        name = dns_hostname(value, f"tls.server.dns_names[{index}]")
        normalized = name.lower()
        if normalized in normalized_dns_names:
            raise ValueError("tls.server.dns_names must not contain duplicates")
        normalized_dns_names.add(normalized)
    validity_days = tls_server.get("validity_days")
    if (
        isinstance(validity_days, bool)
        or not isinstance(validity_days, int)
        or not 2 <= validity_days <= 825
    ):
        raise ValueError("tls.server.validity_days must be between 2 and 825")
    ca_validity_days = tls_server.get("ca_validity_days")
    if (
        isinstance(ca_validity_days, bool)
        or not isinstance(ca_validity_days, int)
        or not 2 <= ca_validity_days <= 3650
    ):
        raise ValueError("tls.server.ca_validity_days must be between 2 and 3650")
    if ca_validity_days <= validity_days:
        raise ValueError("tls.server.ca_validity_days must exceed validity_days")
    if not isinstance(tls_server.get("regenerate_on_setup"), bool):
        raise ValueError("tls.server.regenerate_on_setup must be boolean")

def has_https_parent(data: dict[str, Any]) -> bool:
    return any(
        isinstance(upstream, dict) and upstream.get("type") == "https"
        for upstream in data.get("upstreams", {}).values()
    )


def has_https_listener(data: dict[str, Any]) -> bool:
    return any(
        isinstance(listener, dict) and listener.get("protocol") == "https"
        for listener in data.get("listeners", [])
    )


def listener_ip(data: dict[str, Any], listener: dict[str, Any]) -> str:
    return str(listener.get("listen_ip", data["server"]["listen_ip"]))


def effective_listener_access(data: dict[str, Any], listener: dict[str, Any]) -> dict[str, Any]:
    if "access" in listener:
        return dict(listener["access"])
    return dict(data.get("access", {}))


def validate_access(access: Any, name: str) -> str:
    if not isinstance(access, dict):
        raise ValueError(f"{name} must be a mapping")
    mode = access.get("mode", "strong")
    if mode not in {"strong", "iponly"}:
        raise ValueError(f"{name}.mode must be strong or iponly")
    allowed_client_cidrs = access.get("allowed_client_cidrs", [])
    if not isinstance(allowed_client_cidrs, list):
        raise ValueError(f"{name}.allowed_client_cidrs must be a list")
    if mode == "iponly" and not allowed_client_cidrs:
        raise ValueError(f"iponly access requires at least one allowed client CIDR ({name})")
    for index, value in enumerate(allowed_client_cidrs):
        network = ipaddress.ip_network(str(value), strict=False)
        if network.version != 4:
            raise ValueError(f"{name}.allowed_client_cidrs[{index}] must be IPv4")
        if network.prefixlen == 0:
            raise ValueError(f"iponly access must not allow an open /0 network ({name})")
    return mode


def capability_set(value: Any, name: str, *, allow_udp: bool) -> set[str]:
    if not isinstance(value, list) or not value or any(not isinstance(item, str) for item in value):
        raise ValueError(f"{name} must be a non-empty list")
    result = set(value)
    if len(result) != len(value):
        raise ValueError(f"{name} must not contain duplicates")
    valid = {"tcp", "udp"} if allow_udp else {"tcp"}
    if "tcp" not in result or not result <= valid:
        requirement = "TCP with optional UDP" if allow_udp else "TCP only"
        raise ValueError(f"{name} must support {requirement}")
    return result


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
    if "instance" in data:
        identity(data)
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
    unknown_tls = set(tls) - {"client_ca_file", "server"}
    if unknown_tls:
        raise ValueError(f"unsupported tls settings: {sorted(unknown_tls)}")
    if "client_ca_file" in tls:
        ca_file = client_ca_file(data)
        safe_token(ca_file, "tls.client_ca_file", colon=False)
        if (
            not (ca_file.startswith("/") or Path(ca_file).is_absolute())
            or ca_file == "/"
            or "//" in ca_file
            or posixpath.normpath(ca_file) != ca_file
        ):
            raise ValueError("tls.client_ca_file must be an absolute normalized POSIX path")

    tls_server = tls.get("server")
    if tls_server is not None:
        if not isinstance(tls_server, dict):
            raise ValueError("tls.server must be a mapping")
        validate_tls_server(tls_server)
        if tls_server.get("mode") == "acme_ip" and "instance" not in data:
            raise ValueError("ACME requires a named instance.id")

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
    validate_access(access, "access")

    upstreams = data.get("upstreams", {})
    if not isinstance(upstreams, dict):
        raise ValueError("upstreams must be a mapping")
    unknown_upstreams = set(upstreams) - set(SUPPORTED_UPSTREAMS)
    if unknown_upstreams:
        raise ValueError(f"unsupported upstreams: {sorted(unknown_upstreams)}")
    for name, upstream in upstreams.items():
        if not isinstance(upstream, dict):
            raise ValueError(f"upstreams.{name} must be a mapping")
        expected_type = SUPPORTED_UPSTREAMS[name]
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
        capability_set(
            upstream.get("capabilities", []),
            f"upstreams.{name}.capabilities",
            allow_udp=expected_type == "socks5",
        )
    if "client_ca_file" in tls and not has_https_parent(data):
        raise ValueError("tls.client_ca_file is only valid when an HTTPS upstream is configured")

    listeners = data.get("listeners")
    if not isinstance(listeners, list) or not listeners:
        raise ValueError("listeners must contain at least one entry")
    by_id: dict[str, dict[str, Any]] = {}
    ports: set[int] = set()
    for item in listeners:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            raise ValueError("each listener must be a mapping with id")
        listener_id = item["id"]
        if not LISTENER_ID_PATTERN.fullmatch(listener_id):
            raise ValueError(
                "listener id must be 1-64 ASCII letters, digits, dots, underscores or hyphens "
                "and start with a letter or digit"
            )
        if listener_id in by_id:
            raise ValueError(f"duplicate listener id: {listener_id}")
        by_id[listener_id] = item
        port = item.get("port")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535 or port in ports:
            raise ValueError(f"invalid or duplicate listener port: {port}")
        ports.add(port)
        ipaddress.ip_address(listener_ip(data, item))
    for listener_id, item in by_id.items():
        if "access" in item:
            access_override = item["access"]
            if not isinstance(access_override, dict):
                raise ValueError(f"listener {listener_id}.access must be a mapping")
            unknown_access = set(access_override) - {"mode", "allowed_client_cidrs"}
            if unknown_access:
                raise ValueError(
                    f"unsupported listener {listener_id}.access settings: {sorted(unknown_access)}"
                )
            if "mode" not in access_override:
                raise ValueError(f"listener {listener_id}.access.mode is required")
        validate_access(
            effective_listener_access(data, item),
            f"listener {listener_id}.access",
        )
        protocol = item.get("protocol")
        if protocol not in SUPPORTED_LISTENER_PROTOCOLS:
            raise ValueError(f"listener {listener_id} protocol must be socks5, http or https")
        parent = item.get("parent")
        if not isinstance(parent, str) or (parent != "direct" and parent not in upstreams):
            raise ValueError(f"listener {listener_id} references undefined upstream {parent}")
        listener_capabilities = capability_set(
            item.get("capabilities", []),
            f"listener {listener_id} capabilities",
            allow_udp=protocol == "socks5",
        )
        if parent != "direct":
            parent_capabilities = set(upstreams[parent]["capabilities"])
            if not listener_capabilities <= parent_capabilities:
                raise ValueError(f"listener {listener_id} capabilities exceed upstream {parent}")

    local = data.get("local_auth")
    strong_listener_present = any(
        effective_listener_access(data, item).get("mode", "strong") == "strong"
        for item in listeners
    )
    if strong_listener_present:
        if not isinstance(local, dict):
            raise ValueError("local_auth must be a mapping when any listener uses strong mode")
        safe_token(local.get("username"), "local_auth.username")
        safe_token(local.get("password"), "local_auth.password")
    elif local is not None and not isinstance(local, dict):
        raise ValueError("local_auth must be a mapping when provided")
    if has_https_listener(data) and tls_server_config(data) is None:
        raise ValueError("tls.server is required when an HTTPS listener is configured")
    if tls_server_config(data) is not None and not has_https_listener(data):
        raise ValueError("tls.server is only valid when an HTTPS listener is configured")

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
    instance_paths = paths(identity(data, legacy="instance" not in data))
    local_auth = data.get("local_auth", {})
    user = local_auth.get("username")
    password = local_auth.get("password")
    strong_listener_present = any(
        effective_listener_access(data, listener).get("mode", "strong") == "strong"
        for listener in data["listeners"]
    )
    public_ip = data["server"]["public_ip"]
    logging = data.get("logging", {})
    keep_files = logging.get("keep_files", 14)
    lines = [
        "# Generated by 3proxy-setup; do not edit manually",
        "nserver 8.8.8.8",
        "nserver 8.8.4.4",
        "nscache 65536",
        f"log {instance_paths['LOG_DIR']}/3proxy.log D",
        f"rotate {keep_files}",
        *(["archiver gz /usr/bin/gzip %F"] if logging.get("compress", True) else []),
        'logformat "-|+_Gv1|%t|%.|%D|%N|%p|%E|%U|%C|%c|%R|%r|%Q|%q|%n|%O|%I|%h|%T"',
        "timeouts 1 5 30 60 180 1800 15 60 15 5",
        "maxconn 1000",
        *([f"users {user}:CL:{password}"] if strong_listener_present else []),
        "",
    ]
    if has_https_listener(data):
        lines.extend([
            "# Managed TLS server settings for HTTPS listeners",
            f"ssl_server_cert {instance_paths['CONFIG_DIR']}/tls/server.crt",
            f"ssl_server_key {instance_paths['CONFIG_DIR']}/tls/server.key",
            "ssl_server_min_proto_version TLSv1.2",
            "ssl_server_no_verify",
            "",
        ])
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
        access = effective_listener_access(data, listener)
        mode = access.get("mode", "strong")
        secure_listener = listener["protocol"] == "https"
        secure_parent = (
            listener["parent"] != "direct"
            and data["upstreams"][listener["parent"]]["type"] == "https"
        )
        route = (
            parent_line(data, listener["parent"])
            if listener["parent"] != "direct"
            else None
        )
        if secure_listener:
            lines.append("ssl_serv")
        if secure_parent:
            lines.append("ssl_cli")
        if mode == "strong":
            lines.append("auth strong")
            if listener["protocol"] == "socks5" and "udp" not in listener["capabilities"]:
                lines.append("deny * * * * UDPASSOC")
            lines.append(f"allow {user}")
            if route is not None:
                lines.append(route)
        else:
            lines.append("auth iponly")
            if listener["protocol"] == "socks5" and "udp" not in listener["capabilities"]:
                lines.append("deny * * * * UDPASSOC")
            for cidr in access["allowed_client_cidrs"]:
                lines.append(f"allow * {cidr}")
                if route is not None:
                    lines.append(route)
            lines.append("deny *")
        bind_ip = listener_ip(data, listener)
        if listener["protocol"] == "socks5":
            nat = f" -Ni{public_ip}" if "udp" in listener["capabilities"] else ""
            lines.append(f"socks -i{bind_ip} -p{listener['port']}{nat}")
        else:
            lines.append(f"proxy -i{bind_ip} -p{listener['port']}")
        if secure_listener:
            lines.append("ssl_noserv")
        if secure_parent:
            lines.append("ssl_nocli")
        lines.extend(["flush", ""])
    return "\n".join(lines)


def render_openssl(data: dict[str, Any]) -> str:
    validate(data)
    server_tls = tls_server_config(data)
    if server_tls is None:
        raise ValueError("tls.server is required to render the managed leaf certificate")
    alt_names = [f"IP.1 = {data['server']['public_ip']}"]
    alt_names.extend(
        f"DNS.{index} = {name}"
        for index, name in enumerate(server_tls["dns_names"], 1)
    )
    return "\n".join([
        "[req]",
        "distinguished_name = req_distinguished_name",
        "req_extensions = v3_req",
        "prompt = no",
        "[req_distinguished_name]",
        "CN = 3proxy-managed-leaf",
        "[v3_req]",
        "basicConstraints = critical,CA:FALSE",
        "keyUsage = critical,digitalSignature,keyEncipherment",
        "extendedKeyUsage = serverAuth",
        "subjectAltName = @alt_names",
        "[alt_names]",
        *alt_names,
        "",
    ])


def render_systemd(data: dict | None = None) -> str:
    p = paths(identity(data, legacy="instance" not in data)) if data else paths(None)
    service_settings = ""
    if p["INSTANCE_ID"]:
        service_settings = f"User={p['SERVICE_USER']}\nGroup={p['SERVICE_GROUP']}\nAmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\nRuntimeDirectory={p['SERVICE']}\nRuntimeDirectoryMode=0750\n"
    return f"""[Unit]
Description=3proxy - modular installation
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
{service_settings}ExecStart={p["BINARY"]} {p["CONFIG_DIR"]}/3proxy.cfg
WorkingDirectory={p["DATA_DIR"]}
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
    config_commands = {
        "validate", "get", "render-3proxy", "render-openssl", "ports", "firewall-ports",
        "tls-server-mode", "external-udp", "has-https-listener", "https-listeners", "tls-dns-names",
    }
    for name in sorted(config_commands):
        item = sub.add_parser(name)
        item.add_argument("--config", type=Path, required=True)
        if name == "get":
            item.add_argument("--path", required=True)
        if name in {"render-3proxy", "render-openssl"}:
            item.add_argument("--output", type=Path, required=True)
    systemd = sub.add_parser("render-systemd")
    systemd.add_argument("--output", type=Path, required=True)
    systemd.add_argument("--config", type=Path)
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

    if args.command in config_commands:
        data = load_config(args.config)
        validate(data)
    if args.command == "validate":
        print("configuration valid")
    elif args.command == "get":
        value = scalar(data, args.path)
        print(str(value).lower() if isinstance(value, bool) else value)
    elif args.command == "render-3proxy":
        write_text(args.output, render_3proxy(data))
    elif args.command == "render-openssl":
        write_text(args.output, render_openssl(data))
    elif args.command == "render-systemd":
        write_text(args.output, render_systemd(load_config(args.config) if args.config else None))
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
    elif args.command == "has-https-listener":
        print(str(has_https_listener(data)).lower())
    elif args.command == "https-listeners":
        for item in sorted(data["listeners"], key=lambda value: value["port"]):
            if item["protocol"] == "https":
                print(item["id"])
    elif args.command == "tls-server-mode":
        print(tls_server_mode(data))
    elif args.command == "tls-dns-names":
        server_tls = tls_server_config(data)
        if server_tls is not None:
            for name in server_tls.get("dns_names", []):
                print(name)
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
