"""Version 2 configuration helpers. User YAML stays declarative and unexpanded."""
from __future__ import annotations

import copy
import ipaddress
import re
from pathlib import Path

import addressing as addr


CERT_ID = re.compile(r"[a-z][a-z0-9-]{0,31}")


def enabled(data: dict) -> bool:
    return data.get("schema_version") == 2


def mapping(value: object, name: str, allowed: set[str]) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be a mapping")
    unknown = set(value) - allowed
    if unknown:
        raise ValueError(f"unsupported {name} settings: {sorted(unknown)}")
    return value


def certificates(data: dict) -> dict[str, dict]:
    if enabled(data):
        return data.get("tls", {}).get("certificates", {})
    server = data.get("tls", {}).get("server")
    return {"default": server} if server is not None else {}


def certificate_id(data: dict, listener: dict) -> str:
    return listener["tls_certificate"] if enabled(data) else "default"


def certificate_directory(data: dict, config_dir: str, name: str) -> Path:
    if not CERT_ID.fullmatch(name):
        raise ValueError("invalid certificate id")
    root = Path(config_dir) / "tls"
    return root / name if enabled(data) else root


def certificate_identities(data: dict, name: str) -> tuple[addr.Identity, ...]:
    cert = certificates(data)[name]
    if enabled(data) or "identifiers" in cert:
        return addr.identities(cert["identifiers"])
    values = [data["server"]["public_ip"], *cert.get("dns_names", [])]
    return addr.identities(values)


def expanded_listeners(data: dict) -> list[dict]:
    if not enabled(data):
        return data["listeners"]
    result = []
    for listener in data["listeners"]:
        for bind in listener["bind"]:
            result.append(dict(listener, listen_ip=addr.literal(bind)))
    return result


def endpoint(data: dict, listener: dict) -> dict:
    if enabled(data):
        return listener["endpoint"]
    host = data["server"]["public_ip"]
    return dict(host=host, families=[addr.identity(host).family])


def tls_identity(data: dict, listener: dict) -> str:
    host = endpoint(data, listener)["host"]
    return addr.identity(host).value


def validate(data: dict) -> None:
    import config as cfg
    import acme_config

    mapping(data, "root", {"schema_version", "instance", "install", "server", "logging", "access",
                           "local_auth", "upstreams", "listeners", "tls", "probes"})
    if type(data.get("schema_version")) is not int or data["schema_version"] != 2:
        raise ValueError("schema_version must be 2")
    cfg.identity(data)
    server = mapping(data.get("server"), "server", {"manage_ufw", "udp_client_cidr", "udp_public_ip"})
    if not isinstance(server.get("manage_ufw"), bool):
        raise ValueError("server.manage_ufw must be boolean")
    tls = mapping(data.get("tls", {}), "tls", {"client_ca_file", "certificates", "deploy"})
    deploy = mapping(tls.get("deploy", {}), "tls.deploy", {"time", "timezone"})
    if deploy.get("time", "05:00") != "05:00" or deploy.get("timezone", "Europe/Moscow") != "Europe/Moscow":
        raise ValueError("TLS deploy is fixed at 05:00 Europe/Moscow")
    certs = certificates(data)
    if not isinstance(certs, dict):
        raise ValueError("tls.certificates must be a mapping")
    for name, cert in certs.items():
        if not isinstance(name, str) or not CERT_ID.fullmatch(name):
            raise ValueError("certificate id must match [a-z][a-z0-9-]{0,31}")
        if not isinstance(cert, dict):
            raise ValueError("certificate must be a mapping")
        wanted = addr.identities(cert.get("identifiers"))
        mode = cert.get("mode")
        if mode == "acme":
            acme_config.validate(cert)
            if "deploy" in cert["acme"]:
                raise ValueError("schema 2 uses instance-wide tls.deploy, not certificate acme.deploy")
        elif mode in {"external", "managed"}:
            allowed = ({"mode", "identifiers", "fullchain_file", "private_key_file", "ca_file"}
                       if mode == "external" else {"mode", "identifiers", "validity_days", "ca_validity_days", "regenerate_on_setup"})
            mapping(cert, "certificate", allowed)
            projected = copy.deepcopy(cert)
            projected.pop("identifiers")
            if mode == "managed":
                projected["dns_names"] = [i.value for i in wanted if i.kind == "dns"]
            cfg.validate_tls_server(projected)
        else:
            raise ValueError("schema 2 certificate mode must be acme, external or managed")

    listeners = data.get("listeners")
    if not isinstance(listeners, list) or not listeners:
        raise ValueError("listeners must be a nonempty list")
    names, occupied, used_certs = set(), [], set()
    for listener in listeners:
        mapping(listener, "listener", {"id", "protocol", "port", "bind", "accept_families", "endpoint",
                                       "tls_certificate", "parent", "outbound", "capabilities", "access"})
        name = listener.get("id")
        if not isinstance(name, str) or not cfg.LISTENER_ID_PATTERN.fullmatch(name) or name in names:
            raise ValueError("invalid or duplicate listener id")
        names.add(name)
        port = listener.get("port")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("invalid listener port")
        binds = listener.get("bind")
        if not isinstance(binds, list) or not binds:
            raise ValueError("listener.bind must be a nonempty list of literal IPs")
        accepted = addr.families(listener.get("accept_families"))
        available = set()
        for bind in binds:
            ip = addr.literal(bind)
            family = addr.identity(ip).family
            available.add(family)
            if ip == "::":
                available.add("ipv4")
            if any(port == other_port and addr.overlaps(ip, other_ip) for other_port, other_ip in occupied):
                raise ValueError(f"overlapping listener address/port: {addr.authority(ip, port)}")
            occupied.append((port, ip))
        if set(accepted) != available:
            raise ValueError("accept_families must exactly describe bind sockets; :: requires ipv4 and ipv6")
        ep = mapping(listener.get("endpoint"), "listener.endpoint", {"host", "families"})
        public = addr.identity(ep.get("host"))
        required = addr.families(ep.get("families"))
        if not set(required) <= set(accepted) or (public.kind == "ip" and required != (public.family,)):
            raise ValueError("endpoint families do not match host/bind")
        if listener.get("protocol") == "https":
            reference = listener.get("tls_certificate")
            if not isinstance(reference, str) or reference not in certs:
                raise ValueError("HTTPS listener requires a known tls_certificate")
            if public not in certificate_identities(data, reference):
                raise ValueError("endpoint host must be present in certificate identifiers")
            used_certs.add(reference)
        elif "tls_certificate" in listener:
            raise ValueError("tls_certificate is only valid on HTTPS listeners")
        outbound = mapping(listener.get("outbound", {}), "listener.outbound", {"family"})
        if outbound.get("family", "ipv4") not in addr.OUTBOUND_FLAGS:
            raise ValueError("invalid outbound.family")
        if "udp" in listener.get("capabilities", []):
            if accepted != ("ipv4",) or outbound.get("family", "ipv4") != "ipv4":
                raise ValueError("IPv6 UDP is not supported; use TCP-only or legacy IPv4 UDP")
            relay = addr.identity(server.get("udp_public_ip"))
            if relay.family != "ipv4":
                raise ValueError("IPv4 UDP requires server.udp_public_ip")
            client_cidr = server.get("udp_client_cidr")
            if not isinstance(client_cidr, str):
                raise ValueError("IPv4 UDP requires server.udp_client_cidr")
            if ipaddress.ip_network(client_cidr, strict=False).version != 4:
                raise ValueError("IPv4 UDP requires an IPv4 udp_client_cidr")
    if set(certs) != used_certs:
        raise ValueError("each configured certificate must be used by an HTTPS listener")
    upstreams = data.get("upstreams", {})
    if not isinstance(upstreams, dict):
        raise ValueError("upstreams must be a mapping")
    for name, upstream in upstreams.items():
        mapping(upstream, "upstream", {"type", "host", "port", "username", "password", "capabilities", "tls_server_name", "resolve_family"})
        host = addr.identity(upstream.get("host"))
        preference = upstream.get("resolve_family", host.family or "prefer_ipv4")
        if preference not in addr.OUTBOUND_FLAGS:
            raise ValueError("invalid upstream.resolve_family")
        if host.kind == "ip" and preference in addr.FAMILIES and preference != host.family:
            raise ValueError("upstream resolve_family conflicts with literal host")
    validate_egress(data)
    # Reuse proven credential, protocol, pin and route validation without making
    # synthetic compatibility values part of the user's configuration/state.
    legacy = compatibility_view(data)
    cfg.validate_legacy(legacy, ipv6_access=True)


def validate_egress(data: dict) -> None:
    probes = mapping(data.get("probes"), "probes", {"timeout_seconds", "http_host", "http_port", "dns_server",
                                                     "dns_port", "stun_servers", "egress"})
    egress = probes.get("egress")
    if not isinstance(egress, dict):
        raise ValueError("probes.egress must describe each listener route")
    routes = {item["parent"] for item in data["listeners"]}
    if set(egress) != routes:
        raise ValueError("probes.egress must exactly describe the used listener routes")
    for route, policy in egress.items():
        mapping(policy, f"probes.egress.{route}", {"ipv4", "ipv6"})
        if not policy:
            raise ValueError("egress policy must contain at least one family")
        for family, probe in policy.items():
            mapping(probe, "egress probe", {"expected_ips", "http_host", "http_port"})
            expected = probe.get("expected_ips")
            if not isinstance(expected, list) or not expected or any(addr.identity(ip).family != family for ip in expected):
                raise ValueError("expected_ips must contain literal addresses of the probe family")
            target = addr.identity(probe.get("http_host", probes.get("http_host")))
            if target.kind == "ip" and target.family != family:
                raise ValueError("probe target literal has the wrong family")
            addr.authority(target.value, probe.get("http_port", probes.get("http_port", 80)))
    for item in data["listeners"]:
        family = item.get("outbound", {}).get("family", "ipv4")
        required = {family} if family in addr.FAMILIES else set(addr.FAMILIES)
        if not required <= set(egress[item["parent"]]):
            raise ValueError("egress probes must cover every configured outbound family")


def compatibility_view(data: dict) -> dict:
    """Validation-only view; never serialize or use for runtime addressing."""
    result = copy.deepcopy(data)
    result.pop("schema_version", None)
    result["server"].update(public_ip="127.0.0.1", listen_ip="127.0.0.1", udp_client_cidr="127.0.0.1/32")
    result["listeners"] = copy.deepcopy(data["listeners"])
    for index, listener in enumerate(result["listeners"]):
        # Actual endpoint overlaps are checked above, before this view is used.
        listener["port"] = index + 1
        listener["listen_ip"] = listener["bind"][0]
    for name, upstream in result.get("upstreams", {}).items():
        upstream.pop("resolve_family", None)
        upstream.setdefault("expected_egress_ip", "127.0.0.1")
    tls = result.get("tls", {})
    tls.pop("certificates", None)
    tls.pop("deploy", None)
    if certificates(data):
        cert = copy.deepcopy(next(iter(certificates(data).values())))
        if cert["mode"] != "acme":
            wanted = addr.identities(cert.pop("identifiers"))
            if cert["mode"] == "managed":
                cert["dns_names"] = [i.value for i in wanted if i.kind == "dns"]
        tls["server"] = cert
    probes = result["probes"]
    probes.setdefault("http_host", "api.ipify.org")
    probes.setdefault("http_port", 80)
    probes.setdefault("dns_server", "1.1.1.1")
    probes.setdefault("dns_port", 53)
    probes.setdefault("stun_servers", [{"host": "stun.l.google.com", "port": 19302}])
    return result
