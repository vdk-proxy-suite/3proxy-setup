"""Transport-family / TLS-identity / egress-family independent probes."""
from __future__ import annotations

import hashlib
import ipaddress
import json
from pathlib import Path
import socket
import struct
import time

import addressing as addr
import config as cfg
import schema_v2 as schema
import healthcheck as wire


def transport_addresses(data: dict, listener: dict, scope: str) -> tuple[addr.ResolvedAddress, ...]:
    if scope == "e2e":
        if all(ipaddress.ip_address(bind).is_loopback for bind in listener["bind"]):
            return ()
        ep = listener["endpoint"]
        return addr.resolve(ep["host"], listener["port"], ep["families"])
    addresses = set()
    for bind in listener["bind"]:
        if bind == "::":
            addresses.update([("ipv4", "127.0.0.1"), ("ipv6", "::1")])
        elif bind == "0.0.0.0":
            addresses.add(("ipv4", "127.0.0.1"))
        else:
            ip = addr.identity(bind)
            addresses.add((ip.family, ip.value))
    return tuple(addr.ResolvedAddress(*item) for item in sorted(addresses))


def tls_options(data: dict, listener: dict, scope: str, ca_override: Path | None) -> dict:
    if listener["protocol"] != "https":
        return {}
    name = schema.certificate_id(data, listener)
    cert = schema.certificates(data)[name]
    trust = str(ca_override) if ca_override else None
    if trust is None:
        if cert["mode"] == "managed":
            if scope != "vm":
                raise ValueError("managed TLS E2E requires --proxy-ca-file (CA bundle for selected certificates)")
            trust = str(schema.certificate_directory(data, cfg.paths(data["instance"]["id"])["CONFIG_DIR"], name) / "ca.crt")
        elif cert["mode"] == "acme" and cert["acme"].get("environment", "production") == "staging":
            if scope != "vm":
                raise ValueError("staging TLS E2E requires explicitly supplied --proxy-ca-file")
            trust = str(Path(__file__).with_name("acme-staging-roots.txt"))
        elif cert["mode"] == "external" and scope == "vm":
            trust = cert.get("ca_file")
    return dict(tls_server_name=schema.tls_identity(data, listener), ca_file=trust)


def socks_connect(sock: socket.socket, target: str, port: int) -> None:
    address = ipaddress.ip_address(target)
    sock.sendall(b"\x05\x01\x00" + (b"\x01" if address.version == 4 else b"\x04") + address.packed + struct.pack("!H", port))
    wire.read_socks_reply(sock)


def forwarding(protocol: str, proxy: str, port: int, user, password, target: str, target_port: int,
               host_header: str, timeout: float, *, connect: bool = False, tls: dict | None = None) -> str:
    authority = addr.authority(target, target_port)
    host = addr.authority(host_header, target_port)
    with wire.open_proxy_connection(proxy, port, timeout, **(tls or {})) as sock:
        if protocol == "socks5":
            wire.socks_auth(sock, user, password)
            socks_connect(sock, target, target_port)
        elif connect:
            sock.sendall((f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n" + wire.proxy_authorization(user, password) + "\r\n").encode())
            response = bytearray()
            while b"\r\n\r\n" not in response:
                byte = sock.recv(1)
                if not byte: raise ConnectionError("proxy closed CONNECT")
                response.extend(byte)
                if len(response) > 65536: raise ValueError("CONNECT headers too large")
            if b" 200 " not in response.split(b"\r\n", 1)[0]:
                raise ValueError("proxy rejected CONNECT")
        path = "/" if protocol == "socks5" or connect else f"http://{authority}/"
        auth = "" if protocol == "socks5" or connect else wire.proxy_authorization(user, password)
        sock.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\n{auth}Connection: close\r\n\r\n".encode())
        status, body = wire.read_http_response(sock)
        if " 200 " not in status:
            raise ValueError(f"unexpected target response: {status}")
        # Egress endpoints must return a plain-text IP, not an arbitrary page.
        return str(ipaddress.ip_address(body.decode("ascii").strip()))


def socks_auth_rejected(sock: socket.socket, *, wrong: bool,
                        probe_target: tuple[str, int] = ("127.0.0.1", 1)) -> str:
    sock.sendall(b"\x05\x01\x02" if wrong else b"\x05\x01\x00")
    reply = wire.recv_exact(sock, 2)
    if reply == b"\x05\xff":
        return "authentication rejected"
    expected_method = b"\x05\x02" if wrong else b"\x05\x00"
    if reply != expected_method:
        raise ValueError("SOCKS offered an unexpected authentication method")
    if wrong:
        sock.sendall(b"\x01\x07invalid\x07invalid")
        reply = wire.recv_exact(sock, 2)
        if reply[0] != 1:
            raise ValueError("invalid SOCKS authentication response")
        if reply[1] != 0:
            return "authentication rejected"
    # 3proxy acknowledges the handshake before calling authfunc on the request.
    # Only an explicit ruleset denial proves rejection; a timeout, connection
    # refusal, malformed reply or generic network failure must not count as PASS.
    target = ipaddress.ip_address(probe_target[0])
    sock.sendall(b"\x05\x01\x00" + (b"\x01" if target.version == 4 else b"\x04")
                 + target.packed + struct.pack("!H", probe_target[1]))
    version, status, reserved, atyp = wire.recv_exact(sock, 4)
    if version != 5 or reserved != 0:
        raise ValueError("invalid SOCKS CONNECT response")
    if status != 2:
        raise ValueError(f"SOCKS CONNECT was not denied by authentication/access rules (REP={status})")
    if atyp == 1:
        wire.recv_exact(sock, 4)
    elif atyp == 4:
        wire.recv_exact(sock, 16)
    elif atyp == 3:
        wire.recv_exact(sock, wire.recv_exact(sock, 1)[0])
    else:
        raise ValueError("invalid SOCKS CONNECT reply address type")
    wire.recv_exact(sock, 2)
    return "authentication rejected at CONNECT (REP=2)"


def auth_rejected(protocol: str, proxy: str, port: int, timeout: float, *, wrong: bool, tls: dict) -> str:
    with wire.open_proxy_connection(proxy, port, timeout, **tls) as sock:
        if protocol == "socks5":
            return socks_auth_rejected(sock, wrong=wrong)
        else:
            auth = wire.proxy_authorization("invalid-testuser", "invalid-testpassword") if wrong else ""
            sock.sendall(f"CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n{auth}\r\n".encode())
            response = sock.recv(4096).split(b"\r\n", 1)[0]
            if b" 407 " not in response: raise ValueError("HTTP proxy did not reject credentials with 407")
    return "authentication rejected"


def tls_probe(proxy: str, port: int, timeout: float, tls: dict) -> str:
    with wire.open_proxy_connection(proxy, port, timeout, **tls) as sock:
        return json.dumps(dict(fingerprint=hashlib.sha256(sock.getpeercert(binary_form=True)).hexdigest(),
                               tls_version=sock.version(), tls_identity=tls["tls_server_name"]))


def check(results: list, listener: dict, name: str, call, metadata: dict, expected: list[str] | None = None):
    def checked():
        result = call()
        if expected is not None and result not in {str(ipaddress.ip_address(ip)) for ip in expected}:
            raise ValueError(f"egress mismatch: got {result}, expected one of {expected}")
        return result
    wire.run_check(results, listener["id"], name, True, None, checked)
    results[-1].update(metadata)
    if expected is not None:
        results[-1]["expected"] = expected
        results[-1]["actual_egress"] = results[-1]["detail"]


def run(data: dict, args, parser) -> int:
    cfg.validate(data)
    available = {item["id"] for item in data["listeners"]}
    if not args.skip_upstreams:
        available.update("upstream_" + name for name in data.get("upstreams", {}))
    if args.endpoint is not None and args.endpoint not in available:
        parser.error("unknown or skipped endpoint")
    if args.proxy_ca_file and not args.proxy_ca_file.is_file():
        parser.error("proxy CA file does not exist")
    selected = [item for item in data["listeners"] if args.endpoint is None or item["id"] == args.endpoint]
    if args.tls_gate_only and not any(item["protocol"] == "https" for item in selected):
        parser.error("--tls-gate-only requires an HTTPS listener")
    results = []
    timeout = args.timeout or data["probes"]["timeout_seconds"]
    for listener in selected:
        if args.tls_gate_only and listener["protocol"] != "https": continue
        try:
            addresses = transport_addresses(data, listener, args.scope)
            options = tls_options(data, listener, args.scope, args.proxy_ca_file)
        except (ValueError, OSError) as exc:
            check(results, listener, "endpoint_resolution", lambda: (_ for _ in ()).throw(exc), {})
            continue
        if not addresses:
            wire.add_na(results, listener["id"], "endpoint", "loopback listener requires VM-side checks")
            continue
        user, password = wire.listener_credentials(data, listener)
        for address in addresses:
            ip, port = address.ip, listener["port"]
            meta = dict(address_family=address.family, resolved_ip=ip, certificate_id=listener.get("tls_certificate"),
                        tls_identity=options.get("tls_server_name"))
            if options:
                check(results, listener, "tls_handshake", lambda: tls_probe(ip, port, timeout, options), meta)
                check(results, listener, "plaintext_rejected", lambda: wire.plaintext_proxy_rejected(ip, port, timeout), meta)
            if args.tls_gate_only: continue
            if wire.effective_listener_access_mode(data, listener) == "strong":
                for wrong in (False, True):
                    check(results, listener, "wrong_auth_rejected" if wrong else "no_auth_rejected",
                          lambda: auth_rejected(listener["protocol"], ip, port, timeout, wrong=wrong, tls=options), meta)
            if listener["protocol"] == "socks5" and "udp" not in listener["capabilities"]:
                check(results, listener, "udp_rejected", lambda: wire.socks_udp_rejected(ip, port, user, password, timeout), meta)
            elif listener["protocol"] == "socks5":
                probes = data["probes"]
                check(results, listener, "udp_dns", lambda: wire.dns_probe(ip, port, user, password,
                      probes.get("dns_server", "1.1.1.1"), probes.get("dns_port", 53), timeout), meta)
                check(results, listener, "udp_stun", lambda: wire.stun_probe(ip, port, user, password,
                      probes.get("stun_servers", [{"host": "stun.l.google.com", "port": 19302}]), timeout), meta)
            for family, probe in data["probes"]["egress"][listener["parent"]].items():
                target_host = probe.get("http_host", data["probes"].get("http_host", "api.ipify.org"))
                target_port = probe.get("http_port", data["probes"].get("http_port", 80))
                detail = dict(meta, egress_family=family)
                try:
                    targets = addr.resolve(target_host, target_port, [family])
                except (OSError, ValueError) as exc:
                    check(results, listener, "target_resolution", lambda: (_ for _ in ()).throw(exc), detail)
                    continue
                for target in targets:
                    detail = dict(detail, target_ip=target.ip)
                    modes = [False] if listener["protocol"] == "socks5" else [False, True]
                    for connect in modes:
                        check(results, listener, "tcp" if listener["protocol"] == "socks5" else "http_connect" if connect else "http_get",
                              lambda: forwarding(listener["protocol"], ip, port, user, password, target.ip, target_port,
                                                 target_host, timeout, connect=connect, tls=options), detail, probe["expected_ips"])
                    if (listener["protocol"] == "socks5" and family == "ipv4"
                            and wire.effective_listener_access_mode(data, listener) == "iponly"):
                        check(results, listener, "socks4_tcp", lambda: wire.socks4_tcp(ip, port, target.ip, target_port, timeout, host_header=target_host),
                              detail, probe["expected_ips"])
    if not args.skip_upstreams and not args.tls_gate_only:
        upstream_checks(data, args, results, timeout)
    if args.scope == "vm" and not args.tls_gate_only and args.endpoint is None:
        if any(cert["mode"] == "acme" for cert in schema.certificates(data).values()):
            def lifecycle():
                import tls_v2
                state = tls_v2.status(cfg.paths(data["instance"]["id"]), data)
                if state["state"] != "ok":
                    raise ValueError("certificate lifecycle: " + json.dumps(state))
                return json.dumps(state)
            check(results, {"id": "acme"}, "certificate_lifecycle", lifecycle, {})
    return report(results, args)


def upstream_checks(data: dict, args, results: list, timeout: float) -> None:
    import upstream_resolution
    for name, upstream in data.get("upstreams", {}).items():
        endpoint = "upstream_" + name
        if args.endpoint is not None and args.endpoint != endpoint:
            continue
        listener = {"id": endpoint}
        if name not in data["probes"]["egress"]:
            wire.add_na(results, endpoint, "route", "unused upstream has no egress policy")
            continue
        try:
            ip = upstream_resolution.resolve_parent(upstream)
        except ValueError as exc:
            check(results, listener, "upstream_resolution", lambda: (_ for _ in ()).throw(exc), {})
            continue
        meta = dict(address_family=addr.identity(ip).family, resolved_ip=ip)
        options = {}
        if upstream["type"] == "https":
            options = dict(tls_server_name=upstream["tls_server_name"], ca_file=data.get("tls", {}).get("client_ca_file"))
            meta["tls_identity"] = upstream["tls_server_name"]
            check(results, listener, "tls_handshake", lambda: tls_probe(ip, upstream["port"], timeout, options), meta)
        for family, probe in data["probes"]["egress"][name].items():
            host = probe.get("http_host", data["probes"].get("http_host", "api.ipify.org"))
            port = probe.get("http_port", data["probes"].get("http_port", 80))
            detail = dict(meta, egress_family=family)
            try:
                targets = addr.resolve(host, port, [family])
            except ValueError as exc:
                check(results, listener, "target_resolution", lambda: (_ for _ in ()).throw(exc), detail)
                continue
            for target in targets:
                for connect in ([False] if upstream["type"] == "socks5" else [False, True]):
                    check(results, listener, "tcp" if upstream["type"] == "socks5" else "http_connect" if connect else "http_get",
                          lambda: forwarding(upstream["type"], ip, upstream["port"], upstream.get("username"), upstream.get("password"),
                                             target.ip, port, host, timeout, connect=connect, tls=options),
                          dict(detail, target_ip=target.ip), probe["expected_ips"])


def report(results: list, args) -> int:
    summary = dict(schema_version=2, scope=args.scope, generated_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   endpoints=len({item["endpoint"] for item in results}),
                   passed=sum(item["status"] == "PASS" for item in results), failed=sum(item["status"] == "FAIL" for item in results),
                   not_applicable=sum(item["status"] == "N/A" for item in results), results=results)
    for item in results:
        print(f"{item['status']:<4} {item['endpoint']} {item.get('address_family', '')} {item['check']} {item.get('detail') or item.get('error') or ''}")
    print(f"SUMMARY endpoints={summary['endpoints']} passed={summary['passed']} failed={summary['failed']} n/a={summary['not_applicable']}")
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return 1 if summary["failed"] else 0
