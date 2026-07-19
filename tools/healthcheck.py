#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import socket
import struct
import sys
import time
from pathlib import Path
from typing import Any, Callable

import yaml


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("unexpected EOF")
        data.extend(chunk)
    return bytes(data)


def socks_auth(sock: socket.socket, user: str, password: str) -> None:
    sock.sendall(b"\x05\x01\x02")
    if recv_exact(sock, 2) != b"\x05\x02":
        raise RuntimeError("SOCKS5 username/password authentication was not selected")
    user_b, password_b = user.encode(), password.encode()
    if len(user_b) > 255 or len(password_b) > 255:
        raise RuntimeError("SOCKS5 credentials are too long")
    sock.sendall(b"\x01" + bytes([len(user_b)]) + user_b + bytes([len(password_b)]) + password_b)
    if recv_exact(sock, 2) != b"\x01\x00":
        raise RuntimeError("SOCKS5 authentication failed")


def read_socks_reply(sock: socket.socket) -> tuple[str, int]:
    version, status, _reserved, atyp = recv_exact(sock, 4)
    if version != 5 or status != 0:
        raise RuntimeError(f"SOCKS5 request failed, status={status}")
    if atyp == 1:
        host = socket.inet_ntoa(recv_exact(sock, 4))
    elif atyp == 3:
        host = recv_exact(sock, recv_exact(sock, 1)[0]).decode()
    elif atyp == 4:
        host = socket.inet_ntop(socket.AF_INET6, recv_exact(sock, 16))
    else:
        raise RuntimeError(f"unknown SOCKS5 address type {atyp}")
    return host, struct.unpack("!H", recv_exact(sock, 2))[0]


def read_http_response(sock: socket.socket) -> tuple[str, bytes]:
    response = bytearray()
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        response.extend(chunk)
    status = bytes(response).split(b"\r\n", 1)[0].decode(errors="replace")
    body = bytes(response).split(b"\r\n\r\n", 1)[-1].strip()
    return status, body


def socks_tcp(proxy: str, port: int, user: str, password: str, target: str, target_port: int, timeout: float) -> str:
    with socket.create_connection((proxy, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        socks_auth(sock, user, password)
        host = target.encode()
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + struct.pack("!H", target_port))
        read_socks_reply(sock)
        sock.sendall(f"GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n".encode())
        status, body = read_http_response(sock)
    if " 200 " not in status:
        raise RuntimeError(f"target HTTP response: {status}")
    return body.decode(errors="replace")


def http_get(proxy: str, port: int, user: str, password: str, target: str, target_port: int, timeout: float) -> str:
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    request = (
        f"GET http://{target}:{target_port}/ HTTP/1.1\r\n"
        f"Host: {target}\r\nProxy-Authorization: Basic {token}\r\nConnection: close\r\n\r\n"
    ).encode()
    with socket.create_connection((proxy, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(request)
        status, body = read_http_response(sock)
    if " 200 " not in status:
        raise RuntimeError(f"HTTP proxy response: {status}")
    return body.decode(errors="replace")


def http_connect(proxy: str, port: int, user: str, password: str, target: str, target_port: int, timeout: float) -> str:
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    request = (
        f"CONNECT {target}:{target_port} HTTP/1.1\r\nHost: {target}:{target_port}\r\n"
        f"Proxy-Authorization: Basic {token}\r\n\r\n"
    ).encode()
    with socket.create_connection((proxy, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(request)
        header = bytearray()
        while b"\r\n\r\n" not in header:
            header.extend(sock.recv(4096))
        status = bytes(header).split(b"\r\n", 1)[0].decode(errors="replace")
        if " 200 " not in status:
            raise RuntimeError(f"CONNECT response: {status}")
        sock.sendall(f"GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n".encode())
        target_status, body = read_http_response(sock)
    if " 200 " not in target_status:
        raise RuntimeError(f"target response through CONNECT: {target_status}")
    return body.decode(errors="replace")


def encode_socks_udp_target(host: str, port: int) -> bytes:
    ipv4 = socket.gethostbyname(host)
    return b"\x00\x00\x00\x01" + socket.inet_aton(ipv4) + struct.pack("!H", port)


def decode_socks_udp(packet: bytes) -> tuple[bytes, str, int]:
    if len(packet) < 10 or packet[:3] != b"\x00\x00\x00":
        raise RuntimeError("invalid SOCKS5 UDP response")
    atyp = packet[3]
    if atyp == 1:
        host = socket.inet_ntoa(packet[4:8])
        offset = 8
    elif atyp == 3:
        size = packet[4]
        host = packet[5:5 + size].decode()
        offset = 5 + size
    elif atyp == 4:
        host = socket.inet_ntop(socket.AF_INET6, packet[4:20])
        offset = 20
    else:
        raise RuntimeError(f"invalid SOCKS5 UDP address type {atyp}")
    if len(packet) < offset + 2:
        raise RuntimeError("truncated SOCKS5 UDP response")
    port = struct.unpack("!H", packet[offset:offset + 2])[0]
    return packet[offset + 2:], host, port


def socks_udp_exchange(
    proxy: str, port: int, user: str, password: str, target: str, target_port: int, payload: bytes, timeout: float
) -> tuple[bytes, dict[str, Any]]:
    control = socket.create_connection((proxy, port), timeout=timeout)
    try:
        control.settimeout(timeout)
        socks_auth(control, user, password)
        control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        try:
            relay_host, relay_port = read_socks_reply(control)
        except TimeoutError as exc:
            raise TimeoutError("timed out waiting for UDP ASSOCIATE reply") from exc
        if ipaddress.ip_address(relay_host).is_unspecified:
            relay_host = proxy
        packet = encode_socks_udp_target(target, target_port) + payload
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(timeout)
            udp.sendto(packet, (relay_host, relay_port))
            try:
                response, source = udp.recvfrom(65535)
            except TimeoutError as exc:
                raise TimeoutError(f"no UDP datagram returned through relay {relay_host}:{relay_port}") from exc
        body, response_host, response_port = decode_socks_udp(response)
        return body, {
            "relay": f"{relay_host}:{relay_port}",
            "relay_source": f"{source[0]}:{source[1]}",
            "response_target": f"{response_host}:{response_port}",
        }
    finally:
        control.close()


def dns_probe(proxy: str, port: int, user: str, password: str, dns_host: str, dns_port: int, timeout: float) -> str:
    txid = int.from_bytes(os.urandom(2), "big")
    labels = b"".join(bytes([len(part)]) + part for part in b"example.com".split(b".")) + b"\x00"
    query = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", 1, 1)
    response, meta = socks_udp_exchange(proxy, port, user, password, dns_host, dns_port, query, timeout)
    if len(response) < 12:
        raise RuntimeError("truncated DNS response")
    response_txid, flags, _questions, answers = struct.unpack("!HHHH", response[:8])
    if response_txid != txid or not flags & 0x8000 or answers < 1:
        raise RuntimeError("invalid DNS response")
    return f"answers={answers}, relay={meta['relay']}"


def parse_stun_mapped(response: bytes, txid: bytes) -> str:
    if len(response) < 20:
        raise RuntimeError("truncated STUN response")
    msg_type, length, cookie = struct.unpack("!HHI", response[:8])
    if msg_type != 0x0101 or cookie != 0x2112A442 or response[8:20] != txid:
        raise RuntimeError("invalid STUN Binding response")
    offset = 20
    limit = min(len(response), 20 + length)
    while offset + 4 <= limit:
        attr_type, attr_len = struct.unpack("!HH", response[offset:offset + 4])
        value = response[offset + 4:offset + 4 + attr_len]
        if attr_type in (0x0001, 0x0020) and len(value) >= 8 and value[1] == 1:
            port = struct.unpack("!H", value[2:4])[0]
            address = int.from_bytes(value[4:8], "big")
            if attr_type == 0x0020:
                port ^= 0x2112
                address ^= 0x2112A442
            return socket.inet_ntoa(address.to_bytes(4, "big")) + f":{port}"
        offset += 4 + ((attr_len + 3) & ~3)
    raise RuntimeError("STUN response has no IPv4 mapped address")


def stun_probe(
    proxy: str, port: int, user: str, password: str, stun_servers: list[dict[str, Any]], timeout: float
) -> str:
    errors = []
    for server in stun_servers:
        txid = os.urandom(12)
        request = struct.pack("!HHI", 0x0001, 0, 0x2112A442) + txid
        try:
            response, meta = socks_udp_exchange(
                proxy, port, user, password, server["host"], int(server["port"]), request, timeout
            )
            return f"mapped={parse_stun_mapped(response, txid)}, relay={meta['relay']}"
        except Exception as exc:  # try the configured fallback
            errors.append(f"{server['host']}:{server['port']}={type(exc).__name__}")
    raise RuntimeError("all STUN probes failed: " + ", ".join(errors))


def mapped_ip(detail: str) -> str:
    marker = "mapped="
    start = detail.find(marker)
    if start < 0:
        return ""
    return detail[start + len(marker):].split(":", 1)[0]


def load_config(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as stream:
        return yaml.safe_load(stream)


def run_check(results: list[dict[str, Any]], endpoint: str, name: str, required: bool, expected: str | None, call: Callable[[], str]) -> None:
    started = time.monotonic()
    try:
        detail = call()
        actual = mapped_ip(detail) if name == "udp_stun" else detail.strip()
        if expected and actual != expected:
            raise RuntimeError(f"egress mismatch: expected {expected}, got {actual}")
        status = "PASS"
        error = None
    except Exception as exc:
        detail = None
        status = "FAIL"
        error = f"{type(exc).__name__}: {exc}"
    results.append({
        "endpoint": endpoint,
        "check": name,
        "required": required,
        "status": status,
        "expected": expected,
        "detail": detail,
        "error": error,
        "duration_ms": round((time.monotonic() - started) * 1000),
    })


def add_na(results: list[dict[str, Any]], endpoint: str, check: str, reason: str) -> None:
    results.append({"endpoint": endpoint, "check": check, "required": False, "status": "N/A", "detail": reason})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--scope", choices=("vm", "e2e"), default="e2e")
    parser.add_argument("--endpoint")
    parser.add_argument("--timeout", type=float)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    config = load_config(args.config)
    timeout = args.timeout or float(config["probes"]["timeout_seconds"])
    public_ip = config["server"]["public_ip"]
    local_user = config["local_auth"]["username"]
    local_password = config["local_auth"]["password"]
    http_host = config["probes"]["http_host"]
    http_port = int(config["probes"]["http_port"])
    dns_host = config["probes"]["dns_server"]
    dns_port = int(config["probes"]["dns_port"])
    stun_servers = config["probes"]["stun_servers"]
    results: list[dict[str, Any]] = []

    for listener in config["listeners"]:
        endpoint = listener["id"]
        if args.endpoint and endpoint != args.endpoint:
            continue
        parent = listener["parent"]
        expected = public_ip if parent == "direct" else config["upstreams"][parent]["expected_egress_ip"]
        port = int(listener["port"])
        if listener["protocol"] == "socks5":
            run_check(results, endpoint, "tcp", True, expected, lambda p=port: socks_tcp(
                public_ip, p, local_user, local_password, http_host, http_port, timeout
            ))
            if "udp" in listener["capabilities"]:
                run_check(results, endpoint, "udp_dns", True, None, lambda p=port: dns_probe(
                    public_ip, p, local_user, local_password, dns_host, dns_port, timeout
                ))
                run_check(results, endpoint, "udp_stun", True, expected, lambda p=port: stun_probe(
                    public_ip, p, local_user, local_password, stun_servers, timeout
                ))
            else:
                add_na(results, endpoint, "udp", "not supported by HTTP CONNECT parent")
        else:
            run_check(results, endpoint, "http_get", True, expected, lambda p=port: http_get(
                public_ip, p, local_user, local_password, http_host, http_port, timeout
            ))
            run_check(results, endpoint, "http_connect", True, expected, lambda p=port: http_connect(
                public_ip, p, local_user, local_password, http_host, http_port, timeout
            ))

    for upstream_name, upstream in config["upstreams"].items():
        endpoint = f"upstream_{upstream_name}"
        if args.endpoint and endpoint != args.endpoint:
            continue
        host, port = upstream["host"], int(upstream["port"])
        user, password = upstream["username"], upstream["password"]
        expected = upstream["expected_egress_ip"]
        if upstream["type"] == "socks5":
            run_check(results, endpoint, "tcp", True, expected, lambda: socks_tcp(
                host, port, user, password, http_host, http_port, timeout
            ))
            run_check(results, endpoint, "udp_dns", True, None, lambda: dns_probe(
                host, port, user, password, dns_host, dns_port, timeout
            ))
            run_check(results, endpoint, "udp_stun", True, expected, lambda: stun_probe(
                host, port, user, password, stun_servers, timeout
            ))
        else:
            run_check(results, endpoint, "http_get", True, expected, lambda: http_get(
                host, port, user, password, http_host, http_port, timeout
            ))
            run_check(results, endpoint, "http_connect", True, expected, lambda: http_connect(
                host, port, user, password, http_host, http_port, timeout
            ))

    for result in results:
        suffix = result.get("detail") or result.get("error") or ""
        print(f"{result['status']:<4} {result['endpoint']:<25} {result['check']:<12} {suffix}")
    summary = {
        "scope": args.scope,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "endpoints": len({item["endpoint"] for item in results}),
        "passed": sum(item["status"] == "PASS" for item in results),
        "failed": sum(item["status"] == "FAIL" for item in results),
        "not_applicable": sum(item["status"] == "N/A" for item in results),
        "results": results,
    }
    print(f"SUMMARY endpoints={summary['endpoints']} passed={summary['passed']} failed={summary['failed']} n/a={summary['not_applicable']}")
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return 1 if any(item["required"] and item["status"] == "FAIL" for item in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
