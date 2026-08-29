#!/usr/bin/env python3
"""Deterministic build-time checks for the pinned 3proxy binary."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import socket
import ssl
import sys


MAX_HEADER_BYTES = 64 * 1024


def patchset_sha256(directory: Path) -> str:
    """Hash patch contents and basenames without depending on the checkout path."""
    patches = sorted(
        (path for path in directory.glob("*.patch") if path.is_file()),
        key=lambda path: path.name,
    )
    if not patches:
        raise ValueError(f"no .patch files found in {directory}")

    aggregate = hashlib.sha256()
    for patch in patches:
        content_sha = hashlib.sha256(patch.read_bytes()).hexdigest()
        aggregate.update(f"{content_sha}  {patch.name}\n".encode("utf-8"))
    return aggregate.hexdigest()


def read_http_header(connection: ssl.SSLSocket) -> bytes:
    header = bytearray()
    while b"\r\n\r\n" not in header:
        chunk = connection.recv(4096)
        if not chunk:
            raise ConnectionError("TLS peer closed before completing CONNECT headers")
        header.extend(chunk)
        if len(header) > MAX_HEADER_BYTES:
            raise ValueError("CONNECT headers exceed 64 KiB")
    return bytes(header[: header.index(b"\r\n\r\n") + 4])


def validate_connect_header(header: bytes, expected_authority: str) -> str:
    try:
        request_line = header.split(b"\r\n", 1)[0].decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("CONNECT request line is not ASCII") from exc
    match = re.fullmatch(r"CONNECT ([^ ]+) HTTP/(1\.[01])", request_line)
    if match is None:
        raise ValueError(f"unexpected proxy request line: {request_line!r}")
    authority, http_version = match.groups()
    if authority != expected_authority:
        raise ValueError(
            f"unexpected CONNECT authority: {authority!r}; expected {expected_authority!r}"
        )
    return http_version


class SniGuard:
    def __init__(self, expected_name: str) -> None:
        self.expected_name = expected_name
        self.observed_name: str | None = None

    def __call__(
        self,
        _connection: ssl.SSLSocket,
        server_name: str | None,
        _context: ssl.SSLContext,
    ) -> int | None:
        self.observed_name = server_name
        if server_name != self.expected_name:
            return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
        return None


def run_tls_parent(
    *,
    listen_host: str,
    port: int,
    certificate: Path,
    private_key: Path,
    expected_sni: str,
    expected_authority: str,
    timeout: float,
) -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=certificate, keyfile=private_key)
    sni_guard = SniGuard(expected_sni)
    context.set_servername_callback(sni_guard)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((listen_host, port))
        listener.listen(1)
        listener.settimeout(timeout)
        print(f"PROBE_READY host={listen_host} port={port}", flush=True)

        raw_connection, _peer = listener.accept()
        with raw_connection:
            raw_connection.settimeout(timeout)
            with context.wrap_socket(raw_connection, server_side=True) as tls_connection:
                if sni_guard.observed_name != expected_sni:
                    raise ssl.SSLError(
                        f"unexpected or missing SNI: {sni_guard.observed_name!r}"
                    )
                header = read_http_header(tls_connection)
                http_version = validate_connect_header(header, expected_authority)
                tls_connection.sendall(
                    b"HTTP/1.1 200 Connection Established\r\n"
                    b"Connection: close\r\n\r\n"
                )

    print(
        f"PROBE_OK sni={expected_sni} authority={expected_authority} "
        f"http={http_version}",
        flush=True,
    )


def positive_timeout(value: str) -> float:
    timeout = float(value)
    if timeout <= 0:
        raise argparse.ArgumentTypeError("timeout must be positive")
    return timeout


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    digest_parser = subparsers.add_parser("patchset-sha")
    digest_parser.add_argument("--directory", type=Path, required=True)

    parent_parser = subparsers.add_parser("tls-connect-parent")
    parent_parser.add_argument("--listen-host", default="127.0.0.1")
    parent_parser.add_argument("--port", type=int, required=True)
    parent_parser.add_argument("--cert", type=Path, required=True)
    parent_parser.add_argument("--key", type=Path, required=True)
    parent_parser.add_argument("--expected-sni", required=True)
    parent_parser.add_argument("--expected-authority", required=True)
    parent_parser.add_argument("--timeout", type=positive_timeout, default=8.0)

    args = parser.parse_args()
    try:
        if args.command == "patchset-sha":
            print(patchset_sha256(args.directory))
        else:
            run_tls_parent(
                listen_host=args.listen_host,
                port=args.port,
                certificate=args.cert,
                private_key=args.key,
                expected_sni=args.expected_sni,
                expected_authority=args.expected_authority,
                timeout=args.timeout,
            )
    except (ConnectionError, OSError, ValueError, ssl.SSLError) as exc:
        print(f"BUILD_CHECK_FAILED {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
