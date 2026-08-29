"""Opt-in SOCKS5 UDP regressions for the retained 3proxy 1.0.0 patch.

Set ``THREEPROXY_BINARY`` to the patched 3proxy executable to run the two
process-level tests.  The default test run remains hermetic and only exercises
the wire-parser fixtures.

The runtime topology is deliberately IPv4-only.  That makes both the client
BND reply and the upstream parent's BND reply use ATYP 1, so the one-hop
roundtrip depends on 3proxy reading the IPv4 relay address and port correctly.
Stock 3proxy generates BND replies from a bound socket and therefore cannot be
made to return a domain name in this fixture.  Domain and IPv6 framing are
covered below with parser fixtures instead of requiring non-loopback or
machine-specific IPv6 setup.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Protocol


LOOPBACK = "127.0.0.1"
MIN_TEST_PORT = 20_000
ECHO_PREFIX = b"threeproxy-udp-echo:"
BINARY_ENV = os.environ.get("THREEPROXY_BINARY")


class _RecvStream(Protocol):
    def recv(self, size: int) -> bytes: ...


@dataclass(frozen=True)
class _SocksAddress:
    atyp: int
    host: str
    port: int


@dataclass(frozen=True)
class _SocksReply:
    version: int
    status: int
    reserved: int
    bound: _SocksAddress


@dataclass(frozen=True)
class _UdpRoundTrip:
    relay: _SocksAddress
    response_source: _SocksAddress
    response_body: bytes
    datagram_sender: tuple[str, int]


def _read_exact(stream: _RecvStream, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = stream.recv(size - len(data))
        if not chunk:
            raise EOFError(f"SOCKS5 stream ended after {len(data)} of {size} bytes")
        data.extend(chunk)
    return bytes(data)


def _read_socks_address(stream: _RecvStream, atyp: int) -> _SocksAddress:
    if atyp == 1:
        host = socket.inet_ntop(socket.AF_INET, _read_exact(stream, 4))
    elif atyp == 3:
        length = _read_exact(stream, 1)[0]
        if length == 0:
            raise ValueError("SOCKS5 domain BND address is empty")
        host = _read_exact(stream, length).decode("idna")
    elif atyp == 4:
        host = socket.inet_ntop(socket.AF_INET6, _read_exact(stream, 16))
    else:
        raise ValueError(f"unknown SOCKS5 address type {atyp}")
    port = struct.unpack("!H", _read_exact(stream, 2))[0]
    return _SocksAddress(atyp, host, port)


def _read_socks_reply(stream: _RecvStream) -> _SocksReply:
    header = _read_exact(stream, 4)
    bound = _read_socks_address(stream, header[3])
    return _SocksReply(header[0], header[1], header[2], bound)


def _encode_udp_request(host: str, port: int, body: bytes) -> bytes:
    address = socket.inet_pton(socket.AF_INET, host)
    return b"\x00\x00\x00\x01" + address + struct.pack("!H", port) + body


def _decode_udp_response(packet: bytes) -> tuple[_SocksAddress, bytes]:
    if len(packet) < 4:
        raise ValueError("truncated SOCKS5 UDP response header")
    if packet[:2] != b"\x00\x00":
        raise ValueError("invalid SOCKS5 UDP reserved field")
    if packet[2] != 0:
        raise ValueError("fragmented SOCKS5 UDP responses are unsupported")

    atyp = packet[3]
    offset = 4
    if atyp == 1:
        address_size = 4
        if len(packet) < offset + address_size + 2:
            raise ValueError("truncated IPv4 SOCKS5 UDP response")
        host = socket.inet_ntop(socket.AF_INET, packet[offset : offset + address_size])
        offset += address_size
    elif atyp == 3:
        if len(packet) < 5:
            raise ValueError("truncated domain SOCKS5 UDP response")
        address_size = packet[offset]
        offset += 1
        if address_size == 0 or len(packet) < offset + address_size + 2:
            raise ValueError("truncated domain SOCKS5 UDP response")
        host = packet[offset : offset + address_size].decode("idna")
        offset += address_size
    elif atyp == 4:
        address_size = 16
        if len(packet) < offset + address_size + 2:
            raise ValueError("truncated IPv6 SOCKS5 UDP response")
        host = socket.inet_ntop(socket.AF_INET6, packet[offset : offset + address_size])
        offset += address_size
    else:
        raise ValueError(f"unknown SOCKS5 UDP address type {atyp}")

    port = struct.unpack("!H", packet[offset : offset + 2])[0]
    offset += 2
    return _SocksAddress(atyp, host, port), packet[offset:]


class _FragmentedReader:
    """Small recv() fixture that exposes every SOCKS field one byte at a time."""

    def __init__(self, payload: bytes) -> None:
        self._payload = payload
        self._offset = 0

    def recv(self, size: int) -> bytes:
        if self._offset == len(self._payload):
            return b""
        end = min(len(self._payload), self._offset + max(1, min(size, 1)))
        chunk = self._payload[self._offset : end]
        self._offset = end
        return chunk


class SocksWireParserFixtureTests(unittest.TestCase):
    def test_bnd_reply_parser_handles_ipv4_domain_and_ipv6_fixtures(self) -> None:
        fixtures = [
            (
                b"\x05\x00\x00\x01" + socket.inet_pton(socket.AF_INET, "127.0.0.1") + struct.pack("!H", 40_001),
                _SocksAddress(1, "127.0.0.1", 40_001),
            ),
            (
                b"\x05\x00\x00\x03\x0drelay.example" + struct.pack("!H", 40_002),
                _SocksAddress(3, "relay.example", 40_002),
            ),
            (
                b"\x05\x00\x00\x04" + socket.inet_pton(socket.AF_INET6, "::1") + struct.pack("!H", 40_003),
                _SocksAddress(4, "::1", 40_003),
            ),
        ]
        for wire, expected in fixtures:
            with self.subTest(atyp=expected.atyp):
                reply = _read_socks_reply(_FragmentedReader(wire))
                self.assertEqual((reply.version, reply.status, reply.reserved), (5, 0, 0))
                self.assertEqual(reply.bound, expected)

    def test_udp_response_parser_handles_domain_and_ipv6_fixtures(self) -> None:
        fixtures = [
            (
                b"\x00\x00\x00\x03\x0drelay.example" + struct.pack("!H", 40_004) + b"domain-body",
                _SocksAddress(3, "relay.example", 40_004),
                b"domain-body",
            ),
            (
                b"\x00\x00\x00\x04" + socket.inet_pton(socket.AF_INET6, "::1")
                + struct.pack("!H", 40_005) + b"ipv6-body",
                _SocksAddress(4, "::1", 40_005),
                b"ipv6-body",
            ),
        ]
        for wire, expected_source, expected_body in fixtures:
            with self.subTest(atyp=expected_source.atyp):
                source, body = _decode_udp_response(wire)
                self.assertEqual(source, expected_source)
                self.assertEqual(body, expected_body)


@dataclass
class _TcpPortReservation:
    port: int
    _socket: socket.socket | None

    def release(self) -> None:
        if self._socket is not None:
            self._socket.close()
            self._socket = None


def _reserve_high_tcp_port() -> _TcpPortReservation:
    for _ in range(128):
        candidate = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                candidate.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            candidate.bind((LOOPBACK, 0))
            port = int(candidate.getsockname()[1])
            if port >= MIN_TEST_PORT:
                return _TcpPortReservation(port, candidate)
        except BaseException:
            candidate.close()
            raise
        candidate.close()
    raise RuntimeError(f"could not reserve a loopback TCP port at or above {MIN_TEST_PORT}")


def _bound_high_udp_socket() -> socket.socket:
    for _ in range(128):
        candidate = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                candidate.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            candidate.bind((LOOPBACK, 0))
            if int(candidate.getsockname()[1]) >= MIN_TEST_PORT:
                return candidate
        except BaseException:
            candidate.close()
            raise
        candidate.close()
    raise RuntimeError(f"could not bind a loopback UDP port at or above {MIN_TEST_PORT}")


class _UdpEchoServer:
    def __init__(self) -> None:
        self._socket = _bound_high_udp_socket()
        self._socket.settimeout(0.1)
        self.port = int(self._socket.getsockname()[1])
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._received: list[tuple[bytes, tuple[str, int]]] = []
        self._errors: list[str] = []
        self._thread = threading.Thread(target=self._serve, name="threeproxy-udp-echo", daemon=True)

    @property
    def received(self) -> list[tuple[bytes, tuple[str, int]]]:
        with self._lock:
            return list(self._received)

    @property
    def errors(self) -> list[str]:
        with self._lock:
            return list(self._errors)

    def __enter__(self) -> _UdpEchoServer:
        self._thread.start()
        return self

    def __exit__(self, *unused: object) -> None:
        self._stop.set()
        self._socket.close()
        self._thread.join(timeout=2)

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                payload, source = self._socket.recvfrom(65_535)
            except socket.timeout:
                continue
            except OSError as exc:
                if not self._stop.is_set():
                    with self._lock:
                        self._errors.append(f"{type(exc).__name__}: {exc}")
                return
            with self._lock:
                self._received.append((payload, (source[0], int(source[1]))))
            try:
                self._socket.sendto(ECHO_PREFIX + payload, source)
            except OSError as exc:
                if not self._stop.is_set():
                    with self._lock:
                        self._errors.append(f"{type(exc).__name__}: {exc}")
                return


@dataclass
class _RunningProxy:
    name: str
    port: int
    process: subprocess.Popen[bytes]
    output_path: Path

    def diagnostics(self) -> str:
        with contextlib.suppress(OSError):
            text = self.output_path.read_text(encoding="utf-8", errors="replace")
            return text if text else "<3proxy produced no output>"
        return "<3proxy output unavailable>"


def _render_config(listener_port: int, parent_port: int | None = None) -> str:
    lines = [
        "timeouts 1 5 5 10 30 30 5 10 5 5",
        "maxconn 64",
        "auth iponly",
        f"allow * {LOOPBACK}",
    ]
    if parent_port is not None:
        lines.append(f"parent 1000 socks5 {LOOPBACK} {parent_port}")
    lines.extend(
        [
            "deny *",
            f"socks -i{LOOPBACK} -e{LOOPBACK} -p{listener_port} -Ni{LOOPBACK}",
            "flush",
            "end",
            "",
        ]
    )
    return "\n".join(lines)


def _socks_udp_roundtrip(proxy_port: int, target_port: int, body: bytes) -> _UdpRoundTrip:
    with _bound_high_udp_socket() as udp:
        udp.settimeout(8)
        udp_host, udp_port = udp.getsockname()[:2]
        with socket.create_connection((LOOPBACK, proxy_port), timeout=4) as control:
            control.settimeout(8)
            control.sendall(b"\x05\x01\x00")
            greeting = _read_exact(control, 2)
            if greeting != b"\x05\x00":
                raise RuntimeError(f"SOCKS5 no-authentication negotiation failed: {greeting!r}")

            associate = (
                b"\x05\x03\x00\x01"
                + socket.inet_pton(socket.AF_INET, str(udp_host))
                + struct.pack("!H", int(udp_port))
            )
            control.sendall(associate)
            reply = _read_socks_reply(control)
            if (reply.version, reply.status, reply.reserved) != (5, 0, 0):
                raise RuntimeError(f"UDP ASSOCIATE failed: {reply!r}")
            if reply.bound.atyp != 1 or reply.bound.host != LOOPBACK or reply.bound.port == 0:
                raise RuntimeError(f"expected a usable IPv4 loopback BND reply, got {reply.bound!r}")

            relay_endpoint = (reply.bound.host, reply.bound.port)
            udp.sendto(_encode_udp_request(LOOPBACK, target_port, body), relay_endpoint)
            packet, sender = udp.recvfrom(65_535)
            response_source, response_body = _decode_udp_response(packet)
            return _UdpRoundTrip(
                reply.bound,
                response_source,
                response_body,
                (sender[0], int(sender[1])),
            )


@unittest.skipUnless(
    bool(BINARY_ENV),
    "set THREEPROXY_BINARY to the patched 3proxy 1.0.0 executable (runtime tests are opt-in)",
)
class ThreeProxyUdpRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        assert BINARY_ENV is not None
        resolved = shutil.which(BINARY_ENV)
        if resolved is None:
            candidate = Path(BINARY_ENV).expanduser()
            if candidate.is_file():
                resolved = str(candidate.resolve())
        if resolved is None or not os.access(resolved, os.X_OK):
            raise AssertionError(f"THREEPROXY_BINARY is not executable: {BINARY_ENV}")
        cls.binary = Path(resolved)

    @contextlib.contextmanager
    def _running_proxy(
        self,
        root: Path,
        name: str,
        reservation: _TcpPortReservation,
        parent_port: int | None = None,
    ) -> Iterator[_RunningProxy]:
        directory = root / name
        directory.mkdir(mode=0o700)
        config_path = directory / "3proxy.cfg"
        config_path.write_text(
            _render_config(reservation.port, parent_port),
            encoding="utf-8",
            newline="\n",
        )
        output_path = directory / "3proxy.output"
        listener_port = reservation.port
        reservation.release()

        with output_path.open("wb") as output:
            process = subprocess.Popen(
                [str(self.binary), str(config_path)],
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
                cwd=directory,
            )
            running = _RunningProxy(name, listener_port, process, output_path)
            try:
                self._wait_for_listener(running)
                yield running
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=8)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)

    def _wait_for_listener(self, running: _RunningProxy) -> None:
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline:
            return_code = running.process.poll()
            if return_code is not None:
                self.fail(
                    f"{running.name} 3proxy exited before startup (rc={return_code}):\n"
                    f"{running.diagnostics()}"
                )
            try:
                with socket.create_connection((LOOPBACK, running.port), timeout=0.1):
                    return
            except OSError:
                time.sleep(0.03)
        self.fail(
            f"{running.name} 3proxy did not listen on {LOOPBACK}:{running.port}:\n"
            f"{running.diagnostics()}"
        )

    def _run_and_assert(
        self,
        proxy: _RunningProxy,
        echo: _UdpEchoServer,
        payload: bytes,
        *additional_diagnostics: _RunningProxy,
    ) -> None:
        try:
            result = _socks_udp_roundtrip(proxy.port, echo.port, payload)
        except (EOFError, OSError, RuntimeError, ValueError) as exc:
            diagnostics = "\n".join(
                f"--- {item.name} 3proxy ---\n{item.diagnostics()}"
                for item in (proxy, *additional_diagnostics)
            )
            self.fail(f"SOCKS5 UDP roundtrip failed: {type(exc).__name__}: {exc}\n{diagnostics}")

        self.assertEqual(result.relay.atyp, 1)
        self.assertEqual(result.relay.host, LOOPBACK)
        self.assertGreaterEqual(result.relay.port, 1_024)
        self.assertEqual(result.datagram_sender, (LOOPBACK, result.relay.port))
        self.assertEqual(result.response_source, _SocksAddress(1, LOOPBACK, echo.port))
        self.assertEqual(result.response_body, ECHO_PREFIX + payload)
        self.assertEqual([item[0] for item in echo.received], [payload])
        self.assertTrue(all(item[1][0] == LOOPBACK for item in echo.received), echo.received)
        self.assertFalse(echo.errors, echo.errors)

    def test_direct_socks5_udp_associate_roundtrip(self) -> None:
        listener = _reserve_high_tcp_port()
        self.addCleanup(listener.release)
        with tempfile.TemporaryDirectory(prefix="threeproxy-udp-direct-") as temporary, _UdpEchoServer() as echo:
            with self._running_proxy(Path(temporary), "direct", listener) as direct:
                self._run_and_assert(direct, echo, b"direct-retained-patch\x00roundtrip")

    def test_one_hop_socks5_parent_udp_roundtrip(self) -> None:
        parent_listener = _reserve_high_tcp_port()
        self.addCleanup(parent_listener.release)
        child_listener = _reserve_high_tcp_port()
        self.addCleanup(child_listener.release)
        with tempfile.TemporaryDirectory(prefix="threeproxy-udp-one-hop-") as temporary, _UdpEchoServer() as echo:
            root = Path(temporary)
            with self._running_proxy(root, "parent", parent_listener) as parent:
                with self._running_proxy(root, "child", child_listener, parent.port) as child:
                    self._run_and_assert(
                        child,
                        echo,
                        b"one-hop-retained-patch\x00roundtrip",
                        parent,
                    )


if __name__ == "__main__":
    unittest.main()
