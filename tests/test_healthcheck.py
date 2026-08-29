from __future__ import annotations

import base64
import io
import json
import socket
import ssl
import struct
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import healthcheck  # noqa: E402


class FakeStreamSocket:
    def __init__(self, *chunks: bytes | BaseException) -> None:
        self.chunks = list(chunks)
        self.sent = bytearray()
        self.timeouts: list[float] = []
        self.closed = False

    def sendall(self, payload: bytes) -> None:
        self.sent.extend(payload)

    def recv(self, size: int) -> bytes:
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        if isinstance(chunk, BaseException):
            raise chunk
        if len(chunk) > size:
            self.chunks.insert(0, chunk[size:])
            return chunk[:size]
        return chunk

    def settimeout(self, timeout: float) -> None:
        self.timeouts.append(timeout)

    def close(self) -> None:
        self.closed = True

    def __enter__(self) -> FakeStreamSocket:
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


class FakeDatagramSocket:
    def __init__(self, response: bytes, source: tuple[str, int] = ("192.0.2.25", 40000)) -> None:
        self.response = response
        self.source = source
        self.timeout: float | None = None
        self.sent: list[tuple[bytes, tuple[str, int]]] = []
        self.closed = False

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def sendto(self, payload: bytes, target: tuple[str, int]) -> None:
        self.sent.append((payload, target))

    def recvfrom(self, size: int) -> tuple[bytes, tuple[str, int]]:
        return self.response, self.source

    def __enter__(self) -> FakeDatagramSocket:
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.closed = True


def socks_reply(host: str, port: int) -> bytes:
    try:
        packed = socket.inet_pton(socket.AF_INET, host)
    except OSError:
        try:
            packed = socket.inet_pton(socket.AF_INET6, host)
        except OSError:
            encoded = host.encode()
            address = b"\x03" + bytes([len(encoded)]) + encoded
        else:
            address = b"\x04" + packed
    else:
        address = b"\x01" + packed
    return b"\x05\x00\x00" + address + struct.pack("!H", port)


def udp_packet(host: str, port: int, body: bytes) -> bytes:
    reply = socks_reply(host, port)
    return b"\x00\x00\x00" + reply[3:] + body


def make_health_config(*, mode: str = "strong") -> dict:
    data = {
        "server": {"public_ip": "203.0.113.10", "listen_ip": "0.0.0.0"},
        "access": {"mode": mode},
        "listeners": [],
        "upstreams": {},
        "probes": {
            "timeout_seconds": 8,
            "http_host": "api.ipify.org",
            "http_port": 80,
            "dns_server": "1.1.1.1",
            "dns_port": 53,
            "stun_servers": [{"host": "stun.example.test", "port": 3478}],
        },
    }
    if mode == "strong":
        data["local_auth"] = {"username": "local-user", "password": "local-password"}
    else:
        data["access"]["allowed_client_cidrs"] = ["198.51.100.0/24"]
    return data


class HealthcheckMainMixin:
    def invoke(self, config: dict, *args: str) -> tuple[int, str]:
        output = io.StringIO()
        with mock.patch.object(sys, "argv", ["healthcheck.py", "--config", "unused.yaml", *args]), \
                mock.patch.object(healthcheck, "load_config", return_value=config), \
                redirect_stdout(output):
            result = healthcheck.main()
        return result, output.getvalue()


class SocketPrimitiveTests(unittest.TestCase):
    def test_recv_exact_combines_partial_reads(self) -> None:
        sock = FakeStreamSocket(b"a", b"bc", b"def")
        self.assertEqual(healthcheck.recv_exact(sock, 6), b"abcdef")

    def test_recv_exact_rejects_early_eof(self) -> None:
        sock = FakeStreamSocket(b"ab", b"")
        with self.assertRaisesRegex(ConnectionError, "unexpected EOF"):
            healthcheck.recv_exact(sock, 3)

    def test_socks_no_auth_negotiation(self) -> None:
        sock = FakeStreamSocket(b"\x05\x00")
        healthcheck.socks_auth(sock, None, None)
        self.assertEqual(bytes(sock.sent), b"\x05\x01\x00")

    def test_socks_username_password_negotiation(self) -> None:
        sock = FakeStreamSocket(b"\x05\x02", b"\x01\x00")
        healthcheck.socks_auth(sock, "alice", "secret")
        self.assertEqual(
            bytes(sock.sent),
            b"\x05\x01\x02\x01\x05alice\x06secret",
        )

    def test_socks_auth_rejects_wrong_method_failed_auth_and_long_credentials(self) -> None:
        cases = [
            (FakeStreamSocket(b"\x05\xff"), None, None, "no-authentication method"),
            (FakeStreamSocket(b"\x05\x00"), "alice", "secret", "username/password authentication"),
            (FakeStreamSocket(b"\x05\x02", b"\x01\x01"), "alice", "secret", "authentication failed"),
            (FakeStreamSocket(b"\x05\x02"), "x" * 256, "secret", "credentials are too long"),
        ]
        for sock, user, password, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(RuntimeError, message):
                    healthcheck.socks_auth(sock, user, password)

    def test_read_socks_reply_supports_ipv4_domain_and_ipv6(self) -> None:
        for host, port in (("192.0.2.1", 1080), ("relay.example", 5353), ("2001:db8::1", 443)):
            with self.subTest(host=host):
                self.assertEqual(healthcheck.read_socks_reply(FakeStreamSocket(socks_reply(host, port))), (host, port))

    def test_read_socks_reply_rejects_status_and_unknown_address_type(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "status=5"):
            healthcheck.read_socks_reply(FakeStreamSocket(b"\x05\x05\x00\x01"))
        with self.assertRaisesRegex(RuntimeError, "unknown SOCKS5 address type 9"):
            healthcheck.read_socks_reply(FakeStreamSocket(b"\x05\x00\x00\x09"))

    def test_read_http_response_stops_on_eof_or_timeout(self) -> None:
        for terminator in (b"", socket.timeout()):
            with self.subTest(terminator=type(terminator).__name__):
                sock = FakeStreamSocket(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n",
                    b" egress ",
                    terminator,
                )
                self.assertEqual(healthcheck.read_http_response(sock), ("HTTP/1.1 200 OK", b"egress"))


class TcpProbeTests(unittest.TestCase):
    def test_socks_tcp_performs_auth_connect_and_http_probe(self) -> None:
        sock = FakeStreamSocket(
            b"\x05\x02",
            b"\x01\x00",
            socks_reply("0.0.0.0", 0),
            b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n198.51.100.8",
            b"",
        )
        with mock.patch.object(healthcheck.socket, "create_connection", return_value=sock) as create:
            result = healthcheck.socks_tcp(
                "proxy.example", 1080, "alice", "secret", "api.ipify.org", 80, 3.5
            )
        self.assertEqual(result, "198.51.100.8")
        create.assert_called_once_with(("proxy.example", 1080), timeout=3.5)
        self.assertEqual(sock.timeouts, [3.5])
        self.assertIn(b"\x05\x01\x00\x03\x0dapi.ipify.org\x00P", bytes(sock.sent))
        self.assertTrue(bytes(sock.sent).endswith(b"GET / HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n"))

    def test_socks_tcp_rejects_non_200_target_response(self) -> None:
        sock = FakeStreamSocket(
            b"\x05\x00",
            socks_reply("0.0.0.0", 0),
            b"HTTP/1.1 503 Unavailable\r\n\r\nno",
            b"",
        )
        with mock.patch.object(healthcheck.socket, "create_connection", return_value=sock):
            with self.assertRaisesRegex(RuntimeError, "target HTTP response"):
                healthcheck.socks_tcp("proxy", 1080, None, None, "target", 80, 2)

    def test_proxy_authorization_supports_auth_and_noauth(self) -> None:
        self.assertEqual(healthcheck.proxy_authorization(None, None), "")
        expected = base64.b64encode(b"alice:secret").decode()
        self.assertEqual(
            healthcheck.proxy_authorization("alice", "secret"),
            f"Proxy-Authorization: Basic {expected}\r\n",
        )

    def test_open_proxy_connection_plaintext_does_not_create_tls_context(self) -> None:
        raw = mock.Mock()
        with mock.patch.object(healthcheck.socket, "create_connection", return_value=raw) as create, \
                mock.patch.object(healthcheck.ssl, "create_default_context") as create_context:
            result = healthcheck.open_proxy_connection("proxy.example", 8080, 4)
        self.assertIs(result, raw)
        create.assert_called_once_with(("proxy.example", 8080), timeout=4)
        raw.settimeout.assert_called_once_with(4)
        create_context.assert_not_called()

    def test_open_proxy_connection_wraps_with_verified_tls_sni_and_custom_ca(self) -> None:
        raw = mock.Mock()
        wrapped = mock.Mock()
        context = mock.Mock()
        context.wrap_socket.return_value = wrapped
        with mock.patch.object(healthcheck.socket, "create_connection", return_value=raw), \
                mock.patch.object(healthcheck.ssl, "create_default_context", return_value=context) as create_context:
            result = healthcheck.open_proxy_connection(
                "192.0.2.10",
                8443,
                5,
                tls_server_name="proxy.example.test",
                ca_file="/opt/ca/proxy.pem",
            )
        self.assertIs(result, wrapped)
        create_context.assert_called_once_with(cafile="/opt/ca/proxy.pem")
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertIs(context.check_hostname, True)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        context.wrap_socket.assert_called_once_with(raw, server_hostname="proxy.example.test")
        raw.close.assert_not_called()

    def test_open_proxy_connection_closes_raw_socket_on_tls_setup_or_handshake_failure(self) -> None:
        for failure_at in ("context", "wrap"):
            with self.subTest(failure_at=failure_at):
                raw = mock.Mock()
                context = mock.Mock()
                if failure_at == "context":
                    context_patch = mock.patch.object(
                        healthcheck.ssl, "create_default_context", side_effect=ssl.SSLError("bad CA")
                    )
                else:
                    context.wrap_socket.side_effect = ssl.SSLError("bad certificate")
                    context_patch = mock.patch.object(
                        healthcheck.ssl, "create_default_context", return_value=context
                    )
                with mock.patch.object(healthcheck.socket, "create_connection", return_value=raw), context_patch:
                    with self.assertRaises(ssl.SSLError):
                        healthcheck.open_proxy_connection(
                            "proxy", 8443, 5, tls_server_name="proxy.example.test"
                        )
                raw.close.assert_called_once_with()

    def test_http_get_sends_auth_over_verified_tls_and_returns_body(self) -> None:
        sock = FakeStreamSocket(b"HTTP/1.1 200 OK\r\n\r\n203.0.113.9\n", b"")
        with mock.patch.object(healthcheck, "open_proxy_connection", return_value=sock) as open_connection:
            result = healthcheck.http_get(
                "proxy.example",
                8443,
                "alice",
                "secret",
                "api.ipify.org",
                80,
                6,
                tls_server_name="proxy.example",
                ca_file="/ca.pem",
            )
        self.assertEqual(result, "203.0.113.9")
        open_connection.assert_called_once_with(
            "proxy.example", 8443, 6, tls_server_name="proxy.example", ca_file="/ca.pem"
        )
        request = bytes(sock.sent).decode()
        self.assertTrue(request.startswith("GET http://api.ipify.org:80/ HTTP/1.1\r\n"))
        self.assertIn("Proxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\n", request)

    def test_http_get_noauth_omits_header_and_rejects_non_200(self) -> None:
        ok = FakeStreamSocket(b"HTTP/1.1 200 OK\r\n\r\nbody", b"")
        with mock.patch.object(healthcheck, "open_proxy_connection", return_value=ok):
            self.assertEqual(healthcheck.http_get("proxy", 8080, None, None, "target", 80, 2), "body")
        self.assertNotIn(b"Proxy-Authorization", bytes(ok.sent))

        failed = FakeStreamSocket(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n", b"")
        with mock.patch.object(healthcheck, "open_proxy_connection", return_value=failed):
            with self.assertRaisesRegex(RuntimeError, "HTTP proxy response"):
                healthcheck.http_get("proxy", 8080, None, None, "target", 80, 2)

    def test_http_connect_tunnels_request_over_verified_tls(self) -> None:
        sock = FakeStreamSocket(
            b"HTTP/1.1 200 Connection established\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n198.51.100.7",
            b"",
        )
        with mock.patch.object(healthcheck, "open_proxy_connection", return_value=sock) as open_connection:
            result = healthcheck.http_connect(
                "secure.example",
                8443,
                "alice",
                "secret",
                "api.ipify.org",
                80,
                7,
                tls_server_name="secure.example",
                ca_file="/ca.pem",
            )
        self.assertEqual(result, "198.51.100.7")
        open_connection.assert_called_once_with(
            "secure.example", 8443, 7, tls_server_name="secure.example", ca_file="/ca.pem"
        )
        sent = bytes(sock.sent)
        self.assertIn(b"CONNECT api.ipify.org:80 HTTP/1.1", sent)
        self.assertIn(b"Proxy-Authorization: Basic YWxpY2U6c2VjcmV0", sent)
        self.assertTrue(sent.endswith(b"GET / HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n"))

    def test_http_connect_rejects_proxy_or_target_failure(self) -> None:
        proxy_failure = FakeStreamSocket(b"HTTP/1.1 403 Forbidden\r\n\r\n")
        with mock.patch.object(healthcheck, "open_proxy_connection", return_value=proxy_failure):
            with self.assertRaisesRegex(RuntimeError, "CONNECT response"):
                healthcheck.http_connect("proxy", 8080, None, None, "target", 80, 2)

        target_failure = FakeStreamSocket(
            b"HTTP/1.1 200 Connection established\r\n\r\n",
            b"HTTP/1.1 500 Error\r\n\r\n",
            b"",
        )
        with mock.patch.object(healthcheck, "open_proxy_connection", return_value=target_failure):
            with self.assertRaisesRegex(RuntimeError, "target response through CONNECT"):
                healthcheck.http_connect("proxy", 8080, None, None, "target", 80, 2)

    def test_http_connect_rejects_eof_before_complete_connect_headers(self) -> None:
        sock = mock.MagicMock()
        sock.__enter__.return_value = sock
        sock.recv.side_effect = [b"", AssertionError("read attempted again after EOF")]
        with mock.patch.object(healthcheck, "open_proxy_connection", return_value=sock):
            with self.assertRaisesRegex(ConnectionError, "proxy closed.*CONNECT response"):
                healthcheck.http_connect("proxy", 8080, None, None, "target", 80, 2)

    def test_http_connect_caps_connect_response_headers(self) -> None:
        sock = FakeStreamSocket(b"x" * 65537)
        with mock.patch.object(healthcheck, "open_proxy_connection", return_value=sock):
            with self.assertRaisesRegex(RuntimeError, "headers exceed 64 KiB"):
                healthcheck.http_connect("proxy", 8080, None, None, "target", 80, 2)


class UdpProbeTests(unittest.TestCase):
    def test_encode_socks_udp_target_resolves_ipv4(self) -> None:
        with mock.patch.object(healthcheck.socket, "gethostbyname", return_value="192.0.2.44") as resolve:
            encoded = healthcheck.encode_socks_udp_target("dns.example", 53)
        resolve.assert_called_once_with("dns.example")
        self.assertEqual(encoded, b"\x00\x00\x00\x01" + socket.inet_aton("192.0.2.44") + b"\x005")

    def test_decode_socks_udp_supports_all_address_types(self) -> None:
        for host, port in (("192.0.2.1", 53), ("dns.example", 5353), ("2001:db8::1", 443)):
            with self.subTest(host=host):
                self.assertEqual(healthcheck.decode_socks_udp(udp_packet(host, port, b"payload")), (b"payload", host, port))

    def test_decode_socks_udp_rejects_invalid_and_truncated_packets(self) -> None:
        packets = (
            b"short",
            b"\x00\x00\x01\x01" + b"x" * 10,
            b"\x00\x00\x00\x09" + b"x" * 10,
            b"\x00\x00\x00\x03\x08abc",
        )
        for packet in packets:
            with self.subTest(packet=packet):
                with self.assertRaisesRegex(RuntimeError, "SOCKS5 UDP"):
                    healthcheck.decode_socks_udp(packet)

    def test_socks_udp_exchange_uses_proxy_for_unspecified_relay(self) -> None:
        control = FakeStreamSocket(b"\x05\x00", socks_reply("0.0.0.0", 5000))
        response = udp_packet("1.1.1.1", 53, b"answer")
        udp = FakeDatagramSocket(response)
        with mock.patch.object(healthcheck.socket, "create_connection", return_value=control), \
                mock.patch.object(healthcheck.socket, "socket", return_value=udp), \
                mock.patch.object(healthcheck, "encode_socks_udp_target", return_value=b"target-header"):
            body, meta = healthcheck.socks_udp_exchange(
                "proxy.example", 1080, None, None, "dns.example", 53, b"query", 4
            )
        self.assertEqual(body, b"answer")
        self.assertEqual(
            meta,
            {
                "relay": "proxy.example:5000",
                "relay_source": "192.0.2.25:40000",
                "response_target": "1.1.1.1:53",
            },
        )
        self.assertEqual(udp.sent, [(b"target-headerquery", ("proxy.example", 5000))])
        self.assertEqual(udp.timeout, 4)
        self.assertTrue(control.closed)
        self.assertTrue(udp.closed)

    def test_dns_probe_validates_transaction_response_and_answer_count(self) -> None:
        txid = b"\x12\x34"
        valid = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 2, 0, 0)
        with mock.patch.object(healthcheck.os, "urandom", return_value=txid), \
                mock.patch.object(
                    healthcheck,
                    "socks_udp_exchange",
                    return_value=(valid, {"relay": "proxy.example:5000"}),
                ) as exchange:
            result = healthcheck.dns_probe("proxy", 1080, None, None, "1.1.1.1", 53, 3)
        self.assertEqual(result, "answers=2, relay=proxy.example:5000")
        query = exchange.call_args.args[6]
        self.assertEqual(query[:2], txid)
        self.assertIn(b"\x07example\x03com\x00", query)

        for response in (b"short", struct.pack("!HHHHHH", 0x9999, 0x8180, 1, 1, 0, 0), struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)):
            with self.subTest(response=response):
                with mock.patch.object(healthcheck.os, "urandom", return_value=txid), \
                        mock.patch.object(
                            healthcheck,
                            "socks_udp_exchange",
                            return_value=(response, {"relay": "relay"}),
                        ):
                    with self.assertRaises(RuntimeError):
                        healthcheck.dns_probe("proxy", 1080, None, None, "1.1.1.1", 53, 3)

    def test_parse_stun_mapped_handles_mapped_and_xor_mapped_ipv4(self) -> None:
        txid = b"t" * 12
        ip = "198.51.100.42"
        port = 54321
        mapped_value = b"\x00\x01" + struct.pack("!H", port) + socket.inet_aton(ip)
        mapped_attr = struct.pack("!HH", 0x0001, len(mapped_value)) + mapped_value
        mapped = struct.pack("!HHI", 0x0101, len(mapped_attr), 0x2112A442) + txid + mapped_attr
        self.assertEqual(healthcheck.parse_stun_mapped(mapped, txid), f"{ip}:{port}")

        encoded_port = port ^ 0x2112
        encoded_ip = int.from_bytes(socket.inet_aton(ip), "big") ^ 0x2112A442
        xor_value = b"\x00\x01" + struct.pack("!H", encoded_port) + encoded_ip.to_bytes(4, "big")
        xor_attr = struct.pack("!HH", 0x0020, len(xor_value)) + xor_value
        xor_response = struct.pack("!HHI", 0x0101, len(xor_attr), 0x2112A442) + txid + xor_attr
        self.assertEqual(healthcheck.parse_stun_mapped(xor_response, txid), f"{ip}:{port}")

    def test_parse_stun_mapped_rejects_bad_header_or_missing_ipv4_attribute(self) -> None:
        txid = b"t" * 12
        cases = (
            b"short",
            struct.pack("!HHI", 0x0102, 0, 0x2112A442) + txid,
            struct.pack("!HHI", 0x0101, 0, 0x2112A442) + txid,
        )
        for response in cases:
            with self.subTest(response=response):
                with self.assertRaises(RuntimeError):
                    healthcheck.parse_stun_mapped(response, txid)

    def test_stun_probe_uses_fallback_and_reports_all_failures(self) -> None:
        servers = [{"host": "first", "port": 3478}, {"host": "second", "port": 19302}]
        with mock.patch.object(healthcheck.os, "urandom", side_effect=[b"a" * 12, b"b" * 12]), \
                mock.patch.object(
                    healthcheck,
                    "socks_udp_exchange",
                    side_effect=[TimeoutError("first failed"), (b"response", {"relay": "relay:5000"})],
                ), \
                mock.patch.object(healthcheck, "parse_stun_mapped", return_value="203.0.113.1:50000"):
            self.assertEqual(
                healthcheck.stun_probe("proxy", 1080, None, None, servers, 2),
                "mapped=203.0.113.1:50000, relay=relay:5000",
            )

        with mock.patch.object(healthcheck, "socks_udp_exchange", side_effect=TimeoutError("failed")):
            with self.assertRaisesRegex(RuntimeError, "first:3478=TimeoutError, second:19302=TimeoutError"):
                healthcheck.stun_probe("proxy", 1080, None, None, servers, 2)


class ResultAndScopeTests(unittest.TestCase):
    def test_mapped_ip_extracts_stun_address(self) -> None:
        self.assertEqual(healthcheck.mapped_ip("mapped=203.0.113.5:1234, relay=proxy:5000"), "203.0.113.5")
        self.assertEqual(healthcheck.mapped_ip("answers=1"), "")

    def test_run_check_records_pass_mismatch_and_exception_without_raising(self) -> None:
        results: list[dict] = []
        with mock.patch.object(healthcheck.time, "monotonic", side_effect=[10.0, 10.0124]):
            healthcheck.run_check(results, "endpoint", "tcp", True, "203.0.113.1", lambda: " 203.0.113.1\n")
        self.assertEqual(results[0]["status"], "PASS")
        self.assertEqual(results[0]["detail"], " 203.0.113.1\n")
        self.assertEqual(results[0]["duration_ms"], 12)

        healthcheck.run_check(results, "endpoint", "tcp", True, "203.0.113.2", lambda: "203.0.113.1")
        self.assertEqual(results[1]["status"], "FAIL")
        self.assertIn("egress mismatch", results[1]["error"])

        healthcheck.run_check(results, "endpoint", "tcp", False, None, lambda: (_ for _ in ()).throw(OSError("down")))
        self.assertEqual(results[2]["status"], "FAIL")
        self.assertEqual(results[2]["error"], "OSError: down")

    def test_udp_stun_run_check_compares_only_mapped_ip(self) -> None:
        results: list[dict] = []
        healthcheck.run_check(
            results,
            "socks",
            "udp_stun",
            True,
            "203.0.113.9",
            lambda: "mapped=203.0.113.9:50000, relay=proxy:1234",
        )
        self.assertEqual(results[0]["status"], "PASS")

    def test_listener_probe_host_respects_loopback_scope_override_and_inheritance(self) -> None:
        public_ip = "203.0.113.10"
        self.assertEqual(
            healthcheck.listener_probe_host({"listen_ip": "127.0.0.1"}, "vm", public_ip, "0.0.0.0"),
            "127.0.0.1",
        )
        self.assertIsNone(
            healthcheck.listener_probe_host({"listen_ip": "::1"}, "e2e", public_ip, "0.0.0.0")
        )
        self.assertEqual(
            healthcheck.listener_probe_host({}, "vm", public_ip, "127.0.0.2"),
            "127.0.0.2",
        )
        for scope in ("vm", "e2e"):
            with self.subTest(scope=scope):
                self.assertEqual(
                    healthcheck.listener_probe_host({"listen_ip": "0.0.0.0"}, scope, public_ip, "127.0.0.1"),
                    public_ip,
                )

    def test_add_listener_na_emits_protocol_specific_checks(self) -> None:
        results: list[dict] = []
        healthcheck.add_listener_na(
            results,
            {"id": "socks", "protocol": "socks5", "capabilities": ["tcp", "udp"]},
        )
        healthcheck.add_listener_na(
            results,
            {"id": "socks_tcp", "protocol": "socks5", "capabilities": ["tcp"]},
        )
        healthcheck.add_listener_na(
            results,
            {"id": "http", "protocol": "http", "capabilities": ["tcp"]},
        )
        self.assertEqual(
            [(item["endpoint"], item["check"], item["status"], item["required"]) for item in results],
            [
                ("socks", "tcp", "N/A", False),
                ("socks", "udp_dns", "N/A", False),
                ("socks", "udp_stun", "N/A", False),
                ("socks_tcp", "tcp", "N/A", False),
                ("socks_tcp", "udp", "N/A", False),
                ("http", "http_get", "N/A", False),
                ("http", "http_connect", "N/A", False),
            ],
        )


class MainTests(HealthcheckMainMixin, unittest.TestCase):
    def test_e2e_scope_marks_loopback_listener_na_without_network_calls(self) -> None:
        config = make_health_config()
        config["listeners"] = [
            {
                "id": "socks_direct",
                "protocol": "socks5",
                "port": 1080,
                "parent": "direct",
                "listen_ip": "127.0.0.1",
                "capabilities": ["tcp", "udp"],
            }
        ]
        with mock.patch.object(healthcheck, "socks_tcp") as tcp, \
                mock.patch.object(healthcheck, "dns_probe") as dns, \
                mock.patch.object(healthcheck, "stun_probe") as stun:
            result, output = self.invoke(config, "--scope", "e2e")
        self.assertEqual(result, 0)
        tcp.assert_not_called()
        dns.assert_not_called()
        stun.assert_not_called()
        self.assertEqual(output.count("N/A"), 3)
        self.assertIn("SUMMARY endpoints=1 passed=0 failed=0 n/a=3", output)

    def test_vm_scope_probes_loopback_listener_with_strong_auth(self) -> None:
        config = make_health_config()
        config["listeners"] = [
            {
                "id": "socks_direct",
                "protocol": "socks5",
                "port": 1080,
                "parent": "direct",
                "listen_ip": "127.0.0.1",
                "capabilities": ["tcp", "udp"],
            }
        ]
        with mock.patch.object(healthcheck, "socks_tcp", return_value="203.0.113.10") as tcp, \
                mock.patch.object(healthcheck, "dns_probe", return_value="answers=1, relay=127.0.0.1:5000") as dns, \
                mock.patch.object(
                    healthcheck,
                    "stun_probe",
                    return_value="mapped=203.0.113.10:50000, relay=127.0.0.1:5000",
                ) as stun:
            result, output = self.invoke(config, "--scope", "vm", "--timeout", "3")
        self.assertEqual(result, 0)
        tcp.assert_called_once_with(
            "127.0.0.1", 1080, "local-user", "local-password", "api.ipify.org", 80, 3.0
        )
        dns.assert_called_once_with(
            "127.0.0.1", 1080, "local-user", "local-password", "1.1.1.1", 53, 3.0
        )
        stun.assert_called_once_with(
            "127.0.0.1",
            1080,
            "local-user",
            "local-password",
            config["probes"]["stun_servers"],
            3.0,
        )
        self.assertIn("SUMMARY endpoints=1 passed=3 failed=0 n/a=0", output)

    def test_iponly_listener_uses_noauth_and_https_parent_expected_egress(self) -> None:
        config = make_health_config(mode="iponly")
        config["upstreams"]["https_primary"] = {
            "type": "https",
            "host": "secure.example",
            "port": 8443,
            "tls_server_name": "secure.example",
            "expected_egress_ip": "198.51.100.20",
        }
        config["listeners"] = [
            {
                "id": "http_via_https",
                "protocol": "http",
                "port": 8083,
                "parent": "https_primary",
                "capabilities": ["tcp"],
            }
        ]
        with mock.patch.object(healthcheck, "http_get", return_value="198.51.100.20") as get, \
                mock.patch.object(healthcheck, "http_connect", return_value="198.51.100.20") as connect:
            result, _ = self.invoke(config, "--endpoint", "http_via_https")
        self.assertEqual(result, 0)
        get.assert_called_once_with(
            "203.0.113.10", 8083, None, None, "api.ipify.org", 80, 8.0
        )
        connect.assert_called_once_with(
            "203.0.113.10", 8083, None, None, "api.ipify.org", 80, 8.0
        )

    def test_multiple_generic_listeners_share_https_parent_without_udp_probe(self) -> None:
        config = make_health_config()
        config["tls"] = {"client_ca_file": "/opt/ca/proxy.pem"}
        config["upstreams"]["https_primary"] = {
            "type": "https",
            "host": "192.0.2.30",
            "port": 8443,
            "username": "upstream-user",
            "password": "upstream-password",
            "tls_server_name": "secure.example.test",
            "expected_egress_ip": "198.51.100.30",
            "capabilities": ["tcp"],
        }
        config["listeners"] = [
            {
                "id": "secure-egress.alpha",
                "protocol": "socks5",
                "port": 11080,
                "parent": "https_primary",
                "capabilities": ["tcp"],
            },
            {
                "id": "secure-egress.beta",
                "protocol": "http",
                "port": 18080,
                "parent": "https_primary",
                "capabilities": ["tcp"],
            },
        ]
        with mock.patch.object(healthcheck, "socks_tcp", return_value="198.51.100.30") as tcp, \
                mock.patch.object(healthcheck, "dns_probe") as dns, \
                mock.patch.object(healthcheck, "stun_probe") as stun, \
                mock.patch.object(healthcheck, "http_get", return_value="198.51.100.30") as get, \
                mock.patch.object(healthcheck, "http_connect", return_value="198.51.100.30") as connect:
            result, output = self.invoke(config)
        self.assertEqual(result, 0)
        tcp.assert_called_once_with(
            "203.0.113.10",
            11080,
            "local-user",
            "local-password",
            "api.ipify.org",
            80,
            8.0,
        )
        dns.assert_not_called()
        stun.assert_not_called()
        self.assertEqual(get.call_count, 2)
        self.assertEqual(connect.call_count, 2)
        self.assertIn("secure-egress.alpha", output)
        self.assertIn("secure-egress.beta", output)
        self.assertIn("upstream_https_primary", output)
        self.assertIn("SUMMARY endpoints=3 passed=5 failed=0 n/a=1", output)

    def test_tcp_only_socks_upstream_skips_udp_probes(self) -> None:
        config = make_health_config()
        config["upstreams"]["socks_primary"] = {
            "type": "socks5",
            "host": "socks.example.test",
            "port": 1080,
            "username": "upstream-user",
            "password": "upstream-password",
            "expected_egress_ip": "198.51.100.60",
            "capabilities": ["tcp"],
        }
        with mock.patch.object(healthcheck, "socks_tcp", return_value="198.51.100.60") as tcp, \
                mock.patch.object(healthcheck, "dns_probe") as dns, \
                mock.patch.object(healthcheck, "stun_probe") as stun:
            result, output = self.invoke(config, "--endpoint", "upstream_socks_primary")
        self.assertEqual(result, 0)
        tcp.assert_called_once_with(
            "socks.example.test",
            1080,
            "upstream-user",
            "upstream-password",
            "api.ipify.org",
            80,
            8.0,
        )
        dns.assert_not_called()
        stun.assert_not_called()
        self.assertIn("not advertised by this SOCKS5 upstream", output)
        self.assertIn("SUMMARY endpoints=1 passed=1 failed=0 n/a=1", output)

    def test_udp_capable_socks_upstream_keeps_dns_and_stun_probes(self) -> None:
        config = make_health_config()
        config["upstreams"]["socks_primary"] = {
            "type": "socks5",
            "host": "socks.example.test",
            "port": 1080,
            "expected_egress_ip": "198.51.100.61",
            "capabilities": ["tcp", "udp"],
        }
        with mock.patch.object(healthcheck, "socks_tcp", return_value="198.51.100.61") as tcp, \
                mock.patch.object(
                    healthcheck,
                    "dns_probe",
                    return_value="answers=1, relay=socks.example.test:5000",
                ) as dns, \
                mock.patch.object(
                    healthcheck,
                    "stun_probe",
                    return_value="mapped=198.51.100.61:50000, relay=socks.example.test:5000",
                ) as stun:
            result, output = self.invoke(config, "--endpoint", "upstream_socks_primary")
        self.assertEqual(result, 0)
        tcp.assert_called_once()
        dns.assert_called_once_with(
            "socks.example.test", 1080, None, None, "1.1.1.1", 53, 8.0
        )
        stun.assert_called_once_with(
            "socks.example.test",
            1080,
            None,
            None,
            config["probes"]["stun_servers"],
            8.0,
        )
        self.assertIn("SUMMARY endpoints=1 passed=3 failed=0 n/a=0", output)

    def test_https_upstream_healthcheck_passes_auth_sni_ca_and_tls_check_names(self) -> None:
        config = make_health_config()
        config["tls"] = {"client_ca_file": "/opt/ca/proxy.pem"}
        config["upstreams"]["https_primary"] = {
            "type": "https",
            "host": "192.0.2.30",
            "port": 8443,
            "username": "upstream-user",
            "password": "upstream-password",
            "tls_server_name": "secure.example.test",
            "expected_egress_ip": "198.51.100.30",
        }
        with mock.patch.object(healthcheck, "http_get", return_value="198.51.100.30") as get, \
                mock.patch.object(healthcheck, "http_connect", return_value="198.51.100.30") as connect:
            result, output = self.invoke(config, "--endpoint", "upstream_https_primary")
        self.assertEqual(result, 0)
        get.assert_called_once_with(
            "192.0.2.30",
            8443,
            "upstream-user",
            "upstream-password",
            "api.ipify.org",
            80,
            8.0,
            tls_server_name="secure.example.test",
            ca_file="/opt/ca/proxy.pem",
        )
        connect.assert_called_once_with(
            "192.0.2.30",
            8443,
            "upstream-user",
            "upstream-password",
            "api.ipify.org",
            80,
            8.0,
            tls_server_name="secure.example.test",
            ca_file="/opt/ca/proxy.pem",
        )
        self.assertIn("https_get", output)
        self.assertIn("https_connect", output)
        self.assertIn("SUMMARY endpoints=1 passed=2 failed=0 n/a=0", output)

    def test_https_upstream_supports_noauth_and_default_system_ca(self) -> None:
        config = make_health_config()
        config["upstreams"]["https_primary"] = {
            "type": "https",
            "host": "secure.example.test",
            "port": 443,
            "tls_server_name": "secure.example.test",
            "expected_egress_ip": "198.51.100.40",
        }
        with mock.patch.object(healthcheck, "http_get", return_value="198.51.100.40") as get, \
                mock.patch.object(healthcheck, "http_connect", return_value="198.51.100.40"):
            result, _ = self.invoke(config)
        self.assertEqual(result, 0)
        self.assertEqual(get.call_args.args[2:4], (None, None))
        self.assertEqual(get.call_args.kwargs, {"tls_server_name": "secure.example.test", "ca_file": None})

    def test_required_failure_sets_exit_code_and_json_summary(self) -> None:
        config = make_health_config()
        config["listeners"] = [
            {
                "id": "http_direct",
                "protocol": "http",
                "port": 8080,
                "parent": "direct",
                "capabilities": ["tcp"],
            }
        ]
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "nested" / "report.json"
            with mock.patch.object(healthcheck, "http_get", side_effect=OSError("connection refused")), \
                    mock.patch.object(healthcheck, "http_connect", return_value="203.0.113.10"):
                result, output = self.invoke(config, "--json", str(report))
            payload = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual(result, 1)
        self.assertIn("SUMMARY endpoints=1 passed=1 failed=1 n/a=0", output)
        self.assertEqual(payload["scope"], "e2e")
        self.assertEqual(payload["failed"], 1)
        self.assertEqual(payload["passed"], 1)
        self.assertEqual(payload["results"][0]["error"], "OSError: connection refused")

    def test_endpoint_filter_limits_listener_and_upstream_probes(self) -> None:
        config = make_health_config()
        config["listeners"] = [
            {
                "id": "http_direct",
                "protocol": "http",
                "port": 8080,
                "parent": "direct",
                "capabilities": ["tcp"],
            }
        ]
        config["upstreams"]["http_primary"] = {
            "type": "http",
            "host": "proxy.example",
            "port": 3128,
            "expected_egress_ip": "198.51.100.50",
        }
        with mock.patch.object(healthcheck, "http_get", return_value="198.51.100.50") as get, \
                mock.patch.object(healthcheck, "http_connect", return_value="198.51.100.50") as connect:
            result, output = self.invoke(config, "--endpoint", "upstream_http_primary")
        self.assertEqual(result, 0)
        self.assertEqual(get.call_args.args[:2], ("proxy.example", 3128))
        self.assertEqual(connect.call_args.args[:2], ("proxy.example", 3128))
        self.assertNotIn("http_direct", output)
        self.assertIn("SUMMARY endpoints=1 passed=2 failed=0 n/a=0", output)


class LoadConfigTests(unittest.TestCase):
    def test_load_config_reads_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "health.yaml"
            path.write_text(yaml.safe_dump({"server": {"public_ip": "203.0.113.1"}}), encoding="utf-8")
            self.assertEqual(healthcheck.load_config(path)["server"]["public_ip"], "203.0.113.1")


if __name__ == "__main__":
    unittest.main()
