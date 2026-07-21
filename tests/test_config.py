from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import config as config_tool  # noqa: E402
import healthcheck  # noqa: E402


class FakeSocket:
    def __init__(self, response: bytes) -> None:
        self.response = bytearray(response)
        self.sent = bytearray()

    def sendall(self, payload: bytes) -> None:
        self.sent.extend(payload)

    def recv(self, size: int) -> bytes:
        payload = bytes(self.response[:size])
        del self.response[:size]
        return payload


class ConfigTests(unittest.TestCase):
    def test_existing_strong_topology_is_compatible(self) -> None:
        data = config_tool.load_config(ROOT / "config.example.yaml")
        config_tool.validate(data)
        rendered = config_tool.render_3proxy(data)
        self.assertIn("auth strong", rendered)
        self.assertIn("users CHANGE_ME:CL:CHANGE_ME", rendered)
        self.assertEqual(rendered.count("\nflush\n"), 6)

    def test_iponly_profile_has_two_passwordless_listeners(self) -> None:
        data = config_tool.load_config(ROOT / "config.iponly.example.yaml")
        config_tool.validate(data)
        rendered = config_tool.render_3proxy(data)
        self.assertNotIn("users ", rendered)
        self.assertNotIn(":CL:", rendered)
        self.assertNotIn("auth strong", rendered)
        self.assertEqual(rendered.count("auth iponly"), 2)
        self.assertEqual(rendered.count("allow * 198.51.100.25/32"), 2)
        self.assertEqual(rendered.count("deny *"), 2)
        self.assertIn("socks -i0.0.0.0 -p1080 -Ni203.0.113.10", rendered)
        self.assertIn("proxy -i0.0.0.0 -p8080", rendered)

    def test_iponly_rejects_open_network(self) -> None:
        data = config_tool.load_config(ROOT / "config.iponly.example.yaml")
        data = copy.deepcopy(data)
        data["access"]["allowed_client_cidrs"] = ["0.0.0.0/0"]
        with self.assertRaisesRegex(ValueError, "open /0"):
            config_tool.validate(data)

    def test_listener_requires_its_upstream(self) -> None:
        data = config_tool.load_config(ROOT / "config.example.yaml")
        data = copy.deepcopy(data)
        del data["upstreams"]["socks_primary"]
        with self.assertRaisesRegex(ValueError, "undefined upstream"):
            config_tool.validate(data)


class NoAuthHealthcheckTests(unittest.TestCase):
    def test_socks_no_auth_negotiation(self) -> None:
        sock = FakeSocket(b"\x05\x00")
        healthcheck.socks_auth(sock, None, None)
        self.assertEqual(bytes(sock.sent), b"\x05\x01\x00")

    def test_http_no_auth_header(self) -> None:
        self.assertEqual(healthcheck.proxy_authorization(None, None), "")
        header = healthcheck.proxy_authorization("alice", "secret")
        self.assertTrue(header.startswith("Proxy-Authorization: Basic "))


if __name__ == "__main__":
    unittest.main()
