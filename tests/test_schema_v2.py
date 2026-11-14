from __future__ import annotations
import copy
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import config
import schema_v2 as schema


def profile():
    return {
        "schema_version": 2, "instance": {"id": "dev"},
        "install": {"version": config.INSTALL_VERSION, "source_url": config.INSTALL_SOURCE_URL, "sha256": config.INSTALL_SHA256},
        "server": {"manage_ufw": False},
        "access": {"mode": "strong"},
        "local_auth": {"username": "test-user", "password": "test-password"},
        "upstreams": {},
        "listeners": [{"id": "https", "protocol": "https", "port": 28443, "bind": ["::"],
                       "accept_families": ["ipv4", "ipv6"], "endpoint": {"host": "proxy.example.test", "families": ["ipv4", "ipv6"]},
                       "tls_certificate": "dns", "parent": "direct", "outbound": {"family": "ipv4"}, "capabilities": ["tcp"]}],
        "tls": {"certificates": {"dns": {"mode": "acme", "identifiers": ["proxy.example.test"],
                                          "acme": {"agree_tos": True}}}},
        "probes": {"timeout_seconds": 8, "http_host": "probe.example.test", "http_port": 80,
                   "egress": {"direct": {"ipv4": {"expected_ips": ["192.0.2.1"]}}}},
    }


class SchemaTests(unittest.TestCase):
    def test_input_is_not_mutated_or_dns_pinned_by_validation(self):
        data = profile(); before = copy.deepcopy(data)
        config.validate(data)
        self.assertEqual(data, before)
        self.assertNotIn("public_ip", data["server"])
        self.assertEqual(schema.tls_identity(data, data["listeners"][0]), "proxy.example.test")

    def test_mixed_legacy_roles_and_unsupported_fields_are_rejected(self):
        for section, key, value in [("server", "public_ip", "192.0.2.1"), ("tls", "server", {}),
                                    ("server", "listen_ip", "0.0.0.0"), ("probes", "typo", True)]:
            data = profile(); data[section][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "unsupported"):
                config.validate(data)

    def test_render_preserves_dns_certificate_and_independent_ipv4_egress(self):
        text = config.render_3proxy(profile())
        self.assertIn("proxy -i:: -p28443 -4", text)
        self.assertIn("/instances/dev/tls/dns/server.crt", text)
        self.assertIn("auth strong", text)
        self.assertNotIn("parent ", text)

    def test_distinct_bind_addresses_share_port_and_cert_but_overlap_is_rejected(self):
        data = profile()
        data["listeners"][0]["bind"] = ["192.0.2.1", "2001:db8::1"]
        config.validate(data)
        text = config.render_3proxy(data)
        self.assertIn("proxy -i192.0.2.1 -p28443 -4", text)
        self.assertIn("proxy -i2001:db8::1 -p28443 -4", text)
        data["listeners"][0]["bind"] = ["0.0.0.0", "::"]
        with self.assertRaisesRegex(ValueError, "overlapping"):
            config.validate(data)

    def test_endpoint_certificate_mismatch_and_unused_certificate_are_rejected(self):
        data = profile(); data["listeners"][0]["endpoint"]["host"] = "wrong.example.test"
        with self.assertRaisesRegex(ValueError, "certificate identifiers"): config.validate(data)
        data = profile(); data["tls"]["certificates"]["unused"] = copy.deepcopy(data["tls"]["certificates"]["dns"])
        with self.assertRaisesRegex(ValueError, "must be used"): config.validate(data)

    def test_ipv6_bind_does_not_enable_ipv6_egress_implicitly(self):
        data = profile(); data["listeners"][0]["outbound"]["family"] = "prefer_ipv6"
        with self.assertRaisesRegex(ValueError, "every configured outbound family"): config.validate(data)
        data["probes"]["egress"]["direct"]["ipv6"] = {"expected_ips": ["2001:db8::1"]}
        config.validate(data)
        self.assertIn("-64", config.render_3proxy(data))

    def test_ipv6_acl_supported_without_open_network(self):
        data = profile(); data["access"] = {"mode": "iponly", "allowed_client_cidrs": ["2001:db8:1::/64"]}
        data.pop("local_auth")
        config.validate(data)
        self.assertIn("allow * 2001:db8:1::/64", config.render_3proxy(data))
        self.assertIn("deny *", config.render_3proxy(data))
        data["access"]["allowed_client_cidrs"] = ["::/0"]
        with self.assertRaises(ValueError): config.validate(data)

    def test_mapped_ipv4_acl_is_normalized_and_ipv6_acl_cannot_grant_ipv4(self):
        data = profile()
        data["access"] = dict(mode="iponly", allowed_client_cidrs=["::/1", "192.0.2.0/24", "::ffff:198.51.100.1/128"])
        config.validate(data)
        text = config.render_3proxy(data)
        self.assertIn("allow * ::ffff:c000:200/120", text)
        self.assertIn("allow * ::ffff:c633:6401/128", text)
        self.assertLess(text.index("allow * ::ffff:c000:200/120"), text.index("deny * ::ffff:0:0/96"))
        self.assertLess(text.index("deny * ::ffff:0:0/96"), text.index("allow * ::/1"))
        data["access"]["allowed_client_cidrs"] = ["::ffff:0:0/96"]
        with self.assertRaisesRegex(ValueError, "open /0"):
            config.validate(data)

    def test_ipv6_udp_is_explicitly_rejected(self):
        data = profile(); data["listeners"][0]["capabilities"] = ["tcp", "udp"]
        with self.assertRaisesRegex(ValueError, "IPv6 UDP"): config.validate(data)

    def test_ipv4_udp_requires_a_family_correct_firewall_source(self):
        data = profile(); data.pop("tls")
        listener = data["listeners"][0]
        listener.update(protocol="socks5", bind=["0.0.0.0"], accept_families=["ipv4"], capabilities=["tcp", "udp"])
        listener.pop("tls_certificate")
        listener["endpoint"] = dict(host="192.0.2.1", families=["ipv4"])
        data["server"]["udp_public_ip"] = "192.0.2.1"
        with self.assertRaisesRegex(ValueError, "udp_client_cidr"): config.validate(data)
        data["server"]["udp_client_cidr"] = "2001:db8::/32"
        with self.assertRaisesRegex(ValueError, "IPv4 udp_client_cidr"): config.validate(data)
        data["server"]["udp_client_cidr"] = "192.0.2.0/24"
        config.validate(data)

    def test_two_certificates_render_before_their_own_listener(self):
        data = profile(); second = copy.deepcopy(data["listeners"][0])
        second.update(id="https-other", port=28444, tls_certificate="other")
        second["endpoint"]["host"] = "other.example.test"
        data["listeners"].append(second)
        data["tls"]["certificates"]["other"] = {"mode": "acme", "identifiers": ["other.example.test"], "acme": {"agree_tos": True}}
        config.validate(data)
        text = config.render_3proxy(data)
        first = text.index("tls/dns/server.crt"); first_socket = text.index("-p28443")
        second = text.index("tls/other/server.crt"); second_socket = text.index("-p28444")
        self.assertLess(first, first_socket); self.assertLess(first_socket, second); self.assertLess(second, second_socket)
