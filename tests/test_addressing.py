from __future__ import annotations
import socket
import sys
from pathlib import Path
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import addressing as a


class IdentityTests(unittest.TestCase):
    def test_certificate_type_is_not_derived_from_dns(self):
        self.assertEqual(a.identity("PROXY.Example.").acme_args(), ["-d", "proxy.example"])
        self.assertEqual(a.identity("2001:0DB8:0:0::10").acme_args(), ["--ip-address", "2001:db8::10"])
        self.assertEqual(a.identity("203.0.113.10").verify_args(), ["-verify_ip", "203.0.113.10"])
        self.assertEqual(a.identity("proxy.example").verify_args(), ["-verify_hostname", "proxy.example"])
        self.assertEqual(a.identity("пример.рф").value, "xn--e1afmkfd.xn--p1ai")

    def test_invalid_identity_cannot_become_a_dns_request(self):
        for value in [None, "", " a.test", "a.test\n", "https://a.test", "a.test:80", "[::1]",
                      "fe80::1%eth0", "*.example", "999.1.2.3", "01.2.3.4", "a..test", "a.test..",
                      "a_test", "user@host", "::ffff:192.0.2.1", "-option", "a" * 64 + ".test"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                a.identity(value)

    def test_identity_sets_normalize_order_and_ipv6_spelling(self):
        expected = a.identities(["2001:db8::1", "a.test"])
        self.assertEqual(a.identities(["A.test", "2001:0db8:0:0:0:0:0:1", "a.test."]), expected)
        self.assertEqual(a.normalized_sans([("IP Address", "2001:DB8:0:0:0:0:0:1"), ("DNS", "A.TEST")]), set(expected))

    def test_ipv6_authority_and_bind_validation(self):
        self.assertEqual(a.authority("2001:db8::1", 443), "[2001:db8::1]:443")
        self.assertEqual(a.authority("a.test", 443), "a.test:443")
        with self.assertRaises(ValueError): a.literal("a.test")
        with self.assertRaises(ValueError): a.authority("::1", True)

    def test_overlap_accounts_for_dualstack_and_exact_interfaces(self):
        self.assertTrue(a.overlaps("::", "0.0.0.0"))
        self.assertTrue(a.overlaps("::", "192.0.2.1"))
        self.assertFalse(a.overlaps("::", "0.0.0.0", ipv6_dualstack=False))
        self.assertFalse(a.overlaps("2001:db8::1", "192.0.2.1"))
        self.assertFalse(a.overlaps("2001:db8::1", "2001:db8::2"))
        self.assertTrue(a.overlaps("0.0.0.0", "192.0.2.1"))


class ResolutionTests(unittest.TestCase):
    @staticmethod
    def row(ip, family):
        return (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, 443))

    def test_all_addresses_and_both_families_are_returned_without_changing_identity(self):
        resolver = Mock(side_effect=[
            [self.row("192.0.2.2", socket.AF_INET), self.row("192.0.2.1", socket.AF_INET)],
            [self.row("2001:db8::1", socket.AF_INET6)]])
        result = a.resolve("PROXY.example", 443, ["ipv4", "ipv6"], resolver=resolver)
        self.assertEqual([x.ip for x in result], ["192.0.2.1", "192.0.2.2", "2001:db8::1"])
        self.assertEqual([c.args[2] for c in resolver.call_args_list], [socket.AF_INET, socket.AF_INET6])

    def test_broken_ipv6_cannot_be_hidden_by_working_ipv4(self):
        for failure in [socket.gaierror("missing AAAA"), []]:
            resolver = Mock(side_effect=[[self.row("192.0.2.1", socket.AF_INET)], failure])
            with self.subTest(failure=failure), self.assertRaisesRegex(ValueError, "ipv6"):
                a.resolve("proxy.example", 443, ["ipv4", "ipv6"], resolver=resolver)

    def test_literal_does_not_use_dns_or_claim_other_family(self):
        resolver = Mock()
        self.assertEqual(a.resolve("::1", 443, ["ipv6"], resolver=resolver)[0].ip, "::1")
        resolver.assert_not_called()
        with self.assertRaises(ValueError): a.resolve("::1", 443, ["ipv4", "ipv6"])

    def test_wrong_family_from_resolver_is_rejected(self):
        resolver = Mock(return_value=[self.row("192.0.2.1", socket.AF_INET)])
        with self.assertRaises(ValueError): a.resolve("proxy.example", 443, ["ipv6"], resolver=resolver)
