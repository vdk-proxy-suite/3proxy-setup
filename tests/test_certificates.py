from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import certificates  # noqa: E402


class ManagedCertificateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.data = {
            "server": {"public_ip": "203.0.113.10"},
            "tls": {
                "server": {
                    "dns_names": ["Proxy.Example.Test", "alt.example.test"],
                }
            },
        }

    def test_exact_ip_and_case_insensitive_dns_sans_match(self) -> None:
        with mock.patch.object(
            certificates,
            "certificate_sans",
            return_value=(
                {"203.0.113.10"},
                {"proxy.example.test", "alt.example.test"},
            ),
        ):
            self.assertTrue(certificates.sans_match(Path("unused.crt"), self.data))

    def test_missing_or_extra_sans_do_not_match(self) -> None:
        cases = (
            ({"203.0.113.11"}, {"proxy.example.test", "alt.example.test"}),
            ({"203.0.113.10"}, {"proxy.example.test"}),
            (
                {"203.0.113.10"},
                {"proxy.example.test", "alt.example.test", "extra.example.test"},
            ),
            ({"203.0.113.10", "203.0.113.11"}, {"proxy.example.test", "alt.example.test"}),
        )
        for actual_ips, actual_dns in cases:
            with self.subTest(actual_ips=actual_ips, actual_dns=actual_dns), mock.patch.object(
                certificates,
                "certificate_sans",
                return_value=(actual_ips, actual_dns),
            ):
                self.assertFalse(certificates.sans_match(Path("unused.crt"), self.data))

    def test_tls_server_is_required(self) -> None:
        with self.assertRaisesRegex(ValueError, "tls.server is required"):
            certificates.sans_match(
                Path("unused.crt"),
                {"server": {"public_ip": "203.0.113.10"}, "tls": {}},
            )


if __name__ == "__main__":
    unittest.main()
