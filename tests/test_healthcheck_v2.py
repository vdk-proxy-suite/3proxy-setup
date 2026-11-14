from __future__ import annotations
import argparse
import copy
import io
import socket
from contextlib import redirect_stdout
from types import SimpleNamespace
import unittest
from unittest import mock

from test_schema_v2 import profile
import addressing
import healthcheck_v2 as checks


class TransportTests(unittest.TestCase):
    def test_socks_deferred_auth_requires_connect_denial(self):
        for wrong in (False, True):
            responses = ([b"\x05\x02", b"\x01\x00"] if wrong else [b"\x05\x00"])
            responses += [b"\x05\x02\x00\x01", b"\x00" * 4, b"\x00" * 2]
            sock = mock.MagicMock()
            sock.__enter__.return_value = sock
            sock.recv.side_effect = responses
            with self.subTest(wrong=wrong), mock.patch.object(checks.wire, "open_proxy_connection", return_value=sock):
                self.assertIn("rejected", checks.auth_rejected("socks5", "127.0.0.1", 1080, 1, wrong=wrong, tls={}))
            self.assertTrue(sock.sendall.call_args.args[0].startswith(b"\x05\x01\x00\x01"))

    def test_socks_success_or_network_error_is_not_auth_denial(self):
        for status in (0, 1, 3, 4, 5, 7, 8):
            sock = mock.MagicMock(); sock.__enter__.return_value = sock
            sock.recv.side_effect = [b"\x05\x02", b"\x01\x00", bytes([5, status, 0, 1])]
            with self.subTest(status=status), mock.patch.object(checks.wire, "open_proxy_connection", return_value=sock):
                with self.assertRaisesRegex(ValueError, "CONNECT"):
                    checks.auth_rejected("socks5", "127.0.0.1", 1080, 1, wrong=True, tls={})

    def test_socks_immediate_auth_rejection_remains_supported(self):
        for responses in ([b"\x05\xff"], [b"\x05\x02", b"\x01\x01"]):
            sock = mock.MagicMock(); sock.__enter__.return_value = sock; sock.recv.side_effect = responses
            with mock.patch.object(checks.wire, "open_proxy_connection", return_value=sock):
                self.assertIn("rejected", checks.auth_rejected("socks5", "127.0.0.1", 1080, 1, wrong=True, tls={}))
            self.assertFalse(any(call.args[0].startswith(b"\x05\x01\x00\x01") for call in sock.sendall.call_args_list))

    def test_vm_dualstack_checks_both_loopbacks_without_dns(self):
        data = profile()
        with mock.patch.object(addressing, "resolve") as lookup:
            ips = checks.transport_addresses(data, data["listeners"][0], "vm")
        self.assertEqual([ip.ip for ip in ips], ["127.0.0.1", "::1"])
        lookup.assert_not_called()

    def test_dns_e2e_checks_all_required_families_and_never_rewrites_tls_identity(self):
        data = profile(); listener = data["listeners"][0]
        with mock.patch.object(addressing, "resolve", return_value=(addressing.ResolvedAddress("ipv6", "2001:db8::1"),)) as lookup:
            checks.transport_addresses(data, listener, "e2e")
        lookup.assert_called_once_with("proxy.example.test", 28443, ["ipv4", "ipv6"])
        self.assertEqual(checks.tls_options(data, listener, "e2e", None), dict(tls_server_name="proxy.example.test", ca_file=None))

    def test_staging_and_managed_e2e_require_explicit_client_trust(self):
        for mode in ("managed", "acme"):
            data = profile(); cert = data["tls"]["certificates"]["dns"]
            cert["mode"] = mode
            cert["acme"]["environment"] = "staging"
            with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, "proxy-ca-file"):
                checks.tls_options(data, data["listeners"][0], "e2e", None)

    def test_socks_literal_address_framing_does_not_send_ipv6_as_hostname(self):
        sock = mock.Mock()
        with mock.patch.object(checks.wire, "read_socks_reply"):
            checks.socks_connect(sock, "::1", 80)
        self.assertEqual(sock.sendall.call_args.args[0], b"\x05\x01\x00\x04" + b"\x00" * 15 + b"\x01\x00\x50")

    def test_failure_in_one_family_makes_overall_report_fail(self):
        data = profile()
        args = SimpleNamespace(endpoint=None, proxy_ca_file=None, scope="e2e", timeout=1, tls_gate_only=True, json=None, skip_upstreams=True)
        addresses = (addressing.ResolvedAddress("ipv4", "192.0.2.1"), addressing.ResolvedAddress("ipv6", "2001:db8::1"))
        with mock.patch.object(checks, "transport_addresses", return_value=addresses), \
             mock.patch.object(checks, "tls_probe", side_effect=["v4 valid", ConnectionError("v6 broken")]), \
             mock.patch.object(checks.wire, "plaintext_proxy_rejected", return_value="rejected"), \
             redirect_stdout(io.StringIO()) as output:
            status = checks.run(data, args, argparse.ArgumentParser())
        self.assertEqual(status, 1)
        self.assertIn("ipv6", output.getvalue())
        self.assertIn("v6 broken", output.getvalue())

    def test_egress_compare_is_independent_of_transport_and_records_family(self):
        results = []
        checks.check(results, profile()["listeners"][0], "http_connect", lambda: "192.0.2.1",
                     dict(address_family="ipv6", egress_family="ipv4"), ["192.0.2.1"])
        self.assertEqual(results[0]["status"], "PASS")
        self.assertEqual(results[0]["address_family"], "ipv6")
        self.assertEqual(results[0]["actual_egress"], "192.0.2.1")
        checks.check(results, profile()["listeners"][0], "http_connect", lambda: "192.0.2.2", {}, ["192.0.2.1"])
        self.assertEqual(results[1]["status"], "FAIL")
