from __future__ import annotations
import copy
import unittest
from unittest import mock

from test_schema_v2 import profile
import addressing
import config
import upstream_resolution as resolution


def with_parent():
    data = profile()
    data["upstreams"]["https_primary"] = dict(type="https", host="parent.example.test", port=443,
        tls_server_name="certificate.example.test", resolve_family="ipv6", capabilities=["tcp"],
        username="test-user", password="test-password")
    data["listeners"][0]["parent"] = "https_primary"
    data["probes"]["egress"]["https_primary"] = data["probes"]["egress"].pop("direct")
    return data


class ParentResolutionTests(unittest.TestCase):
    def test_ipv6_transport_preserves_separate_parent_tls_identity(self):
        data = with_parent(); config.validate(data)
        with mock.patch.object(addressing, "resolve", return_value=(addressing.ResolvedAddress("ipv6", "2001:db8::2"),)):
            snapshot = resolution.create(data)
        addresses = resolution.validate(data, snapshot)
        text = config.render_3proxy(data, addresses)
        self.assertIn("parent 1000 connect+s 2001:db8::2 443", text)
        self.assertIn("ssl_client_sni certificate.example.test", text)
        self.assertNotIn("parent.example.test", text)
        self.assertEqual(data["upstreams"]["https_primary"]["host"], "parent.example.test")
        self.assertNotIn("password", str(snapshot))

    def test_changed_dns_policy_cannot_reuse_stale_snapshot(self):
        data = with_parent()
        with mock.patch.object(addressing, "resolve", return_value=(addressing.ResolvedAddress("ipv6", "2001:db8::2"),)):
            snapshot = resolution.create(data)
        data["upstreams"]["https_primary"]["host"] = "different.example.test"
        with self.assertRaisesRegex(ValueError, "different routing policy"):
            resolution.validate(data, snapshot)

    def test_parent_address_resolution_does_not_fall_back_to_direct(self):
        data = with_parent()
        with mock.patch.object(addressing, "resolve", side_effect=ValueError("no AAAA")):
            with self.assertRaisesRegex(ValueError, "cannot resolve"):
                resolution.create(data)
        with self.assertRaisesRegex(ValueError, "snapshot"):
            config.render_3proxy(data)

    def test_preference_only_falls_back_between_same_parent_dns_families(self):
        data = with_parent(); parent = data["upstreams"]["https_primary"]
        parent["resolve_family"] = "prefer_ipv6"
        with mock.patch.object(addressing, "resolve", side_effect=[ValueError("no AAAA"),
                (addressing.ResolvedAddress("ipv4", "192.0.2.2"),)]) as lookup:
            self.assertEqual(resolution.resolve_parent(parent), "192.0.2.2")
        self.assertEqual([c.args[2] for c in lookup.call_args_list], [["ipv6"], ["ipv4"]])
        self.assertTrue(all(c.args[0] == "parent.example.test" for c in lookup.call_args_list))

    def test_wrong_family_or_changed_literal_in_snapshot_is_rejected(self):
        data = with_parent()
        snapshot = dict(schema=1, policy_key=resolution.policy_key(data), addresses={"https_primary": "192.0.2.2"})
        with self.assertRaisesRegex(ValueError, "family"): resolution.validate(data, snapshot)
        data["upstreams"]["https_primary"]["host"] = "2001:db8::1"
        snapshot.update(policy_key=resolution.policy_key(data), addresses={"https_primary": "2001:db8::2"})
        with self.assertRaisesRegex(ValueError, "literal"): resolution.validate(data, snapshot)
