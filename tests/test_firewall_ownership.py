import copy
import contextlib
import io
import subprocess
import unittest
from unittest import mock

import test_instance as base
import firewall
real_neighbor_uses = firewall.neighbor_uses


class FirewallOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.p = base.instance.paths('a')
        self.manifest = dict(token='fixture-owner', ufw_rules=[])
        self.data = dict(server=dict(manage_ufw=True, listen_ip='0.0.0.0', udp_client_cidr='192.0.2.0/24'),
                         listeners=[dict(port=1080, capabilities=['tcp'])])
        self.existing = []
        self.calls = []
        self.busy = False
        def run(argv, **kwargs):
            self.calls.append(argv)
            output = 'Status: active' if argv == ['ufw', 'status'] else 'busy' if argv[0] == 'ss' and self.busy else ''
            return subprocess.CompletedProcess(argv, 0, output)
        for target, kwargs in [
            ('shutil.which', dict(return_value='/usr/sbin/ufw')),
            ('read_manifest', dict(return_value=self.manifest)),
            ('atomic_json', dict(return_value=None)),
            ('added_rules', dict(side_effect=lambda: self.existing.copy())),
            ('neighbor_uses', dict(return_value=False)),
            ('subprocess.run', dict(side_effect=run)),
        ]:
            patcher = mock.patch('firewall.' + target, **kwargs)
            patched = patcher.start(); self.addCleanup(patcher.stop)
            if target == 'neighbor_uses': self.neighbor = patched
        self.output = contextlib.redirect_stdout(io.StringIO()); self.output.__enter__()
        self.addCleanup(self.output.__exit__, None, None, None)

    def configure(self):
        firewall.configure(self.p, self.data)

    def owned(self):
        self.configure()
        record = self.manifest['ufw_rules'][0]
        self.existing = [(record['args'], record['comment'])]
        self.calls.clear()

    def test_new_rule_is_marked_and_ownership_recorded(self):
        self.configure()
        self.assertIn(['ufw', 'allow', '1080/tcp', 'comment', '3proxy-setup:a:fixture-owner'], self.calls)
        self.assertEqual(len(self.manifest['ufw_rules']), 1)

    def test_identical_preexisting_rule_is_never_claimed_or_relabelled(self):
        self.existing = [(['allow', '1080/tcp'], 'foreign')]
        self.configure()
        self.assertEqual(self.manifest['ufw_rules'], [])
        self.assertFalse(any(call[:2] == ['ufw', 'allow'] for call in self.calls))

    def test_alternate_spelling_of_preexisting_rule_is_not_overwritten(self):
        self.existing = [(['allow', 'proto', 'tcp', 'from', 'any', 'to', 'any', 'port', '1080'], None)]
        self.configure()
        self.assertEqual(self.manifest['ufw_rules'], [])

    def test_preexisting_cidr_alias_is_never_claimed(self):
        self.data["listeners"][0]["capabilities"] = ["tcp", "udp"]
        self.data["server"]["udp_client_cidr"] = "192.0.2.4"
        self.existing = [
            (["allow", "1080/tcp"], None),
            (["allow", "proto", "udp", "from", "192.0.2.4/32", "to", "0.0.0.0/0", "port", "1024:65535"], "foreign"),
        ]
        self.configure()
        self.assertEqual(self.manifest["ufw_rules"], [])
        self.assertFalse(any(call[:2] == ["ufw", "allow"] for call in self.calls))

    def test_any_and_zero_prefix_are_identical(self):
        left = ["allow", "proto", "tcp", "from", "0.0.0.0/0", "to", "any", "port", "1080"]
        self.assertEqual(firewall.signature(left), firewall.signature(["allow", "1080/tcp"]))

    def test_loopback_listener_does_not_create_public_rule(self):
        self.data['listeners'][0]['listen_ip'] = '127.0.0.1'
        self.data['listeners'][0]['capabilities'] = ['tcp', 'udp']
        self.configure()
        self.assertEqual(self.manifest['ufw_rules'], [])

    def test_explicit_purge_removes_exclusive_marked_rule(self):
        self.owned()
        firewall.purge(self.p, self.manifest, execute=True)
        self.assertIn(['ufw', '--force', 'delete', 'allow', '1080/tcp'], self.calls)
        self.assertEqual(self.manifest['ufw_rules'], [])

    def test_canonicalized_udp_rule_is_removed_by_semantic_ownership(self):
        self.data["listeners"][0]["capabilities"] = ["tcp", "udp"]
        self.configure()
        record = self.manifest["ufw_rules"][1]
        canonical = ["allow", "proto", "udp", "from", "192.0.2.0/24", "to", "any", "port", "1024:65535"]
        self.existing = [(canonical, record["comment"])]
        self.calls.clear()
        firewall.purge(self.p, self.manifest, execute=True)
        self.assertIn(["ufw", "--force", "delete", *record["args"]], self.calls)

    def test_source_port_and_extra_qualifiers_are_not_equivalent(self):
        self.assertIsNone(firewall.signature(["allow", "proto", "tcp", "from", "any", "port", "1080", "to", "any"]))
        self.assertIsNone(firewall.signature(["allow", "in", "on", "eth0", "proto", "tcp", "from", "any", "to", "any", "port", "1080"]))
        self.assertIsNone(firewall.signature(["allow", "proto", "tcp", "from", "any", "to", "any", "port", "1080", "log"]))

    def test_malformed_records_refuse_without_ufw(self):
        for malformed in ("not-a-list", [False], [{"args": [False], "comment": "foreign"}]):
            with self.subTest(records=malformed):
                self.manifest["ufw_rules"] = malformed
                with mock.patch.object(firewall.shutil, "which", return_value=None):
                    with self.assertRaisesRegex(ValueError, "ownership record"):
                        firewall.purge(self.p, self.manifest, execute=True)
        self.assertEqual(self.calls, [])

    def test_neighbor_dependency_retains_marked_rule(self):
        self.owned(); self.neighbor.return_value = True
        firewall.purge(self.p, self.manifest, execute=True)
        self.assertFalse(any('delete' in call for call in self.calls))
        self.assertEqual(len(self.manifest['ufw_rules']), 1)

    def test_live_foreign_listener_retains_marked_rule(self):
        self.owned(); self.busy = True
        firewall.purge(self.p, self.manifest, execute=True)
        self.assertFalse(any('delete' in call for call in self.calls))

    def test_changed_comment_and_dry_run_never_delete(self):
        self.owned()
        self.existing = [(['allow', '1080/tcp'], 'someone-else')]
        firewall.purge(self.p, self.manifest, execute=True)
        self.assertFalse(any('delete' in call for call in self.calls))
        self.existing = [(['allow', '1080/tcp'], self.manifest['ufw_rules'][0]['comment'])]
        firewall.purge(self.p, self.manifest, execute=False)
        self.assertFalse(any('delete' in call for call in self.calls))


class NeighborRegistryTests(unittest.TestCase):
    def test_neighbor_ports_loopback_and_unknown_state(self):
        import json
        import tempfile
        from pathlib import Path
        import yaml
        with tempfile.TemporaryDirectory() as temp:
            registry = Path(temp)
            p = dict(INSTANCE_ID="a", INSTANCE_STATE=str(registry / "instances/a"))
            neighbor = registry / "instances/b"; neighbor.mkdir(parents=True)
            (neighbor / "manifest.json").write_text(json.dumps({"status": "installed"}))
            self.assertTrue(real_neighbor_uses(p, ["allow", "1080/tcp"]))
            data = dict(server=dict(listen_ip="0.0.0.0", udp_client_cidr="192.0.2.0/24"),
                        listeners=[dict(port=1080, capabilities=["tcp"])])
            (neighbor / "requested.yaml").write_text(yaml.safe_dump(data))
            self.assertTrue(real_neighbor_uses(p, ["allow", "1080/tcp"]))
            self.assertFalse(real_neighbor_uses(p, ["allow", "1081/tcp"]))
            data["listeners"][0]["listen_ip"] = "127.0.0.1"
            (neighbor / "requested.yaml").write_text(yaml.safe_dump(data))
            self.assertFalse(real_neighbor_uses(p, ["allow", "1080/tcp"]))
            (neighbor / "manifest.json").write_text("{broken")
            self.assertTrue(real_neighbor_uses(p, ["allow", "1080/tcp"]))

    def test_external_udp_neighbor_retains_dynamic_range(self):
        import json
        import tempfile
        from pathlib import Path
        import yaml
        with tempfile.TemporaryDirectory() as temp:
            registry = Path(temp)
            p = dict(INSTANCE_ID="a", INSTANCE_STATE=str(registry / "instances/a"))
            neighbor = registry / "instances/b"; neighbor.mkdir(parents=True)
            (neighbor / "manifest.json").write_text(json.dumps({"status": "installed"}))
            data = dict(server=dict(listen_ip="0.0.0.0", udp_client_cidr="192.0.2.0/25"),
                        listeners=[dict(port=2080, capabilities=["tcp", "udp"])])
            (neighbor / "requested.yaml").write_text(yaml.safe_dump(data))
            target = ["allow", "from", "192.0.2.0/24", "to", "any", "port", "1024:65535", "proto", "udp"]
            self.assertTrue(real_neighbor_uses(p, target))
            (neighbor / "manifest.json").write_text(json.dumps({"status": "removed"}))
            self.assertFalse(real_neighbor_uses(p, target))
