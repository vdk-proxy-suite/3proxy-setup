"""Adversarial ownership tests; OS commands are mocked, filesystem is real."""
import hashlib
import os
from pathlib import Path
import subprocess
import unittest
from unittest import mock

import test_instance as base
instance = base.instance


class SecurityTests(unittest.TestCase):
    setUp = base.OwnershipLifecycleTests.setUp
    clean = base.OwnershipLifecycleTests.clean

    def test_matching_execstart_with_foreign_execstop_refuses_cleanup(self):
        unit = Path(self.p["UNIT_FILE"]); unit.parent.mkdir(parents=True)
        text = f"[Service]\nExecStart={self.p['BINARY']} {self.p['CONFIG_DIR']}/3proxy.cfg\n"
        self.manifest["unit_hashes"] = [hashlib.sha256(text.encode()).hexdigest()]
        instance.atomic_json(Path(self.p["INSTANCE_STATE"]) / "manifest.json", self.manifest)
        unit.write_text(text + "ExecStop=/bin/systemctl stop 3proxy-b\n")
        with self.assertRaisesRegex(ValueError, "unit identity changed"):
            self.clean()
        self.assertFalse(any(call[0] == "systemctl" for call in self.calls))

    def test_other_unpacking_requires_explicit_update_before_writes(self):
        source = self.root / "other-unpacking"; source.mkdir()
        cfg = source / "config.yaml"; cfg.write_text("instance: {id: a}\n")
        before = (Path(self.p["INSTANCE_STATE"]) / "manifest.json").read_bytes()
        with self.assertRaisesRegex(ValueError, "update-existing"):
            instance.prepare(self.p, cfg, source, False)
        self.assertEqual((Path(self.p["INSTANCE_STATE"]) / "manifest.json").read_bytes(), before)
        self.assertFalse((Path(self.p["INSTANCE_STATE"]) / "requested.yaml").exists())

    def test_foreign_marker_rejects_update_without_writing_manifest(self):
        source = self.root / "other-unpacking"; source.mkdir()
        cfg = source / "config.yaml"; cfg.write_text("instance: {id: a}\n")
        (source / ".3proxy-instance.json").write_text('{"instance":"b","token":"different"}')
        before = (Path(self.p["INSTANCE_STATE"]) / "manifest.json").read_bytes()
        with self.assertRaisesRegex(ValueError, "different instance"):
            instance.prepare(self.p, cfg, source, True)
        self.assertEqual((Path(self.p["INSTANCE_STATE"]) / "manifest.json").read_bytes(), before)

    def test_captured_source_log_requires_separate_purge(self):
        import json
        origin = Path(self.manifest["origin"]); origin.mkdir()
        (origin / ".3proxy-instance.json").write_text(json.dumps(dict(instance="a", token="test-token")))
        log = origin / "setup.log"; log.write_text("retain")
        self.args.purge_setup = True
        self.clean()
        self.assertEqual(log.read_text(), "retain")
        self.args.purge_logs = True
        self.clean()
        self.assertFalse(origin.exists())

    def test_invalid_second_firewall_record_refuses_before_stop_or_delete(self):
        import firewall
        marker = "3proxy-setup:a:test-token"
        valid = dict(args=["allow", "1080/tcp"], comment=marker)
        invalid = dict(args=["allow", "proto", "tcp", "from", "any", "to", "any", "port", "1081", "log"], comment=marker)
        self.manifest["ufw_rules"] = [valid, invalid]
        instance.atomic_json(Path(self.p["INSTANCE_STATE"]) / "manifest.json", self.manifest)
        self.args.purge_ufw = True
        for executable in (None, "/usr/sbin/ufw"):
            with self.subTest(ufw=executable), \
                 mock.patch.object(firewall.shutil, "which", return_value=executable), \
                 mock.patch.object(firewall, "added_rules", return_value=[(valid["args"], marker)]), \
                 mock.patch.object(firewall, "neighbor_uses", return_value=False):
                with self.assertRaisesRegex(ValueError, "ownership record is invalid"):
                    self.clean()
        self.assertFalse(any(call[0] == "systemctl" or "delete" in call for call in self.calls))
        self.assertTrue(Path(self.p["CONFIG_DIR"]).exists())

    def test_partial_build_cleanup_removes_keys_but_preserves_logs(self):
        directory = Path(self.p["INSTANCE_STATE"]) / "build.interrupted"
        directory.mkdir()
        (directory / "probe.key").write_text("temporary-private-material")
        (directory / "probe.log").write_text("build-log")
        self.clean()
        self.assertFalse(directory.exists())
        retained = Path(self.p["LOG_DIR"]) / "setup-build/build.interrupted/probe.log"
        self.assertEqual(retained.read_text(), "build-log")
        self.assertFalse((Path(self.p["INSTANCE_STATE"]) / "probe.key").exists())
        self.args.purge_logs = True
        self.clean()
        self.assertFalse(retained.exists())

    def test_relative_ca_survives_foreign_cwd_and_deleted_unpacking(self):
        import shutil
        import yaml
        source = Path(self.manifest["origin"]); source.mkdir()
        for name in ("setup3proxy.sh", "clean3proxy.sh", "VERSION"):
            (source / name).write_text("fixture")
        ca = source / "certs/provider.crt"; ca.parent.mkdir()
        ca.write_text("public-ca-fixture")
        data = base.config.load_config(Path(__file__).resolve().parents[1] / "config.https.example.yaml")
        data["instance"] = {"id": "a"}
        data["tls"]["client_ca_file"] = "certs/provider.crt"
        cfg = source / "config.yaml"
        cfg.write_text(yaml.safe_dump(data), encoding="utf-8")
        previous = Path.cwd()
        try:
            os.chdir(self.root)
            loaded = base.config.load_config(cfg)
            self.assertEqual(loaded["tls"]["client_ca_file"], ca.resolve().as_posix())
            with mock.patch.object(instance, "account_exists", return_value=True):
                instance.prepare(self.p, cfg, source, False)
        finally:
            os.chdir(previous)
        snapshot = Path(self.p["INSTANCE_STATE"]) / "requested.yaml"
        installed = base.config.load_config(snapshot)
        installed_ca = Path(installed["tls"]["client_ca_file"])
        self.assertEqual(installed_ca, Path(self.p["CONFIG_DIR"]) / "client-ca.crt")
        # Configure promotes the staged public input only after the old CA has been backed up.
        staged_ca = Path(self.p["INSTANCE_STATE"]) / "pending-client-ca.crt"
        self.assertFalse(installed_ca.exists())
        installed_ca.write_bytes(staged_ca.read_bytes())
        shutil.rmtree(source)
        self.assertEqual(installed_ca.read_text(), "public-ca-fixture")
        self.assertIn(str(installed_ca), base.config.render_3proxy(installed))

    @unittest.skipUnless(os.name == "posix", "hardlinks require POSIX")
    def test_hardlinked_log_refuses_prepare_and_preserves_target(self):
        source = Path(self.manifest["origin"]); source.mkdir()
        cfg = source / "config.yaml"; cfg.write_text("instance: {id: a}\n")
        external = self.root / "external"; external.write_text("untouched")
        os.link(external, Path(self.p["LOG_DIR"]) / "3proxy.log")
        with self.assertRaisesRegex(ValueError, "hardlink"):
            instance.prepare(self.p, cfg, source, False)
        self.assertEqual(external.read_text(), "untouched")


class PendingAccountTests(unittest.TestCase):
    def test_interrupted_creation_reconciles_only_expected_attributes(self):
        p = instance.paths("a")
        manifest = dict(status="preparing", user_created=True, group_created=True, uid=None, gid=None)
        def run(argv, **kwargs):
            value = "3proxy-a:x:551:\n" if argv[1] == "group" else f"3proxy-a:x:552:551::{p['DATA_DIR']}:/usr/sbin/nologin\n"
            return subprocess.CompletedProcess(argv, 0, value)
        with mock.patch.object(instance.subprocess, "run", side_effect=run):
            instance.checked_accounts(p, manifest)
        self.assertEqual((manifest["uid"], manifest["gid"]), (552, 551))
        manifest.update(uid=None, gid=None, status="installed")
        with mock.patch.object(instance.subprocess, "run", side_effect=run):
            with self.assertRaisesRegex(ValueError, "identity changed"):
                instance.checked_accounts(p, manifest)


class FreshResourceSafetyTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.p = instance.paths("a")
        for key, value in self.p.items():
            if value.startswith("/"):
                self.p[key] = str(self.root / value.lstrip("/"))
        self.source = self.root / "unpacked"; self.source.mkdir()
        self.config = self.source / "config.yaml"
        self.config.write_text("instance: {id: a}")
        self.binary_root = Path(self.p["BINARY"]).parent.parent
        self.binary_root.mkdir(parents=True)
        self.target = self.root / "foreign-sentinel"; self.target.write_text("untouched")
        self.calls = []
        patcher = mock.patch.object(instance.subprocess, "run", side_effect=lambda argv, **kwargs: self.calls.append(argv))
        patcher.start(); self.addCleanup(patcher.stop)

    def assert_no_mutation(self):
        self.assertEqual(self.target.read_text(), "untouched")
        self.assertFalse((Path(self.p["INSTANCE_STATE"]) / "manifest.json").exists())
        self.assertFalse(self.calls)

    def test_unowned_binary_root_refused_even_when_binary_leaf_is_absent(self):
        (self.binary_root / "foreign-data").write_text("keep")
        with self.assertRaisesRegex(ValueError, "unowned binary root"):
            instance.prepare(self.p, self.config, self.source, False)
        self.assertEqual((self.binary_root / "foreign-data").read_text(), "keep")
        self.assert_no_mutation()

    @unittest.skipUnless(os.name == "posix", "link checks require POSIX")
    def test_pending_binary_symlink_refused_before_manifest_or_accounts(self):
        pending = Path(self.p["BINARY"] + ".new"); pending.parent.mkdir()
        pending.symlink_to(self.target)
        with self.assertRaisesRegex(ValueError, "symlink"):
            instance.prepare(self.p, self.config, self.source, False)
        self.assert_no_mutation()

    @unittest.skipUnless(os.name == "posix", "hardlinks require POSIX")
    def test_pending_binary_hardlink_refused_before_manifest_or_accounts(self):
        pending = Path(self.p["BINARY"] + ".new"); pending.parent.mkdir()
        os.link(self.target, pending)
        with self.assertRaisesRegex(ValueError, "exclusively owned regular file"):
            instance.prepare(self.p, self.config, self.source, False)
        self.assert_no_mutation()
