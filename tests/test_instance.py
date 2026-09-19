from __future__ import annotations

import argparse
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import instance
import config


class InstanceContractTests(unittest.TestCase):
    def test_identity_is_explicit_and_safe(self):
        for value in ("", "../b", "A", "a/b", "a b", "a" * 21, True, None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                instance.identity({"instance": {"id": value}})
        with self.assertRaisesRegex(ValueError, "required"):
            instance.identity({})
        self.assertIsNone(instance.identity({}, legacy=True))
        with self.assertRaises(ValueError):
            instance.identity({"instance": {"id": "a"}}, legacy=True)

    def test_all_owned_resources_are_distinct(self):
        a, b = instance.paths("a"), instance.paths("b")
        self.assertFalse(set(a.values()) & set(b.values()))
        self.assertEqual(a["BINARY"], "/opt/3proxy/instances/a/bin/3proxy")
        self.assertEqual(a["SERVICE_USER"], "3proxy-a")

    def test_render_systemd_and_tls_log_paths_use_identity(self):
        data = config.load_config(Path(__file__).resolve().parents[1] / "config.matrix.example.yaml")
        for name in ("a", "b"):
            data["instance"] = {"id": name}
            config.validate(data)
            unit = config.render_systemd(data)
            self.assertIn(f"User=3proxy-{name}", unit)
            self.assertIn(f"/opt/3proxy/instances/{name}/bin/3proxy", unit)
            self.assertIn(f"RuntimeDirectory=3proxy-{name}", unit)
            rendered = config.render_3proxy(data)
            self.assertIn(f"/etc/3proxy-setup/instances/{name}/tls/server.key", rendered)
            self.assertIn(f"/var/log/3proxy-setup/instances/{name}/3proxy.log", rendered)
            self.assertNotIn("log /var/log/3proxy/3proxy.log", rendered)

    def test_cleanup_by_id_needs_no_yaml(self):
        args = argparse.Namespace(action="cleanup", config=None, instance="alpha", source=Path("missing"), legacy=False)
        p, selected = instance.selected(args)
        self.assertEqual(p["INSTANCE_ID"], "alpha")
        self.assertIsNone(selected)

    def test_selector_rejects_mismatch(self):
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / "config.yaml"
            file.write_text("instance: {id: a}")
            args = argparse.Namespace(action="env", config=file, instance="b", source=Path(temp), legacy=False)
            with self.assertRaisesRegex(ValueError, "does not match"):
                instance.selected(args)

    def test_changed_numeric_identity_is_rejected(self):
        p = instance.paths("a")
        result = subprocess.CompletedProcess([], 0, "3proxy-a:x:501:501::/:/bin/false\n")
        with mock.patch.object(instance.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(ValueError, "identity changed"):
                instance.checked_accounts(p, {"uid": 500, "gid": 500})


class OwnershipLifecycleTests(unittest.TestCase):
    """Real temporary files, fake OS accounts/systemctl; live acceptance is separate."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.p = instance.paths("a")
        for key, value in self.p.items():
            if value.startswith("/"):
                self.p[key] = str(self.root / value.lstrip("/"))
        self.manifest = dict(schema=1, paths=self.p, origin=str(self.root / "unpacked"), token="test-token",
                             status="installed", user_created=False, group_created=False, uid=55, gid=55)
        self.guard = mock.patch.object(instance, "guard")
        self.guard.start()
        self.addCleanup(self.guard.stop)
        instance.atomic_json(Path(self.p["INSTANCE_STATE"]) / "manifest.json", self.manifest)
        for key in ("CONFIG_DIR", "LOG_DIR", "DATA_DIR", "BACKUP_ROOT", "INSTALLED_ROOT"):
            directory = Path(self.p[key]); directory.mkdir(parents=True, exist_ok=True)
            (directory / "sentinel").write_text(key)
        self.calls = []
        def run(argv, **kwargs):
            self.calls.append(argv)
            return subprocess.CompletedProcess(argv, 3 if argv[0] in ("systemctl", "getent") else 0, "")
        patcher = mock.patch.object(instance.subprocess, "run", side_effect=run)
        patcher.start(); self.addCleanup(patcher.stop)
        patcher = mock.patch.object(instance.os, "geteuid", return_value=0, create=True)
        patcher.start(); self.addCleanup(patcher.stop)
        self.args = argparse.Namespace(yes=True, dry_run=False, keep_backups=False, purge_logs=False,
                                       purge_shared_components=False, purge_setup=False, purge_ufw=False)

    def clean(self):
        with contextlib.redirect_stdout(io.StringIO()):
            instance.cleanup(self.p, self.args)

    def test_default_cleanup_retains_logs_manifest_and_controller_and_other_instance(self):
        neighbor = self.root / "etc/3proxy/instances/b/config"
        neighbor.parent.mkdir(parents=True); neighbor.write_text("neighbor")
        self.clean()
        self.assertTrue(Path(self.p["LOG_DIR"]).exists())
        self.assertTrue(Path(self.p["INSTALLED_ROOT"]).exists())
        self.assertEqual(instance.read_manifest(self.p)["status"], "removed")
        self.assertEqual(neighbor.read_text(), "neighbor")
        self.assertFalse(Path(self.p["CONFIG_DIR"]).exists())
        self.assertTrue(all("3proxy-b" not in call for call in self.calls))
        self.assertFalse(any("pkill" in call or "journalctl" in call or "apt-get" in call for call in self.calls))
        self.args.purge_logs = True
        self.clean()
        self.assertFalse(Path(self.p["LOG_DIR"]).exists())

    def test_dry_run_mutates_nothing(self):
        self.args.yes = False
        self.clean()
        self.assertTrue(Path(self.p["CONFIG_DIR"]).exists())
        self.assertEqual(instance.read_manifest(self.p)["status"], "installed")
        self.assertFalse(any(call[0] == "systemctl" for call in self.calls))

    def test_manifest_path_injection_rejected_before_service_actions(self):
        self.manifest["paths"] = dict(self.p, CONFIG_DIR="/etc")
        instance.atomic_json(Path(self.p["INSTANCE_STATE"]) / "manifest.json", self.manifest)
        with self.assertRaisesRegex(ValueError, "identity/paths"):
            self.clean()
        self.assertFalse(self.calls)

    def test_unowned_unit_blocks_cleanup(self):
        unit = Path(self.p["UNIT_FILE"]); unit.parent.mkdir(parents=True)
        unit.write_text("[Service]\nExecStart=/foreign/service\n")
        with self.assertRaisesRegex(ValueError, "unit identity changed"):
            self.clean()
        self.assertTrue(Path(self.p["CONFIG_DIR"]).exists())

    def test_partial_install_manifest_allows_cleanup(self):
        self.manifest["status"] = "preparing"
        instance.atomic_json(Path(self.p["INSTANCE_STATE"]) / "manifest.json", self.manifest)
        self.clean()
        self.assertFalse(Path(self.p["CONFIG_DIR"]).exists())

    def test_shared_flag_never_uninstalls_packages(self):
        self.args.purge_shared_components = True
        self.clean()
        self.assertFalse(any(call[0] in ("apt-get", "dpkg", "journalctl") for call in self.calls))

    def test_foreign_source_marker_refuses_purge(self):
        origin = Path(self.manifest["origin"]); origin.mkdir()
        (origin / ".3proxy-instance.json").write_text('{"instance":"b","token":"foreign"}')
        self.args.purge_setup = True
        with self.assertRaisesRegex(ValueError, "ownership mismatch"):
            self.clean()

    @unittest.skipUnless(os.name == "posix", "symlink owner checks require POSIX")
    def test_guard_rejects_symlink_ancestor(self):
        self.guard.stop()
        link = self.root / "link"
        link.symlink_to(self.root / "etc", target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            instance.guard(link / "child", root_owned=False)


if __name__ == "__main__":
    unittest.main()
