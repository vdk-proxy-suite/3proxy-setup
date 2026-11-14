from __future__ import annotations
import copy
import contextlib
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_schema_v2 import profile
import acme
import acme_config
import instance
import tls_v2
import config


class CertificateContextTests(unittest.TestCase):
    def test_certificates_share_instance_ownership_but_not_candidate_state(self):
        data = profile()
        data["tls"]["certificates"]["other"] = copy.deepcopy(data["tls"]["certificates"]["dns"])
        p = instance.paths("dev")
        contexts = list(tls_v2.contexts(p, data))
        first, second = [acme_config.resources(item[1]) for item in contexts]
        self.assertEqual(first["root"], second["root"])
        self.assertEqual(first["client"], second["client"])
        self.assertEqual(first["registry"], second["registry"])
        self.assertNotEqual(first["candidate"], second["candidate"])
        self.assertNotEqual(first["status"], second["status"])
        self.assertNotEqual(acme.active_directory(contexts[0][1]), acme.active_directory(contexts[1][1]))

    def test_dualstack_served_checks_keep_dns_identity_and_probe_both_loops(self):
        _, _, view = next(tls_v2.contexts(instance.paths("dev"), profile()))
        self.assertEqual([item["listen_ip"] for item in view["listeners"]], ["127.0.0.1", "::1"])
        self.assertTrue(all(item["endpoint"]["host"] == "proxy.example.test" for item in view["listeners"]))


@unittest.skipUnless(os.name == "posix", "root-owned manifest integration")
class CertificateManifestIntegrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.p = {key: str(self.root / value.lstrip("/")) if value.startswith("/") else value
                  for key, value in instance.paths("manifest-test").items()}
        self.manifest = dict(schema=1, paths=dict(self.p), token="fixture-owner", status="installed")
        instance.atomic_json(Path(self.p["INSTANCE_STATE"]) / "manifest.json", self.manifest)
        original = acme_config.resources
        def resources(p):
            result = original(p)
            old_root = result["root"]
            new_root = self.root / "acme"
            for key, value in result.items():
                if isinstance(value, Path) and value.is_relative_to(old_root):
                    result[key] = new_root / value.relative_to(old_root)
            return result
        patch = mock.patch.object(acme_config, "resources", side_effect=resources)
        patch.start(); self.addCleanup(patch.stop)
        self.view = next(tls_v2.contexts(self.p, profile()))[2]

    def test_named_certificates_register_against_real_instance_manifest(self):
        for name in ("dns", "secondary"):
            scoped = dict(self.p, CERTIFICATE_ID=name)
            acme.register(scoped, self.view)
            stored = instance.read_manifest(self.p)
            self.assertEqual(stored["paths"], self.p)
            self.assertNotIn("CERTIFICATE_ID", stored["paths"])
            acme.verify_owned(scoped, stored)
        self.assertEqual(json.loads((self.root / "acme/owner.json").read_text()),
                         dict(instance="manifest-test", token="fixture-owner"))

    def test_real_preflight_reaches_issuance_without_mocking_manifest_validation(self):
        scoped = dict(self.p, CERTIFICATE_ID="dns")
        with mock.patch.object(acme, "bootstrap") as bootstrap, mock.patch.object(acme, "issuance") as issue:
            acme.preflight(scoped, self.view)
        bootstrap.assert_called_once_with(scoped)
        issue.assert_called_once_with(scoped, self.view)
        self.assertEqual(instance.read_manifest(self.p)["paths"], self.p)

    def test_certificate_selector_does_not_hide_changed_or_extra_paths(self):
        for changes in ({"CONFIG_DIR": str(self.root / "foreign")}, {"UNEXPECTED_PATH": "/etc"}):
            scoped = dict(self.p, CERTIFICATE_ID="dns", **changes)
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, "identity/paths"):
                acme.register(scoped, self.view)
            self.assertFalse((self.root / "acme").exists())

    def test_invalid_selector_is_rejected_before_ownership_writes(self):
        for name in ("../other", "", None, 1):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "certificate id"):
                acme.register(dict(self.p, CERTIFICATE_ID=name), self.view)
            self.assertFalse((self.root / "acme").exists())


@unittest.skipUnless(os.name == "posix", "root-owned Linux transaction integration")
class BatchDeploymentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.p = instance.paths("dev")
        self.p.update(CONFIG_DIR=str(self.root / "config"), INSTANCE_STATE=str(self.root / "state"), SERVICE_GROUP="root")
        self.data = profile()
        second = copy.deepcopy(self.data["listeners"][0])
        second.update(id="other", port=28444, tls_certificate="other")
        self.data["listeners"].append(second)
        self.data["tls"]["certificates"]["other"] = copy.deepcopy(self.data["tls"]["certificates"]["dns"])
        original_resources = acme_config.resources
        def resources(p):
            value = original_resources(p)
            root = self.root / "acme"
            scope = root / "certificates" / p["CERTIFICATE_ID"] if "CERTIFICATE_ID" in p else root
            value.update(root=root, candidate=scope / "candidate", status=scope / "status.json")
            return value
        patch = mock.patch.object(acme_config, "resources", side_effect=resources)
        patch.start(); self.addCleanup(patch.stop)
        for name, scoped, _ in tls_v2.contexts(self.p, self.data):
            active = acme.active_directory(scoped); active.mkdir(parents=True)
            (active / "server.crt").write_bytes(("old-" + name).encode())
            (active / "server.key").write_bytes(("old-key-" + name).encode())
            (active / "server.key").chmod(0o600)
            candidate = resources(scoped)["candidate"]; candidate.mkdir(parents=True)
            (candidate / "server.crt").write_bytes(("new-" + name).encode())
            (candidate / "server.key").write_bytes(("new-key-" + name).encode())
            (candidate / "server.key").chmod(0o600)
            (candidate / "identity.json").write_text("{}")
        self.now = datetime(2026, 11, 15, 2, 0, tzinfo=timezone.utc)
        self.run = self.patch(acme, "run", return_value=SimpleNamespace(returncode=0))
        self.patch(acme, "validate")
        self.patch(acme, "check_identity")
        self.patch(acme, "fingerprint", side_effect=lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest())
        self.patch(acme, "served", return_value=[])
        self.wait = self.patch(acme, "wait_served")
        self.patch(tls_v2, "active_permissions")
        self.installed = []
        def install(scoped, view):
            name = scoped["CERTIFICATE_ID"]
            self.installed.append(name)
            active, candidate = acme.active_directory(scoped), resources(scoped)["candidate"]
            for filename in ("server.crt", "server.key"):
                (active / filename).write_bytes((candidate / filename).read_bytes())
        self.install = self.patch(acme, "install_candidate", side_effect=install)

    def patch(self, obj, attr, **kwargs):
        patch = mock.patch.object(obj, attr, **kwargs)
        result = patch.start(); self.addCleanup(patch.stop)
        return result

    def restarts(self):
        return [call.args[0] for call in self.run.call_args_list if call.args[0][1] == "restart"]

    def test_two_renewed_certificates_use_one_restart_of_selected_instance(self):
        result = tls_v2.deploy(self.p, self.data, now=self.now)
        self.assertIn("one instance restart", result)
        self.assertEqual(self.installed, ["dns", "other"])
        self.assertEqual(self.restarts(), [["systemctl", "restart", "3proxy-dev"]])
        self.assertEqual(self.wait.call_count, 2)
        for name in ("dns", "other"):
            self.assertEqual((self.root / "config/tls" / name / "server.crt").read_bytes(), ("new-" + name).encode())

    def test_failed_served_verification_restores_both_pairs(self):
        self.wait.side_effect = [RuntimeError("served wrong cert"), None, None]
        with self.assertRaisesRegex(RuntimeError, "wrong cert"):
            tls_v2.deploy(self.p, self.data, now=self.now)
        for name in ("dns", "other"):
            self.assertEqual((self.root / "config/tls" / name / "server.crt").read_bytes(), ("old-" + name).encode())
            self.assertEqual((self.root / "config/tls" / name / "server.key").read_bytes(), ("old-key-" + name).encode())
        self.assertEqual(self.restarts(), [["systemctl", "restart", "3proxy-dev"]] * 2)

    def test_invalid_second_candidate_does_not_touch_first_or_restart(self):
        acme.validate.side_effect = [None, ValueError("bad second certificate")]
        with self.assertRaisesRegex(ValueError, "second"):
            tls_v2.deploy(self.p, self.data, now=self.now)
        self.install.assert_not_called()
        self.assertEqual(self.restarts(), [])

    def test_outside_window_or_stopped_does_not_apply_candidates(self):
        tls_v2.deploy(self.p, self.data, now=self.now.replace(hour=3))
        self.run.return_value = SimpleNamespace(returncode=3)
        tls_v2.deploy(self.p, self.data, now=self.now)
        self.install.assert_not_called()
        self.assertEqual(self.restarts(), [])

    def test_test_renewal_uses_dry_run_without_candidate_or_active_changes(self):
        _, scoped, view = next(tls_v2.contexts(self.p, self.data))
        resources = acme_config.resources(scoped)
        renewal = resources["root"] / "production/config/renewal" / (acme_config.lineage(view) + ".conf")
        renewal.parent.mkdir(parents=True); renewal.write_text("fixture renewal configuration")
        candidate = resources["candidate"] / "server.crt"
        active = acme.active_directory(scoped) / "server.crt"
        before = candidate.read_bytes(), active.read_bytes()
        self.patch(acme.operation_lock, "acquire", return_value=contextlib.nullcontext())
        acme.test_renewal(scoped, view)
        self.assertEqual(before, (candidate.read_bytes(), active.read_bytes()))
        self.assertIn("--dry-run", self.run.call_args.args[0])
        self.assertIn("renew", self.run.call_args.args[0])
        self.install.assert_not_called()
        self.assertEqual(self.restarts(), [])


@unittest.skipUnless(os.name == "posix", "Linux managed certificate lifecycle")
class ManagedNamedCertificateTests(unittest.TestCase):
    def test_reconfigure_reuses_ca_and_leaf_then_changes_only_leaf_for_new_dns_name(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            p = instance.paths("dev")
            p.update(CONFIG_DIR=str(root / "config"), INSTANCE_STATE=str(root / "state"), SERVICE_GROUP="root")
            data = profile()
            data["tls"]["certificates"]["dns"] = dict(mode="managed", identifiers=["proxy.example.test"],
                validity_days=2, ca_validity_days=3, regenerate_on_setup=False)
            config.validate(data)
            neighbor = root / "neighbor"; neighbor.mkdir(); (neighbor / "sentinel").write_text("preserve")
            with mock.patch.object(acme, "run", return_value=SimpleNamespace(returncode=3)) as run:
                tls_v2.preflight(p, data)
                run.assert_not_called()
                tls_v2.install(p, data)
                directory = root / "config/tls/dns"
                before = {name: (directory / name).read_bytes() for name in ("ca.crt", "ca.key", "server.crt", "server.key")}
                tls_v2.preflight(p, data)
                tls_v2.install(p, data)
                self.assertEqual(before, {name: (directory / name).read_bytes() for name in before})
                data["tls"]["certificates"]["dns"]["identifiers"] = ["other.example.test"]
                data["listeners"][0]["endpoint"]["host"] = "other.example.test"
                config.validate(data)
                tls_v2.preflight(p, data)
                tls_v2.install(p, data)
                self.assertEqual(before["ca.crt"], (directory / "ca.crt").read_bytes())
                self.assertEqual(before["ca.key"], (directory / "ca.key").read_bytes())
                self.assertNotEqual(before["server.crt"], (directory / "server.crt").read_bytes())
                self.assertEqual((directory / "ca.key").stat().st_mode & 0o777, 0o600)
                self.assertEqual((directory / "server.key").stat().st_mode & 0o777, 0o640)
                self.assertTrue(all(call.args[0][1] == "is-active" for call in run.call_args_list))
            self.assertEqual((neighbor / "sentinel").read_text(), "preserve")

