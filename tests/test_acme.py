from __future__ import annotations
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import yaml

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
import acme
import acme_config as policy
import config
import instance
import tls_material as tls


def data():
    value=config.load_config(ROOT/"config.https.example.yaml")
    value["tls"]["server"]={"mode":"acme_ip","acme":{"agree_tos":True}}
    return value


class AcmeSchemaTests(unittest.TestCase):
    def test_defaults_and_explicit_schedule(self):
        value=data();config.validate(value)
        self.assertEqual(policy.settings(value)["interval_minutes"],60)
        value["tls"]["server"]["acme"]["deploy"]={"time":"05:00","timezone":"Europe/Moscow"}
        config.validate(value)

    def test_reject_unsupported_or_unsafe_policy(self):
        for update in ({"agree_tos":False},{"profile":"classic"},{"challenge":"dns-01"},
                       {"environment":"custom"},{"email":"bad\nemail"},{"renewal":{"enabled":"yes"}},
                       {"renewal":{"interval_minutes":True}},{"renewal":{"interval_minutes":721}},
                       {"deploy":{"time":"06:00"}},{"deploy":{"timezone":"UTC"}},
                       {"cleanup":{"retain_state":"yes"}},{"server_url":"https://unknown"}):
            value=data();value["tls"]["server"]["acme"].update(update)
            with self.subTest(update=update),self.assertRaises(ValueError):config.validate(value)
        value=data();value.pop("instance")
        with self.assertRaisesRegex(ValueError,"named instance"):config.validate(value)
        value=data();value["tls"]["server"]["private_key_file"]="/foreign/key"
        with self.assertRaises(ValueError):config.validate(value)

    def test_timers_separate_renewal_and_exact_nonpersistent_deploy(self):
        p=instance.paths("alpha");units=acme.rendered_units(p,data())
        self.assertEqual(set(units),set(policy.unit_names(p)))
        deploy=units["3proxy-alpha-acme-deploy.timer"]
        self.assertIn("OnCalendar=*-*-* 05:00:00 Europe/Moscow",deploy)
        self.assertIn("Persistent=false",deploy)
        self.assertIn("RandomizedDelaySec=0",deploy)
        self.assertIn("OnUnitActiveSec=60min",units["3proxy-alpha-acme-renew.timer"])
        self.assertTrue(all("beta" not in content for content in units.values()))
        self.assertIn("/usr/local/lib/3proxy-setup/instances/alpha/tools/acme.py deploy --instance alpha",
                      units["3proxy-alpha-acme-deploy.service"])

    def test_certbot_arguments_pin_environment_identity_and_policy(self):
        p=instance.paths("a");value=data()
        first=acme.certbot_args(p,value,first=True)
        renewal=acme.certbot_args(p,value,first=False)
        self.assertIn("--ip-address",first);self.assertIn("--keep-until-expiring",first)
        self.assertIn("--required-profile",first);self.assertIn("shortlived",first)
        self.assertIn("--no-reuse-key",renewal);self.assertIn("renew",renewal)
        self.assertNotIn("--force-renewal",renewal)
        self.assertNotIn("--no-verify-ssl",first)
        self.assertIn(policy.DIRECTORIES["production"],first)
        value["tls"]["server"]["acme"]["environment"]="staging"
        staging=acme.certbot_args(p,value,first=True)
        self.assertIn(policy.DIRECTORIES["staging"],staging)
        self.assertNotEqual(first[first.index("--config-dir")+1],staging[staging.index("--config-dir")+1])

    @unittest.skipUnless(os.name=="posix","system timezone database")
    def test_window_uses_moscow_and_no_daytime_catchup(self):
        for hour,minute,expected in ((1,59,False),(2,0,True),(2,1,False),(5,0,False)):
            with self.subTest(hour=hour,minute=minute):
                self.assertEqual(acme.in_window(datetime(2026,9,20,hour,minute,tzinfo=timezone.utc)),expected)


@unittest.skipUnless(os.name=="posix" and shutil.which("openssl"),"POSIX/OpenSSL deployment integration")
class AcmeDeployTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from test_external_tls import ExternalMaterialTests
        cls.fixture=ExternalMaterialTests
        cls.fixture.setUpClass()
        cls.bundle=cls.fixture.bundle

    @classmethod
    def tearDownClass(cls):
        cls.fixture.tearDownClass()

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.p=instance.paths("a")
        self.p.update(CONFIG_DIR=str(self.root/"config"),INSTANCE_STATE=str(self.root/"state"),
                      SERVICE_GROUP="root",UNIT_FILE=str(self.root/"units/3proxy-a.service"))
        r=policy.resources(self.p)
        r.update(root=self.root/"acme",candidate=self.root/"acme/candidate",
                 client=self.root/"acme/client",status=self.root/"acme/status.json",registry=self.root/"acme/owner.json",
                 unit_dir=self.root/"units")
        patch=mock.patch.object(policy,"resources",return_value=r);patch.start();self.addCleanup(patch.stop)
        self.r=r
        self.value=data();self.value["server"]["public_ip"]="127.0.0.1"
        self.value["tls"]["server"]["acme"]["environment"]="staging"
        patch=mock.patch.object(acme,"trust_file",return_value=self.fixture.root/"root.crt");patch.start();self.addCleanup(patch.stop)
        self.active=Path(self.p["CONFIG_DIR"])/"tls"
        tls.replace_directory(self.active,self.bundle)
        (self.active/"mode").write_text("acme:staging\n")
        tls.replace_directory(r["candidate"],self.bundle)
        self.old=acme.fingerprint(self.active/"server.crt")
        instance.atomic_json(r["candidate"]/"identity.json",{"environment":"staging","ip":"127.0.0.1","fingerprint":self.old})
        self.calls=[]
        def run(args,**kwargs):
            self.calls.append([str(x) for x in args])
            return subprocess.CompletedProcess(args,0,"","")
        patch=mock.patch.object(acme,"run",side_effect=run);patch.start();self.addCleanup(patch.stop)
        self.at5=datetime(2026,9,20,2,0,tzinfo=timezone.utc)

    def new_candidate(self):
        f=self.fixture
        f.run_ssl("x509","-req","-in","leaf.csr","-CA","inter.crt","-CAkey","inter.key",
                  "-set_serial","999","-days","3","-extfile","leaf.ext","-out","renewed.crt")
        bundle=dict(self.bundle,**{"server.crt":(f.root/"renewed.crt").read_bytes()+(f.root/"inter.crt").read_bytes()})
        tls.replace_directory(self.r["candidate"],bundle)
        sha=acme.fingerprint(self.r["candidate"]/"server.crt")
        instance.atomic_json(self.r["candidate"]/"identity.json",{"environment":"staging","ip":"127.0.0.1","fingerprint":sha})
        return sha

    def test_outside_window_disabled_or_stopped_never_restarts(self):
        self.new_candidate()
        self.assertIn("outside",acme.deploy(self.p,self.value,now=datetime(2026,9,20,12,0,tzinfo=timezone.utc)))
        self.assertFalse(self.calls)
        self.value["tls"]["server"]["acme"]["renewal"]={"enabled":False}
        self.assertIn("disabled",acme.deploy(self.p,self.value,now=self.at5))
        self.assertFalse(self.calls)
        self.value["tls"]["server"]["acme"]["renewal"]["enabled"]=True
        with mock.patch.object(acme,"run",return_value=subprocess.CompletedProcess([],3,"","")):
            self.assertIn("stopped",acme.deploy(self.p,self.value,now=self.at5))
        self.assertEqual(acme.fingerprint(self.active/"server.crt"),self.old)

    def test_unchanged_certificate_does_not_restart(self):
        with mock.patch.object(acme,"served",return_value=[{"fingerprint":self.old}]):
            self.assertEqual(acme.deploy(self.p,self.value,now=self.at5),"already deployed")
        self.assertFalse(any("restart" in x for x in self.calls))

    def test_new_certificate_restarts_only_selected_instance_and_verifies_leaf(self):
        new=self.new_candidate()
        neighbor=self.root/"neighbor";neighbor.write_text("unchanged")
        with mock.patch.object(acme,"served",side_effect=[[{"fingerprint":self.old}],[{"fingerprint":new}]]) as served:
            self.assertIn("verified",acme.deploy(self.p,self.value,now=self.at5))
            self.assertEqual(served.call_args.args[2],new)
        self.assertEqual(acme.fingerprint(self.active/"server.crt"),new)
        self.assertEqual([x for x in self.calls if "restart" in x],[["systemctl","restart","3proxy-a"]])
        self.assertEqual(neighbor.read_text(),"unchanged")

    def test_bad_candidate_or_identity_does_not_change_active_certificate(self):
        self.new_candidate()
        (self.r["candidate"]/"server.key").write_bytes((self.fixture.root/"root.key").read_bytes())
        with self.assertRaises(ValueError):acme.deploy(self.p,self.value,now=self.at5)
        self.assertEqual(acme.fingerprint(self.active/"server.crt"),self.old)
        self.assertFalse(any("restart" in x for x in self.calls))

    def test_failed_served_leaf_verification_rolls_back_pair_and_restarts_only_a(self):
        import grp
        self.p["SERVICE_GROUP"] = "nogroup"
        acme.active_permissions(self.p)
        expected_gid = grp.getgrnam("nogroup").gr_gid
        self.new_candidate()
        def served(p,data,expected=None):
            if expected and expected!=self.old:raise ValueError("injected listener mismatch")
            return [{"fingerprint":self.old}]
        with mock.patch.object(acme,"served",side_effect=served),mock.patch.object(acme.time,"sleep"):
            with self.assertRaises(ValueError):acme.deploy(self.p,self.value,now=self.at5)
        self.assertEqual(acme.fingerprint(self.active/"server.crt"),self.old)
        self.assertEqual([x for x in self.calls if "restart" in x],[["systemctl","restart","3proxy-a"]]*2)
        self.assertIn("restored",json.loads(self.r["status"].read_text())["last_deploy_error"])
        self.assertEqual((self.active/"server.key").stat().st_gid, expected_gid)
        self.assertEqual((self.active/"server.key").stat().st_mode & 0o777, 0o640)
        self.assertEqual(self.active.stat().st_gid, expected_gid)

    def test_reconfigure_leaves_candidate_queued(self):
        self.new_candidate()
        acme.setup_install(self.p,self.value)
        self.assertEqual(acme.fingerprint(self.active/"server.crt"),self.old)
        self.assertFalse(self.calls)

    def test_staging_cannot_replace_existing_production_or_external_leaf(self):
        (self.active/"mode").write_text("external\n")
        with self.assertRaisesRegex(ValueError,"staging cannot replace"):acme.preflight(self.p,self.value)
        self.assertFalse(self.calls)



class AcmeOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.p=instance.paths("ownership-test")
        self.p["UNIT_FILE"]=str(self.root/"units/3proxy-ownership-test.service")
        self.p["INSTANCE_STATE"]=str(self.root/"state")
        r=policy.resources(self.p)
        r.update(root=self.root/"acme",registry=self.root/"acme/owner.json",unit_dir=self.root/"units")
        self.r=r
        patch=mock.patch.object(policy,"resources",return_value=r);patch.start();self.addCleanup(patch.stop)
        self.manifest={"token":"fixture-owner","acme":{"root":str(r["root"]),"token":"fixture-owner","units":{}}}
        r["root"].mkdir();r["unit_dir"].mkdir()
        r["registry"].write_text(json.dumps({"instance":"ownership-test","token":"fixture-owner"}))
        # Ownership of fixture paths is tested under POSIX/root in live acceptance.
        patch=mock.patch.object(instance,"guard");patch.start();self.addCleanup(patch.stop)

    def test_foreign_root_or_owner_refuses_before_any_systemctl(self):
        for mutate in ("root","token","units","retain_state","marker"):
            with self.subTest(mutate=mutate),mock.patch.object(acme,"run") as calls:
                value=copy.deepcopy(self.manifest)
                if mutate=="marker":self.r["registry"].write_text('{"instance":"other","token":"fixture-owner"}')
                else:value["acme"][mutate]="foreign"
                with self.assertRaises(ValueError):acme.cleanup(self.p,value,execute=True)
                calls.assert_not_called()

    def test_foreign_unit_and_dropins_refuse_before_stop(self):
        name=policy.unit_names(self.p)[0];file=self.r["unit_dir"]/name
        file.write_text("[Service]\nExecStart=/foreign\n")
        with mock.patch.object(acme,"run") as calls:
            with self.assertRaisesRegex(ValueError,"identity changed"):acme.cleanup(self.p,self.manifest,execute=True)
            calls.assert_not_called()
            self.manifest["acme"]["units"][name]=[acme.digest(file)]
            Path(str(file)+".d").mkdir()
            with self.assertRaisesRegex(ValueError,"drop-ins"):acme.cleanup(self.p,self.manifest,execute=True)
            calls.assert_not_called()

    def test_partial_empty_owned_directory_can_be_reconciled(self):
        self.r["registry"].unlink()
        acme.verify_owned(self.p,self.manifest)
        (self.r["root"]/"foreign").write_text("foreign")
        with self.assertRaisesRegex(ValueError,"nonempty"):acme.verify_owned(self.p,self.manifest)

    @unittest.skipUnless(os.name=="posix","POSIX links")
    def test_only_exact_certbot_archive_links_are_allowed(self):
        root=self.r["root"];lineage="ip-"+"a"*16
        archive=root/"production/config/archive"/lineage;archive.mkdir(parents=True)
        live=root/"production/config/live"/lineage;live.mkdir(parents=True)
        leaf=archive/"cert1.pem";leaf.write_text("public fixture")
        link=live/"cert.pem";link.symlink_to(leaf)
        acme.verify_tree(root)
        link.unlink();link.symlink_to(self.r["registry"])
        with self.assertRaisesRegex(ValueError,"symlink"):acme.verify_tree(root)
        link.unlink()
        os.link(leaf,archive/"alias.pem")
        with self.assertRaisesRegex(ValueError,"hardlink"):acme.verify_tree(root)

    def test_retain_state_removes_automation_and_client_but_keeps_account(self):
        self.manifest["acme"]["retain_state"]=True
        client=self.r["root"]/"client";client.mkdir()
        account=self.r["root"]/"production/config/accounts";account.mkdir(parents=True)
        (account/"fixture.json").write_text("{}")
        with mock.patch.object(acme,"run",return_value=subprocess.CompletedProcess([],0,"","")):
            acme.cleanup(self.p,self.manifest,execute=True,purge_logs=True)
        self.assertFalse(client.exists())
        self.assertTrue((account/"fixture.json").exists())
        self.assertTrue(self.r["registry"].exists())



class AcmeQueuedPolicyTests(unittest.TestCase):
    def invoke_queued(self, change):
        import contextlib
        import io
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);p=instance.paths("main")
            p["CONFIG_DIR"]=str(root)
            file=root/"setup.yaml";value=data()
            file.write_text(yaml.safe_dump(value))
            @contextlib.contextmanager
            def waited(*args,**kwargs):
                updated=copy.deepcopy(value);change(updated)
                file.write_text(yaml.safe_dump(updated))
                yield 1
            with mock.patch.object(sys,"argv",["acme.py","renew","--instance","main"]), \
                 mock.patch.object(instance,"paths",return_value=p), \
                 mock.patch.object(instance,"read_manifest",return_value={"status":"installed"}), \
                 mock.patch.object(instance,"checked_accounts"),mock.patch.object(instance,"verify_unit"), \
                 mock.patch.object(acme.os,"geteuid",return_value=0,create=True), \
                 mock.patch.object(acme.operation_lock,"acquire",side_effect=waited), \
                 mock.patch.object(acme,"issuance") as issuance, \
                 mock.patch.object(acme,"run",return_value=subprocess.CompletedProcess([],3,"","")), \
                 contextlib.redirect_stdout(io.StringIO()):
                result=acme.main()
                issuance.assert_not_called()
                return result

    def test_queued_job_rereads_disabled_policy_after_lock(self):
        self.assertEqual(self.invoke_queued(lambda value:value["tls"]["server"]["acme"].update(
            renewal={"enabled":False})),0)

    def test_queued_job_rereads_removed_acme_mode_after_lock(self):
        def change(value):
            value["tls"]["server"]={"dns_names":[],"validity_days":365,"ca_validity_days":3650,"regenerate_on_setup":False}
        self.assertEqual(self.invoke_queued(change),0)

    def test_queued_job_rejects_changed_instance_identity_after_lock(self):
        with self.assertRaisesRegex(ValueError,"identity"):
            self.invoke_queued(lambda value:value["instance"].update(id="another"))


if __name__=="__main__":unittest.main()
