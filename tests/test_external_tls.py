from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import config
import tls_material as tls


class ExternalSchemaTests(unittest.TestCase):
    def data(self):
        data = config.load_config(ROOT / "config.https.example.yaml")
        data["tls"]["server"] = {"mode": "external", "fullchain_file": "/secure/fullchain.pem",
                                 "private_key_file": "/secure/key.pem"}
        return data

    def test_explicit_external_and_backward_compatible_managed(self):
        config.validate(self.data())
        self.assertEqual(config.server_ca_file(self.data()), tls.SYSTEM_CA)
        original = config.load_config(ROOT / "config.https.example.yaml")
        config.validate(original)
        original["tls"]["server"]["mode"] = "managed"
        config.validate(original)

    def test_invalid_mode_mixed_fields_missing_key_and_path_injection(self):
        for changes in ({"mode": "typo"}, {"validity_days": 365}, {"private_key_file": None},
                        {"fullchain_file": "/secure/file\nssl_server_no_verify"}, {"ca_file": "/a/../b"}):
            data = self.data()
            data["tls"]["server"].update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                config.validate(data)

    def test_relative_paths_resolve_against_yaml_not_cwd(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            data = self.data()
            data["tls"]["server"].update(fullchain_file="fullchain.pem", private_key_file="key.pem")
            path = root / "config.yaml"
            path.write_text(yaml.safe_dump(data))
            loaded = config.load_config(path)
            self.assertEqual(loaded["tls"]["server"]["fullchain_file"], (root / "fullchain.pem").as_posix())
            config.validate(loaded)


@unittest.skipUnless(os.name == "posix" and shutil.which("openssl"), "POSIX/OpenSSL crypto integration")
class ExternalMaterialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="3proxy-external-tests-")
        cls.root = Path(cls.temp.name)
        def run(*args):
            subprocess.run(["openssl", *args], cwd=cls.root, check=True, capture_output=True)
        cls.run_ssl = staticmethod(run)
        run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "root.key",
            "-out", "root.crt", "-days", "5", "-subj", "/CN=external-test-root",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        (cls.root / "inter.ext").write_text("basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n")
        run("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", "inter.key",
            "-out", "inter.csr", "-subj", "/CN=external-test-intermediate")
        run("x509", "-req", "-in", "inter.csr", "-CA", "root.crt", "-CAkey", "root.key",
            "-CAcreateserial", "-days", "4", "-extfile", "inter.ext", "-out", "inter.crt")
        (cls.root / "leaf.ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n")
        run("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", "leaf.key",
            "-out", "leaf.csr", "-subj", "/CN=external-test-leaf")
        for name, days in (("leaf", "3"), ("expired", "-1")):
            run("x509", "-req", "-in", "leaf.csr", "-CA", "inter.crt", "-CAkey", "inter.key",
                "-CAcreateserial", "-days", days, "-extfile", "leaf.ext", "-out", name + ".crt")
        cls.bundle = {"server.crt": (cls.root / "leaf.crt").read_bytes() + (cls.root / "inter.crt").read_bytes(),
                      "server.key": (cls.root / "leaf.key").read_bytes(),
                      "trust.crt": (cls.root / "root.crt").read_bytes()}

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_valid_fullchain_and_failure_cases(self):
        tls.validate_bundle(self.bundle, "127.0.0.1")
        cases = [
            (self.bundle, "127.0.0.2"),
            (dict(self.bundle, **{"server.key": (self.root / "root.key").read_bytes()}), "127.0.0.1"),
            (dict(self.bundle, **{"server.crt": (self.root / "leaf.crt").read_bytes()}), "127.0.0.1"),
            (dict(self.bundle, **{"server.crt": (self.root / "expired.crt").read_bytes() + (self.root / "inter.crt").read_bytes()}), "127.0.0.1"),
            (dict(self.bundle, **{"server.crt": self.bundle["server.crt"] + b"unexpected trailing data"}), "127.0.0.1"),
            ({k: v for k, v in self.bundle.items() if k != "trust.crt"}, "127.0.0.1"),
        ]
        for bundle, ip in cases:
            with self.subTest(keys=list(bundle), ip=ip), self.assertRaises(ValueError):
                tls.validate_bundle(bundle, ip)

    def test_staging_survives_original_removal_and_install_preserves_neighbor(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            source = root / "source"; source.mkdir()
            for filename, value in self.bundle.items():
                (source / filename).write_bytes(value); (source / filename).chmod(0o600)
            data = ExternalSchemaTests().data()
            data["server"]["public_ip"] = "127.0.0.1"
            data["tls"]["server"].update(fullchain_file=str(source / "server.crt"),
                                          private_key_file=str(source / "server.key"), ca_file=str(source / "trust.crt"))
            p = {"CONFIG_DIR": str(root / "instance-a"), "INSTANCE_STATE": str(root / "state-a")}
            neighbor = root / "instance-b"; neighbor.mkdir(); (neighbor / "sentinel").write_text("unchanged")
            bundle = tls.collect(data)
            tls.stage(data, p, bundle)
            shutil.rmtree(source)
            with mock.patch.object(config, "paths", return_value=p):
                recovered = tls.collect(data, root / "state-a" / "pending-server-tls")
                self.assertEqual(recovered, bundle)
                tls.replace_directory(root / "instance-a" / "tls", recovered)
                self.assertEqual(tls.collect(data), bundle)
            self.assertEqual((neighbor / "sentinel").read_text(), "unchanged")
            self.assertEqual((root / "instance-a" / "tls" / "server.key").stat().st_mode & 0o777, 0o600)
            self.assertFalse((root / "instance-a" / "tls" / "ca.key").exists())

    def test_failed_directory_swap_restores_previous_material(self):
        with tempfile.TemporaryDirectory() as name:
            dest = Path(name) / "tls"
            tls.replace_directory(dest, self.bundle)
            before = (dest / "server.crt").read_bytes()
            original = os.rename
            def rename(src, target):
                if Path(target) == dest and not str(src).endswith(".old"):
                    raise OSError("simulated install failure")
                original(src, target)
            with mock.patch.object(tls.os, "rename", side_effect=rename), self.assertRaises(OSError):
                tls.replace_directory(dest, self.bundle)
            self.assertEqual((dest / "server.crt").read_bytes(), before)

    def test_input_links_and_world_readable_key_are_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); key = root / "key"
            key.write_bytes(self.bundle["server.key"]); key.chmod(0o600)
            link = root / "link"; link.symlink_to(key)
            with self.assertRaises(ValueError): tls.read_input(link, private=True)
            link.unlink(); os.link(key, link)
            with self.assertRaises(ValueError): tls.read_input(key, private=True)
            link.unlink(); key.chmod(0o644)
            with self.assertRaises(ValueError): tls.read_input(key, private=True)

    @unittest.skipUnless(os.environ.get("THREEPROXY_BINARY"), "native binary opt-in")
    def test_real_3proxy_serves_intermediate_chain_to_root_only_client(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            tls.replace_directory(root / "tls", self.bundle)
            with socket.socket() as bind:
                bind.bind(("127.0.0.1", 0)); port = bind.getsockname()[1]
            cfg = root / "proxy.cfg"
            cfg.write_text(f"auth iponly\nallow * 127.0.0.1\nssl_server_cert {root}/tls/server.crt\nssl_server_key {root}/tls/server.key\nssl_server_min_proto_version TLSv1.2\nssl_serv\nproxy -i127.0.0.1 -p{port}\nssl_noserv\n")
            with (root / "log").open("w") as log:
                proc = subprocess.Popen([os.environ["THREEPROXY_BINARY"], str(cfg)], stdout=log, stderr=log)
                try:
                    ctx = ssl.create_default_context(cafile=str(root / "tls" / "trust.crt"))
                    for _ in range(80):
                        try:
                            raw = socket.create_connection(("127.0.0.1", port), timeout=1)
                            break
                        except ConnectionRefusedError: time.sleep(.05)
                    else: self.fail("native listener did not start")
                    with ctx.wrap_socket(raw, server_hostname="127.0.0.1") as client:
                        self.assertIn(client.version(), ("TLSv1.2", "TLSv1.3"))
                        expected = ssl.PEM_cert_to_DER_cert((self.root / "leaf.crt").read_text())
                        self.assertEqual(client.getpeercert(binary_form=True), expected)
                    with socket.create_connection(("127.0.0.1", port), timeout=1) as plain:
                        plain.sendall(b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test\r\n\r\n")
                        try: reply = plain.recv(100)
                        except (OSError, TimeoutError): reply = b""
                        self.assertNotIn(b"200", reply)
                finally:
                    proc.terminate()
                    try: proc.wait(timeout=5)
                    except subprocess.TimeoutExpired: proc.kill(); proc.wait()


if __name__ == "__main__":
    unittest.main()
