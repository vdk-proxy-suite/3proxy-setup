from __future__ import annotations

import hashlib
import os
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(
    os.name == "posix" and shutil.which("bash") and shutil.which("openssl"),
    "managed-PKI shell integration requires POSIX bash and OpenSSL",
)
class ManagedTlsShellIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="3proxy-tls-test-")
        self.root = Path(self.temporary.name)
        self.config_path = self.root / "config.yaml"
        self.tls_dir = self.root / "etc" / "3proxy" / "tls"
        data = yaml.safe_load((ROOT / "config.https.example.yaml").read_text(encoding="utf-8"))
        data["server"]["public_ip"] = "192.0.2.10"
        data["tls"]["server"] = {
            "dns_names": ["proxy-a.example.test"],
            "validity_days": 2,
            "ca_validity_days": 3,
            "regenerate_on_setup": False,
        }
        self.write_config(data)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_config(self, data: dict) -> None:
        self.config_path.write_text(
            yaml.safe_dump(data, sort_keys=False),
            encoding="utf-8",
            newline="\n",
        )

    def read_config(self) -> dict:
        return yaml.safe_load(self.config_path.read_text(encoding="utf-8"))

    def run_prepare(self, *, succeeds: bool = True) -> subprocess.CompletedProcess[str]:
        script = "\n".join(
            [
                "set -Eeuo pipefail",
                f"source {shlex.quote(str(ROOT / 'lib' / 'common.sh'))}",
                f"source {shlex.quote(str(ROOT / 'lib' / 'tls.sh'))}",
                f"CONFIG={shlex.quote(str(self.config_path))}",
                f"set_managed_tls_paths {shlex.quote(str(self.tls_dir))}",
                "prepare_managed_tls",
            ]
        )
        result = subprocess.run(
            ["bash", "-c", script],
            text=True,
            capture_output=True,
            timeout=120,
        )
        if succeeds and result.returncode != 0:
            self.fail(f"managed PKI failed:\nstdout={result.stdout}\nstderr={result.stderr}")
        if not succeeds and result.returncode == 0:
            self.fail("managed PKI unexpectedly accepted an invalid configuration")
        return result

    def hashes(self) -> dict[str, str]:
        return {
            name: hashlib.sha256((self.tls_dir / name).read_bytes()).hexdigest()
            for name in ("ca.crt", "ca.key", "server.crt", "server.key")
        }

    def assert_certificate_matches_config(self) -> None:
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools" / "certificates.py"),
                "--config",
                str(self.config_path),
                "--certificate",
                str(self.tls_dir / "server.crt"),
            ],
            check=True,
            text=True,
            capture_output=True,
        )
        public_ip = self.read_config()["server"]["public_ip"]
        subprocess.run(
            [
                "openssl",
                "x509",
                "-in",
                str(self.tls_dir / "server.crt"),
                "-checkip",
                public_ip,
                "-noout",
            ],
            check=True,
            text=True,
            capture_output=True,
        )

    def test_reuse_leaf_reissue_rotation_permissions_and_atomic_validation_failure(self) -> None:
        self.run_prepare()
        initial = self.hashes()
        self.assert_certificate_matches_config()
        self.assertEqual(stat.S_IMODE(self.tls_dir.stat().st_mode), 0o700)
        for name in ("ca.key", "server.key"):
            self.assertEqual(stat.S_IMODE((self.tls_dir / name).stat().st_mode), 0o600)
        for name in ("ca.crt", "server.crt"):
            self.assertEqual(stat.S_IMODE((self.tls_dir / name).stat().st_mode), 0o644)
        self.assertEqual(
            {path.name for path in self.tls_dir.iterdir()},
            {"ca.crt", "ca.key", "server.crt", "server.key"},
        )

        self.run_prepare()
        self.assertEqual(self.hashes(), initial, "unchanged valid PKI was not reused")

        changed = self.read_config()
        changed["server"]["public_ip"] = "192.0.2.11"
        changed["tls"]["server"]["dns_names"] = ["proxy-b.example.test"]
        self.write_config(changed)
        self.run_prepare()
        reissued = self.hashes()
        self.assertEqual(reissued["ca.crt"], initial["ca.crt"])
        self.assertEqual(reissued["ca.key"], initial["ca.key"])
        self.assertNotEqual(reissued["server.crt"], initial["server.crt"])
        self.assertNotEqual(reissued["server.key"], initial["server.key"])
        self.assert_certificate_matches_config()

        rotated_config = self.read_config()
        rotated_config["tls"]["server"]["regenerate_on_setup"] = True
        self.write_config(rotated_config)
        self.run_prepare()
        rotated = self.hashes()
        self.assertNotEqual(rotated["ca.crt"], reissued["ca.crt"])
        self.assertNotEqual(rotated["ca.key"], reissued["ca.key"])
        self.assertNotEqual(rotated["server.crt"], reissued["server.crt"])
        self.assertNotEqual(rotated["server.key"], reissued["server.key"])
        self.assert_certificate_matches_config()

        invalid = self.read_config()
        invalid["tls"]["server"]["dns_names"] = ["bad name"]
        self.write_config(invalid)
        before_failure = self.hashes()
        self.run_prepare(succeeds=False)
        self.assertEqual(self.hashes(), before_failure, "failed setup changed the active PKI")


if __name__ == "__main__":
    unittest.main()
