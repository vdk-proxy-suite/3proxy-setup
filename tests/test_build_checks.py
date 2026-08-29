from __future__ import annotations

import hashlib
import os
from pathlib import Path
import select
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import build_checks  # noqa: E402


class PatchsetDigestTests(unittest.TestCase):
    def test_digest_is_path_independent_and_covers_names_and_contents(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first" / "patches"
            second = root / "a-much-longer-checkout-path" / "patches"
            first.mkdir(parents=True)
            second.mkdir(parents=True)
            fixtures = {
                "0001-first.patch": b"first patch\n",
                "0002-second.patch": b"second patch\n",
            }
            for name, contents in fixtures.items():
                (first / name).write_bytes(contents)
                (second / name).write_bytes(contents)

            expected_input = b"".join(
                f"{hashlib.sha256(contents).hexdigest()}  {name}\n".encode()
                for name, contents in sorted(fixtures.items())
            )
            expected = hashlib.sha256(expected_input).hexdigest()
            self.assertEqual(build_checks.patchset_sha256(first), expected)
            self.assertEqual(build_checks.patchset_sha256(second), expected)

            (second / "0002-second.patch").rename(second / "0003-renamed.patch")
            self.assertNotEqual(build_checks.patchset_sha256(second), expected)

    def test_digest_requires_at_least_one_patch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "no .patch files"):
                build_checks.patchset_sha256(Path(temporary))


class ConnectValidationTests(unittest.TestCase):
    def test_connect_header_requires_expected_authority(self) -> None:
        header = (
            b"CONNECT 127.0.0.1:443 HTTP/1.1\r\n"
            b"Host: 127.0.0.1:443\r\n\r\n"
        )
        self.assertEqual(
            build_checks.validate_connect_header(header, "127.0.0.1:443"),
            "1.1",
        )
        with self.assertRaisesRegex(ValueError, "unexpected CONNECT authority"):
            build_checks.validate_connect_header(header, "127.0.0.1:444")

    def test_connect_header_rejects_other_methods_and_malformed_lines(self) -> None:
        invalid = (
            b"GET 127.0.0.1:443 HTTP/1.1\r\n\r\n",
            b"CONNECT 127.0.0.1:443 HTTP/2\r\n\r\n",
            b"CONNECT \xff HTTP/1.1\r\n\r\n",
        )
        for header in invalid:
            with self.subTest(header=header), self.assertRaises(ValueError):
                build_checks.validate_connect_header(header, "127.0.0.1:443")

    def test_sni_guard_accepts_only_the_exact_expected_name(self) -> None:
        guard = build_checks.SniGuard("feature-check.invalid")
        self.assertIsNone(guard(None, "feature-check.invalid", None))  # type: ignore[arg-type]
        self.assertEqual(guard.observed_name, "feature-check.invalid")
        self.assertEqual(
            guard(None, "wrong.invalid", None),  # type: ignore[arg-type]
            ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME,
        )
        self.assertEqual(guard.observed_name, "wrong.invalid")


@unittest.skipUnless(
    os.name == "posix" and shutil.which("openssl"),
    "TLS parent integration requires POSIX and OpenSSL",
)
class TlsConnectParentIntegrationTests(unittest.TestCase):
    def test_probe_captures_verified_sni_and_connect_then_returns_200(self) -> None:
        openssl = shutil.which("openssl")
        assert openssl is not None
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            certificate = root / "server.crt"
            private_key = root / "server.key"
            subprocess.run(
                [
                    openssl,
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-sha256",
                    "-days",
                    "1",
                    "-keyout",
                    str(private_key),
                    "-out",
                    str(certificate),
                    "-subj",
                    "/CN=feature-check.invalid",
                    "-addext",
                    "subjectAltName=DNS:feature-check.invalid",
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]

            process = subprocess.Popen(
                [
                    sys.executable,
                    str(ROOT / "tools" / "build_checks.py"),
                    "tls-connect-parent",
                    "--port",
                    str(port),
                    "--cert",
                    str(certificate),
                    "--key",
                    str(private_key),
                    "--expected-sni",
                    "feature-check.invalid",
                    "--expected-authority",
                    "127.0.0.1:443",
                    "--timeout",
                    "5",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.addCleanup(self._stop_process, process)
            assert process.stdout is not None
            ready, _, _ = select.select([process.stdout], [], [], 5)
            self.assertTrue(ready, "TLS parent did not report readiness")
            ready_line = process.stdout.readline()
            self.assertIn("PROBE_READY", ready_line)

            context = ssl.create_default_context(cafile=str(certificate))
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
                with context.wrap_socket(
                    raw, server_hostname="feature-check.invalid"
                ) as connection:
                    connection.sendall(
                        b"CONNECT 127.0.0.1:443 HTTP/1.1\r\n"
                        b"Host: 127.0.0.1:443\r\n\r\n"
                    )
                    response = connection.recv(4096)

            remaining_stdout, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, stderr)
            self.assertIn(b"HTTP/1.1 200 Connection Established", response)
            self.assertIn(
                "PROBE_OK sni=feature-check.invalid authority=127.0.0.1:443 http=1.1",
                remaining_stdout,
            )
            self.assertEqual(stderr, "")

    @staticmethod
    def _stop_process(process: subprocess.Popen[str]) -> None:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)


if __name__ == "__main__":
    unittest.main()
