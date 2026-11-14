"""Native OpenSSL 3proxy gates; run with THREEPROXY_BINARY pointing at pinned build."""
from __future__ import annotations

import copy
import http.server
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import threading
import unittest
from unittest import mock

from test_schema_v2 import profile
import config
import healthcheck_v2


@unittest.skipUnless(os.name == "posix" and os.environ.get("THREEPROXY_BINARY") and shutil.which("openssl"),
                     "native Linux/OpenSSL 3proxy opt-in")
class DualstackCertificateRuntimeTests(unittest.TestCase):
    def test_socks_auth_probe_checks_real_connect_and_detects_open_access(self):
        for mode in ("strong", "open", "invalid-is-valid"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix="socks-auth-") as temporary:
                root = Path(temporary)
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as target:
                    target.bind(("127.0.0.1", 0)); target.listen(); target.settimeout(.2)
                    target_address = target.getsockname()
                    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as reserved:
                        reserved.bind(("::", 0)); port = reserved.getsockname()[1]
                    auth = {"strong": "users fixture:CL:fixture-password\nauth strong\nallow fixture\n",
                            "open": "auth none\n",
                            "invalid-is-valid": "users invalid:CL:invalid\nauth strong\nallow invalid\n"}[mode]
                    path = root / "3proxy.cfg"; path.write_text(auth + f"socks -i:: -p{port} -46\n")
                    with (root / "stdout.log").open("w") as output:
                        process = subprocess.Popen([os.environ["THREEPROXY_BINARY"], str(path)], stdout=output, stderr=output)
                        try:
                            deadline = time.monotonic() + 5
                            while True:
                                try:
                                    with socket.create_connection(("127.0.0.1", port), timeout=.2): pass
                                    break
                                except OSError:
                                    if process.poll() is not None or time.monotonic() > deadline:
                                        self.fail("SOCKS fixture did not start")
                                    time.sleep(.03)
                            for host in ("127.0.0.1", "::1"):
                                for wrong in ((False, True) if mode == "strong" else (mode == "invalid-is-valid",)):
                                    with socket.create_connection((host, port), timeout=3) as client:
                                        if mode == "strong":
                                            result = healthcheck_v2.socks_auth_rejected(client, wrong=wrong, probe_target=target_address)
                                            self.assertIn("CONNECT (REP=2)", result)
                                            with self.assertRaises(socket.timeout): target.accept()
                                        else:
                                            with self.assertRaisesRegex(ValueError, "REP=0"):
                                                healthcheck_v2.socks_auth_rejected(client, wrong=wrong, probe_target=target_address)
                                            accepted, _ = target.accept(); accepted.close()
                        finally:
                            process.terminate()
                            try: process.wait(timeout=5)
                            except subprocess.TimeoutExpired:
                                process.kill(); process.wait(timeout=3)

    def test_two_listeners_keep_distinct_certificates_on_both_families(self):
        with tempfile.TemporaryDirectory(prefix="3proxy-dualstack-") as directory:
            root = Path(directory)
            def openssl(*args):
                subprocess.run(["openssl", *args], cwd=root, check=True, capture_output=True, timeout=30)
            openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.crt",
                    "-days", "3", "-subj", "/CN=dualstack-test-root", "-addext", "basicConstraints=critical,CA:TRUE")
            data = profile()
            sockets = []
            try:
                for _ in range(3):
                    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                    sock.bind(("::", 0)); sockets.append(sock)
                ports = [sock.getsockname()[1] for sock in sockets]
            finally:
                for sock in sockets: sock.close()
            first = data["listeners"][0]
            first["port"] = ports[0]
            first["outbound"]["family"] = "prefer_ipv4"
            data["probes"]["egress"]["direct"]["ipv6"] = {"expected_ips": ["2001:db8::1"]}
            second = copy.deepcopy(first)
            second.update(id="second", port=ports[1], tls_certificate="other")
            second["endpoint"]["host"] = "other.example.test"
            data["listeners"].append(second)
            iponly = copy.deepcopy(first)
            iponly.update(id="iponly", port=ports[2], access=dict(mode="iponly", allowed_client_cidrs=["127.0.0.1/32", "::/1"]))
            data["listeners"].append(iponly)
            data["tls"]["certificates"]["other"] = {"mode": "acme", "identifiers": ["other.example.test"], "acme": {"agree_tos": True}}
            expected = {}
            for name, host in [("dns", "proxy.example.test"), ("other", "other.example.test")]:
                cert_dir = root / "tls" / name
                cert_dir.mkdir(parents=True)
                ext = root / (name + ".ext")
                ext.write_text(f"basicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:{host}\n")
                openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(cert_dir / "server.key"),
                        "-out", name + ".csr", "-subj", "/CN=unused-common-name")
                openssl("x509", "-req", "-in", name + ".csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial",
                        "-days", "2", "-extfile", str(ext), "-out", str(cert_dir / "server.crt"))
                expected[name] = ssl.PEM_cert_to_DER_cert((cert_dir / "server.crt").read_text())
            p = config.paths("dev")
            p.update(CONFIG_DIR=str(root), LOG_DIR=str(root))
            config.validate(data)
            with mock.patch.object(config, "paths", return_value=p):
                rendered = config.render_3proxy(data)
            path = root / "proxy.cfg"; path.write_text(rendered)
            with (root / "process.log").open("w") as log:
                process = subprocess.Popen([os.environ["THREEPROXY_BINARY"], str(path)], stdout=log, stderr=log)
                try:
                    context = ssl.create_default_context(cafile=str(root / "ca.crt"))
                    context.minimum_version = ssl.TLSVersion.TLSv1_2
                    for port in ports:
                        deadline = time.monotonic() + 8
                        while True:
                            try:
                                with socket.create_connection(("127.0.0.1", port), timeout=.3): pass
                                break
                            except OSError:
                                if process.poll() is not None or time.monotonic() >= deadline:
                                    self.fail("3proxy did not bind test listeners: " + (root / "process.log").read_text())
                                time.sleep(.05)
                    for host in ("127.0.0.1", "::1"):
                        for index, name in enumerate(("dns", "other")):
                            identity = data["listeners"][index]["endpoint"]["host"]
                            with self.subTest(host=host, certificate=name):
                                with socket.create_connection((host, ports[index]), timeout=3) as raw:
                                    with context.wrap_socket(raw, server_hostname=identity) as secure:
                                        self.assertEqual(secure.getpeercert(binary_form=True), expected[name])
                                        secure.sendall(b"CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n")
                                        self.assertIn(b" 407 ", secure.recv(4096).split(b"\r\n", 1)[0])
                                with socket.create_connection((host, ports[index]), timeout=3) as raw:
                                    with self.assertRaises(ssl.SSLCertVerificationError):
                                        context.wrap_socket(raw, server_hostname="wrong.example.test")
                    class Handler(http.server.BaseHTTPRequestHandler):
                        def log_message(self, *_): pass
                        def do_GET(self):
                            value = self.client_address[0].encode()
                            self.send_response(200)
                            self.send_header("Content-Length", str(len(value)))
                            self.end_headers(); self.wfile.write(value)
                    class IPv6Server(http.server.ThreadingHTTPServer):
                        address_family = socket.AF_INET6
                    for target, server_class in [("127.0.0.1", http.server.ThreadingHTTPServer), ("::1", IPv6Server)]:
                        server = server_class((target, 0), Handler)
                        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
                        try:
                            for ingress in ("127.0.0.1", "::1"):
                                for connect in (False, True):
                                    with self.subTest(ingress=ingress, target=target, connect=connect):
                                        result = healthcheck_v2.forwarding("https", ingress, ports[0], "test-user", "test-password",
                                            target, server.server_port, target, 3, connect=connect,
                                            tls=dict(tls_server_name="proxy.example.test", ca_file=str(root / "ca.crt")))
                                        self.assertEqual(result, target)
                                with self.subTest(ingress=ingress, target=target, access="iponly"):
                                    result = healthcheck_v2.forwarding("https", ingress, ports[2], None, None,
                                        target, server.server_port, target, 3, connect=True,
                                        tls=dict(tls_server_name="proxy.example.test", ca_file=str(root / "ca.crt")))
                                    self.assertEqual(result, target)
                            with socket.create_connection(("127.0.0.1", ports[2]), timeout=3, source_address=("127.0.0.2", 0)) as raw:
                                with context.wrap_socket(raw, server_hostname="proxy.example.test") as secure:
                                    secure.sendall(b"CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n")
                                    self.assertIn(b" 403 ", secure.recv(4096).split(b"\r\n", 1)[0])
                        finally:
                            server.shutdown(); server.server_close(); thread.join(timeout=3)
                finally:
                    process.terminate()
                    try: process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill(); process.wait(timeout=5)
