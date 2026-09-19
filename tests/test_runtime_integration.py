from __future__ import annotations

import base64
import contextlib
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


ROOT = Path(__file__).resolve().parents[1]
BINARY_ENV = os.environ.get("THREEPROXY_BINARY")
RUNTIME_ENABLED = bool(BINARY_ENV) and os.name == "posix"

DUMMY_LOCAL_USER = "runtime_local_dummy"
DUMMY_LOCAL_PASSWORD = "RuntimeLocalDummy_91"
DUMMY_UPSTREAM_USER = "runtime_parent_dummy"
DUMMY_UPSTREAM_PASSWORD = "RuntimeParentDummy_73"
GOOD_PARENT_NAME = "parent.runtime.test"
WRONG_PARENT_NAME = "wrong-parent.runtime.test"
SENTINEL_PREFIX = b"runtime-sentinel:"


def _basic_value(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


def _recv_header(sock: socket.socket, limit: int = 64 * 1024) -> bytes:
    data = bytearray()
    while b"\r\n\r\n" not in data and len(data) < limit:
        try:
            chunk = sock.recv(min(4096, limit - len(data)))
        except (ConnectionResetError, socket.timeout):
            break
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("unexpected EOF")
        data.extend(chunk)
    return bytes(data)


def _unused_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = int(sock.getsockname()[1])
    if port < 20_000:
        return _unused_loopback_port()
    return port


class _SentinelTarget:
    def __init__(self, port_last_digit: int | None = None) -> None:
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if port_last_digit is None:
            self._listener.bind(("127.0.0.1", 0))
        else:
            for candidate in range(24000 + port_last_digit, 65000, 10):
                try:
                    self._listener.bind(("127.0.0.1", candidate))
                    break
                except OSError:
                    continue
            else:
                raise RuntimeError("no free sentinel port with the requested final digit")
        self._listener.listen()
        self._listener.settimeout(0.1)
        self.port = int(self._listener.getsockname()[1])
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._connections = 0
        self._payloads: list[bytes] = []
        self._thread = threading.Thread(target=self._serve, name="runtime-sentinel", daemon=True)

    @property
    def payloads(self) -> list[bytes]:
        with self._lock:
            return list(self._payloads)

    @property
    def hit_count(self) -> int:
        with self._lock:
            return self._connections

    def start(self) -> "_SentinelTarget":
        self._thread.start()
        return self

    def close(self) -> None:
        self._stop.set()
        self._listener.close()
        self._thread.join(timeout=2)

    def __enter__(self) -> "_SentinelTarget":
        return self.start()

    def __exit__(self, *unused: object) -> None:
        self.close()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                client, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self._lock:
                self._connections += 1
            with client:
                client.settimeout(3)
                try:
                    payload = client.recv(64 * 1024)
                except (ConnectionResetError, socket.timeout):
                    payload = b""
                if not payload:
                    continue
                with self._lock:
                    self._payloads.append(payload)
                try:
                    client.sendall(SENTINEL_PREFIX + payload)
                except (BrokenPipeError, ConnectionResetError, socket.timeout):
                    pass


class _TlsConnectParent:
    def __init__(
        self,
        certificate: Path,
        private_key: Path,
        allowed_target: tuple[str, int],
        expected_username: str | None = DUMMY_UPSTREAM_USER,
        expected_password: str | None = DUMMY_UPSTREAM_PASSWORD,
    ) -> None:
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen()
        self._listener.settimeout(0.1)
        self.port = int(self._listener.getsockname()[1])
        self._allowed_target = allowed_target
        if (expected_username is None) != (expected_password is None):
            raise ValueError("expected parent username and password must be provided together")
        self._expected_authorization = (
            None
            if expected_username is None
            else _basic_value(expected_username, expected_password)
        )
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._context.minimum_version = ssl.TLSVersion.TLSv1_2
        self._context.load_cert_chain(certificate, private_key)
        self._context.set_servername_callback(self._record_sni)
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._attempt_done = threading.Event()
        self._handlers: list[threading.Thread] = []
        self.raw_prefixes: list[bytes] = []
        self.plaintext_requests: list[bytes] = []
        self.sni_names: list[str | None] = []
        self.requests: list[bytes] = []
        self.authorization_values: list[str] = []
        self.auth_rejections = 0
        self.connect_targets: list[tuple[str, int]] = []
        self.tls_sessions = 0
        self.tls_errors: list[str] = []
        self.errors: list[str] = []
        self._thread = threading.Thread(target=self._serve, name="runtime-tls-parent", daemon=True)

    @property
    def connection_count(self) -> int:
        with self._lock:
            return len(self.raw_prefixes)

    def start(self) -> "_TlsConnectParent":
        self._thread.start()
        return self

    def close(self) -> None:
        self._stop.set()
        self._listener.close()
        self._thread.join(timeout=2)
        for handler in self._handlers:
            handler.join(timeout=1)

    def wait_for_attempt(self, timeout: float = 4) -> bool:
        return self._attempt_done.wait(timeout)

    def __enter__(self) -> "_TlsConnectParent":
        return self.start()

    def __exit__(self, *unused: object) -> None:
        self.close()

    def _record_sni(self, unused_socket: ssl.SSLSocket, server_name: str | None, unused_context: ssl.SSLContext) -> None:
        with self._lock:
            self.sni_names.append(server_name)

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                client, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            handler = threading.Thread(target=self._handle, args=(client,), daemon=True)
            self._handlers.append(handler)
            handler.start()

    def _handle(self, client: socket.socket) -> None:
        client.settimeout(4)
        tls_client: ssl.SSLSocket | None = None
        try:
            prefix = b""
            peek_deadline = time.monotonic() + 1
            while len(prefix) < 3 and time.monotonic() < peek_deadline:
                prefix = client.recv(8, socket.MSG_PEEK)
                if len(prefix) < 3:
                    time.sleep(0.002)
            with self._lock:
                self.raw_prefixes.append(prefix)
            if not prefix.startswith(b"\x16\x03"):
                plaintext = _recv_header(client)
                with self._lock:
                    self.plaintext_requests.append(plaintext)
                return

            try:
                tls_client = self._context.wrap_socket(client, server_side=True)
            except ssl.SSLError as exc:
                with self._lock:
                    self.tls_errors.append(str(exc))
                return
            with self._lock:
                self.tls_sessions += 1

            request = _recv_header(tls_client)
            with self._lock:
                self.requests.append(request)
            request_line, authorization_values = self._parse_request(request)
            with self._lock:
                self.authorization_values.extend(authorization_values)
            authorization_matches = (
                not authorization_values
                if self._expected_authorization is None
                else self._expected_authorization in authorization_values
            )
            if not authorization_matches:
                try:
                    tls_client.sendall(
                        b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                        b'Proxy-Authenticate: Basic realm="runtime-test"\r\n'
                        b"Content-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                    with self._lock:
                        self.auth_rejections += 1
                except (ssl.SSLEOFError, BrokenPipeError, ConnectionResetError):
                    # 3proxy may close as soon as it consumes this deliberate rejection.
                    # Keep all errors outside this one expected peer-close path observable.
                    pass
                return

            target = self._connect_target(request_line)
            if target is None or target != self._allowed_target:
                tls_client.sendall(
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                return
            with self._lock:
                self.connect_targets.append(target)

            with socket.create_connection(target, timeout=3) as destination:
                destination.settimeout(3)
                tls_client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                payload = tls_client.recv(64 * 1024)
                if not payload:
                    return
                destination.sendall(payload)
                response = destination.recv(64 * 1024)
                if response:
                    tls_client.sendall(response)
        except (ConnectionError, OSError, ValueError) as exc:
            if not self._stop.is_set():
                with self._lock:
                    self.errors.append(f"{type(exc).__name__}: {exc}")
        finally:
            self._attempt_done.set()
            if tls_client is not None:
                with contextlib.suppress(OSError):
                    tls_client.close()
            else:
                with contextlib.suppress(OSError):
                    client.close()

    @staticmethod
    def _parse_request(request: bytes) -> tuple[str, list[str]]:
        lines = request.decode("iso-8859-1", errors="replace").split("\r\n")
        request_line = lines[0] if lines else ""
        authorization_values = [
            line.split(":", 1)[1].strip()
            for line in lines[1:]
            if line.lower().startswith("proxy-authorization:")
        ]
        return request_line, authorization_values

    @staticmethod
    def _connect_target(request_line: str) -> tuple[str, int] | None:
        match = re.fullmatch(r"CONNECT ([^: ]+):(\d+) HTTP/\d\.\d", request_line)
        if match is None:
            return None
        return match.group(1), int(match.group(2))


@dataclass(frozen=True)
class _ProxyResult:
    status: int | None
    header: bytes
    tunneled: bytes


@dataclass
class _RunningProxy:
    process: subprocess.Popen[bytes]
    stdout_path: Path
    config_path: Path

    def diagnostics(self) -> str:
        with contextlib.suppress(OSError):
            return self.stdout_path.read_text(encoding="utf-8", errors="replace")
        return "<3proxy stdout unavailable>"


@unittest.skipUnless(
    RUNTIME_ENABLED,
    "set THREEPROXY_BINARY to an OpenSSL-enabled POSIX 3proxy binary",
)
class GeneratedHttpsBridgeRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        assert BINARY_ENV is not None
        resolved = shutil.which(BINARY_ENV)
        if resolved is None:
            candidate = Path(BINARY_ENV).expanduser()
            if candidate.is_file():
                resolved = str(candidate.resolve())
        if resolved is None or not os.access(resolved, os.X_OK):
            raise AssertionError(f"THREEPROXY_BINARY is not executable: {BINARY_ENV}")
        cls.binary = Path(resolved)

        cls.openssl = shutil.which("openssl")
        if cls.openssl is None:
            raise unittest.SkipTest("openssl CLI is required to generate isolated test certificates")

        sys.path.insert(0, str(ROOT / "tools"))
        import config as config_tool  # noqa: PLC0415

        cls.config_tool = config_tool
        cls._temporary = tempfile.TemporaryDirectory(prefix="threeproxy-runtime-")
        cls.temporary_root = Path(cls._temporary.name)
        cls.ca_certificate, cls.server_certificate, cls.server_key = cls._generate_certificate_chain(
            "trusted", GOOD_PARENT_NAME
        )
        cls.untrusted_ca_certificate, _, _ = cls._generate_certificate_chain(
            "untrusted", "untrusted-parent.runtime.test"
        )

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "_temporary"):
            cls._temporary.cleanup()
        super().tearDownClass()

    @classmethod
    def _run_openssl(cls, *arguments: str) -> None:
        completed = subprocess.run(
            [cls.openssl, *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=20,
        )
        if completed.returncode != 0:
            raise RuntimeError(
                f"openssl {' '.join(arguments[:2])} failed ({completed.returncode}): {completed.stderr}"
            )

    @classmethod
    def _generate_certificate_chain(cls, stem: str, hostname: str) -> tuple[Path, Path, Path]:
        directory = cls.temporary_root / stem
        directory.mkdir(mode=0o700)
        ca_config = directory / "ca.cnf"
        ca_key = directory / "ca.key"
        ca_certificate = directory / "ca.pem"
        leaf_config = directory / "leaf.cnf"
        leaf_key = directory / "leaf.key"
        leaf_request = directory / "leaf.csr"
        leaf_certificate = directory / "leaf.pem"
        ca_config.write_text(
            "[req]\n"
            "distinguished_name = dn\n"
            "prompt = no\n"
            "x509_extensions = v3_ca\n"
            "[dn]\n"
            f"CN = {stem} 3proxy runtime dummy CA\n"
            "[v3_ca]\n"
            "basicConstraints = critical,CA:TRUE\n"
            "keyUsage = critical,keyCertSign,cRLSign\n"
            "subjectKeyIdentifier = hash\n",
            encoding="utf-8",
        )
        leaf_config.write_text(
            "[req]\n"
            "distinguished_name = dn\n"
            "prompt = no\n"
            "req_extensions = server_ext\n"
            "[dn]\n"
            f"CN = {hostname}\n"
            "[server_ext]\n"
            f"subjectAltName = DNS:{hostname}\n"
            "basicConstraints = critical,CA:FALSE\n"
            "keyUsage = critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage = serverAuth\n",
            encoding="utf-8",
        )
        cls._run_openssl(
            "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "2",
            "-config", str(ca_config), "-keyout", str(ca_key), "-out", str(ca_certificate),
        )
        cls._run_openssl(
            "req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256",
            "-config", str(leaf_config), "-keyout", str(leaf_key), "-out", str(leaf_request),
        )
        cls._run_openssl(
            "x509", "-req", "-in", str(leaf_request), "-CA", str(ca_certificate),
            "-CAkey", str(ca_key), "-CAcreateserial", "-days", "2", "-sha256",
            "-extfile", str(leaf_config), "-extensions", "server_ext", "-out", str(leaf_certificate),
        )
        return ca_certificate, leaf_certificate, leaf_key

    def _render_config(
        self,
        directory: Path,
        listener_port: int,
        parent_port: int,
        ca_file: Path,
        server_name: str = GOOD_PARENT_NAME,
        upstream_password: str = DUMMY_UPSTREAM_PASSWORD,
        upstream_auth: bool = True,
        listeners: list[dict[str, object]] | None = None,
        access_mode: str = "strong",
    ) -> Path:
        https_upstream = {
            "type": "https",
            "host": "127.0.0.1",
            "port": parent_port,
            "tls_server_name": server_name,
            "expected_egress_ip": "127.0.0.1",
            "capabilities": ["tcp"],
        }
        if upstream_auth:
            https_upstream.update({
                "username": DUMMY_UPSTREAM_USER,
                "password": upstream_password,
            })
        data = {
            "install": {
                "version": self.config_tool.INSTALL_VERSION,
                "source_url": self.config_tool.INSTALL_SOURCE_URL,
                "sha256": self.config_tool.INSTALL_SHA256,
            },
            "server": {
                "public_ip": "127.0.0.1",
                "listen_ip": "127.0.0.1",
                "udp_client_cidr": "127.0.0.1/32",
                "manage_ufw": False,
            },
            "tls": {"client_ca_file": str(ca_file)},
            "logging": {
                "format": "monitor_v1",
                "rotation": "daily",
                "keep_files": 1,
                "compress": False,
            },
            "access": {
                "mode": access_mode,
                "allowed_client_cidrs": ["127.0.0.1/32"] if access_mode == "iponly" else [],
            },
            "upstreams": {
                "https_primary": https_upstream,
            },
            "listeners": listeners or [
                {
                    "id": "runtime.https-http",
                    "protocol": "http",
                    "listen_ip": "127.0.0.1",
                    "port": listener_port,
                    "parent": "https_primary",
                    "capabilities": ["tcp"],
                }
            ],
            "probes": {"timeout_seconds": 3, "stun_servers": ["127.0.0.1:9"]},
        }
        if access_mode == "strong":
            data["local_auth"] = {
                "username": DUMMY_LOCAL_USER,
                "password": DUMMY_LOCAL_PASSWORD,
            }
        effective_listeners = listeners or data["listeners"]
        if any(listener["protocol"] == "https" for listener in effective_listeners):
            data["tls"]["server"] = {
                "dns_names": [GOOD_PARENT_NAME],
                "validity_days": 2,
                "ca_validity_days": 3,
                "regenerate_on_setup": False,
            }
        self.config_tool.validate(data)
        rendered = self.config_tool.render_3proxy(data)
        if any(listener["protocol"] == "https" for listener in effective_listeners):
            rendered = rendered.replace(
                self.config_tool.MANAGED_TLS_SERVER_CERT_FILE,
                str(self.server_certificate),
            ).replace(
                self.config_tool.MANAGED_TLS_SERVER_KEY_FILE,
                str(self.server_key),
            )
        production_log = "log /var/log/3proxy/3proxy.log D"
        self.assertEqual(rendered.count(production_log), 1)
        rendered = rendered.replace(production_log, f"log {directory / '3proxy.log'} D")
        self.assertEqual(rendered.count("maxconn 1000"), 1)
        rendered = rendered.replace("maxconn 1000", "maxconn 1000\nparentretries 1")
        config_path = directory / "3proxy.cfg"
        config_path.write_text(rendered, encoding="utf-8", newline="\n")
        config_path.chmod(0o600)
        return config_path

    @contextlib.contextmanager
    def _running_proxy(
        self,
        scenario: str,
        listener_port: int,
        parent_port: int,
        ca_file: Path,
        server_name: str = GOOD_PARENT_NAME,
        upstream_password: str = DUMMY_UPSTREAM_PASSWORD,
        upstream_auth: bool = True,
        listeners: list[dict[str, object]] | None = None,
        access_mode: str = "strong",
    ) -> Iterator[_RunningProxy]:
        directory = self.temporary_root / scenario
        directory.mkdir(mode=0o700)
        config_path = self._render_config(
            directory,
            listener_port,
            parent_port,
            ca_file,
            server_name=server_name,
            upstream_password=upstream_password,
            upstream_auth=upstream_auth,
            listeners=listeners,
            access_mode=access_mode,
        )
        stdout_path = directory / "3proxy.stdout"
        with stdout_path.open("wb") as stdout:
            process = subprocess.Popen(
                [str(self.binary), str(config_path)],
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=subprocess.STDOUT,
                cwd=directory,
            )
            running = _RunningProxy(process, stdout_path, config_path)
            try:
                listener_ports = (
                    [listener_port]
                    if listeners is None
                    else [int(listener["port"]) for listener in listeners]
                )
                for port in listener_ports:
                    self._wait_for_listener(running, port)
                yield running
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=8)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)

    def _wait_for_listener(self, running: _RunningProxy, port: int) -> None:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            return_code = running.process.poll()
            if return_code is not None:
                self.fail(
                    f"3proxy exited before listener startup (rc={return_code}):\n{running.diagnostics()}"
                )
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    return
            except OSError:
                time.sleep(0.03)
        self.fail(f"3proxy listener 127.0.0.1:{port} did not start:\n{running.diagnostics()}")

    def _proxy_connect(
        self,
        proxy_port: int,
        target_port: int,
        credentials: tuple[str, str] | None,
        payload: bytes,
    ) -> _ProxyResult:
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=3) as client:
            client.settimeout(5)
            lines = [
                f"CONNECT 127.0.0.1:{target_port} HTTP/1.1",
                f"Host: 127.0.0.1:{target_port}",
            ]
            if credentials is not None:
                lines.append(f"Proxy-Authorization: {_basic_value(*credentials)}")
            client.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
            header = _recv_header(client)
            match = re.match(rb"HTTP/\d\.\d (\d{3})", header)
            status = int(match.group(1)) if match else None
            tunneled = b""
            if status is not None and 200 <= status < 300:
                client.sendall(payload)
                expected_size = len(SENTINEL_PREFIX) + len(payload)
                chunks = bytearray()
                while len(chunks) < expected_size:
                    try:
                        chunk = client.recv(expected_size - len(chunks))
                    except (ConnectionResetError, socket.timeout):
                        break
                    if not chunk:
                        break
                    chunks.extend(chunk)
                tunneled = bytes(chunks)
            return _ProxyResult(status, header, tunneled)

    def _https_proxy_connect(
        self,
        proxy_port: int,
        target_port: int,
        credentials: tuple[str, str] | None,
        payload: bytes,
        *,
        ca_file: Path | None = None,
        server_name: str = GOOD_PARENT_NAME,
    ) -> _ProxyResult:
        context = ssl.create_default_context(cafile=str(ca_file or self.ca_certificate))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=3) as raw:
            with context.wrap_socket(raw, server_hostname=server_name) as client:
                client.settimeout(5)
                lines = [
                    f"CONNECT 127.0.0.1:{target_port} HTTP/1.1",
                    f"Host: 127.0.0.1:{target_port}",
                ]
                if credentials is not None:
                    lines.append(f"Proxy-Authorization: {_basic_value(*credentials)}")
                client.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
                header = _recv_header(client)
                match = re.match(rb"HTTP/\d\.\d (\d{3})", header)
                status = int(match.group(1)) if match else None
                tunneled = b""
                if status is not None and 200 <= status < 300:
                    client.sendall(payload)
                    tunneled = _recv_exact(client, len(SENTINEL_PREFIX) + len(payload))
                return _ProxyResult(status, header, tunneled)

    def _plaintext_proxy_status(self, proxy_port: int, target_port: int) -> int | None:
        try:
            return self._proxy_connect(proxy_port, target_port, None, b"plaintext-must-fail").status
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError, socket.timeout):
            return None

    def _socks_connect(
        self,
        proxy_port: int,
        target_port: int,
        payload: bytes,
    ) -> bytes:
        username = DUMMY_LOCAL_USER.encode("utf-8")
        password = DUMMY_LOCAL_PASSWORD.encode("utf-8")
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=3) as client:
            client.settimeout(5)
            client.sendall(b"\x05\x01\x02")
            self.assertEqual(_recv_exact(client, 2), b"\x05\x02")
            client.sendall(
                b"\x01"
                + bytes([len(username)])
                + username
                + bytes([len(password)])
                + password
            )
            self.assertEqual(_recv_exact(client, 2), b"\x01\x00")
            client.sendall(
                b"\x05\x01\x00\x01"
                + socket.inet_aton("127.0.0.1")
                + target_port.to_bytes(2, "big")
            )
            version, status, reserved, address_type = _recv_exact(client, 4)
            self.assertEqual((version, status, reserved), (5, 0, 0))
            if address_type == 1:
                _recv_exact(client, 4)
            elif address_type == 3:
                _recv_exact(client, _recv_exact(client, 1)[0])
            elif address_type == 4:
                _recv_exact(client, 16)
            else:
                self.fail(f"unexpected SOCKS5 BND address type: {address_type}")
            _recv_exact(client, 2)

            client.sendall(payload)
            expected_size = len(SENTINEL_PREFIX) + len(payload)
            response = _recv_exact(client, expected_size)
        return response

    def _socks4_noauth_connect(
        self,
        proxy_port: int,
        target_port: int,
        payload: bytes,
    ) -> bytes:
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=3) as client:
            client.settimeout(5)
            client.sendall(
                b"\x04\x01"
                + target_port.to_bytes(2, "big")
                + socket.inet_aton("127.0.0.1")
                + b"\x00"
            )
            version, status = _recv_exact(client, 2)
            _recv_exact(client, 6)
            self.assertEqual((version, status), (0, 0x5A))
            client.sendall(payload)
            response = _recv_exact(client, len(SENTINEL_PREFIX) + len(payload))
        return response

    def _socks_udp_associate_status(self, proxy_port: int) -> int | None:
        username = DUMMY_LOCAL_USER.encode("utf-8")
        password = DUMMY_LOCAL_PASSWORD.encode("utf-8")
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=3) as client:
            client.settimeout(5)
            client.sendall(b"\x05\x01\x02")
            self.assertEqual(_recv_exact(client, 2), b"\x05\x02")
            client.sendall(
                b"\x01"
                + bytes([len(username)])
                + username
                + bytes([len(password)])
                + password
            )
            self.assertEqual(_recv_exact(client, 2), b"\x01\x00")
            client.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
            try:
                version, status, reserved, _address_type = _recv_exact(client, 4)
            except (ConnectionError, ConnectionAbortedError, ConnectionResetError):
                return None
        self.assertEqual((version, reserved), (5, 0))
        return status

    def _assert_tls_only(self, parent: _TlsConnectParent) -> None:
        self.assertGreaterEqual(parent.connection_count, 1, "3proxy never contacted the configured parent")
        self.assertFalse(
            parent.plaintext_requests,
            f"plaintext reached the HTTPS parent: {parent.plaintext_requests!r}",
        )
        self.assertTrue(
            all(prefix.startswith(b"\x16\x03") for prefix in parent.raw_prefixes),
            f"first parent bytes were not TLS ClientHello records: {parent.raw_prefixes!r}",
        )

    def test_https_frontend_is_verified_tls_only_and_keeps_local_auth_inside_tls(self) -> None:
        listener_port = _unused_loopback_port()
        payload = b"https-frontend-direct"
        listeners: list[dict[str, object]] = [
            {
                "id": "runtime.https-direct",
                "protocol": "https",
                "listen_ip": "127.0.0.1",
                "port": listener_port,
                "parent": "direct",
                "capabilities": ["tcp"],
            }
        ]
        with _SentinelTarget() as sentinel:
            with self._running_proxy(
                "https-frontend-direct",
                listener_port,
                _unused_loopback_port(),
                self.ca_certificate,
                listeners=listeners,
            ) as running:
                rendered = running.config_path.read_text(encoding="utf-8")
                block = rendered[rendered.index("# runtime.https-direct"):]
                self.assertIn("ssl_serv\nauth strong", block)
                self.assertIn(f"proxy -i127.0.0.1 -p{listener_port}\nssl_noserv\nflush", block)
                self.assertNotIn("ssl_cli", block)

                self.assertIsNone(self._plaintext_proxy_status(listener_port, sentinel.port))
                unauthenticated = self._https_proxy_connect(
                    listener_port,
                    sentinel.port,
                    None,
                    payload,
                )
                self.assertEqual(unauthenticated.status, 407)
                self.assertEqual(sentinel.hit_count, 0)

                with self.assertRaises(ssl.SSLCertVerificationError):
                    self._https_proxy_connect(
                        listener_port,
                        sentinel.port,
                        (DUMMY_LOCAL_USER, DUMMY_LOCAL_PASSWORD),
                        payload,
                        ca_file=self.untrusted_ca_certificate,
                    )
                with self.assertRaises(ssl.SSLCertVerificationError):
                    self._https_proxy_connect(
                        listener_port,
                        sentinel.port,
                        (DUMMY_LOCAL_USER, DUMMY_LOCAL_PASSWORD),
                        payload,
                        server_name=WRONG_PARENT_NAME,
                    )
                self.assertEqual(sentinel.hit_count, 0)

                result = self._https_proxy_connect(
                    listener_port,
                    sentinel.port,
                    (DUMMY_LOCAL_USER, DUMMY_LOCAL_PASSWORD),
                    payload,
                )
                self.assertEqual(result.status, 200, running.diagnostics())
                self.assertEqual(result.tunneled, SENTINEL_PREFIX + payload)
            self.assertEqual(sentinel.hit_count, 1)
            self.assertEqual(sentinel.payloads, [payload])

    def test_https_frontend_direct_supports_iponly_without_basic_auth(self) -> None:
        listener_port = _unused_loopback_port()
        payload = b"https-frontend-iponly"
        listeners: list[dict[str, object]] = [
            {
                "id": "runtime.https-iponly",
                "protocol": "https",
                "listen_ip": "127.0.0.1",
                "port": listener_port,
                "parent": "direct",
                "capabilities": ["tcp"],
            }
        ]
        with _SentinelTarget() as sentinel:
            with self._running_proxy(
                "https-frontend-iponly",
                listener_port,
                _unused_loopback_port(),
                self.ca_certificate,
                listeners=listeners,
                access_mode="iponly",
            ) as running:
                rendered = running.config_path.read_text(encoding="utf-8")
                block = rendered[rendered.index("# runtime.https-iponly"):]
                self.assertIn(
                    "ssl_serv\nauth iponly\nallow * 127.0.0.1/32\ndeny *\n"
                    f"proxy -i127.0.0.1 -p{listener_port}\nssl_noserv\nflush",
                    block,
                )
                self.assertIsNone(self._plaintext_proxy_status(listener_port, sentinel.port))
                result = self._https_proxy_connect(
                    listener_port,
                    sentinel.port,
                    None,
                    payload,
                )
                self.assertEqual(result.status, 200, running.diagnostics())
                self.assertEqual(result.tunneled, SENTINEL_PREFIX + payload)
            self.assertEqual(sentinel.payloads, [payload])

    def test_https_frontend_to_https_parent_enables_both_tls_directions(self) -> None:
        listener_port = _unused_loopback_port()
        payload = b"https-frontend-to-https-parent"
        listeners: list[dict[str, object]] = [
            {
                "id": "runtime.https-to-https",
                "protocol": "https",
                "listen_ip": "127.0.0.1",
                "port": listener_port,
                "parent": "https_primary",
                "capabilities": ["tcp"],
            }
        ]
        with _SentinelTarget() as sentinel, _TlsConnectParent(
            self.server_certificate,
            self.server_key,
            ("127.0.0.1", sentinel.port),
        ) as parent:
            with self._running_proxy(
                "https-frontend-to-https-parent",
                listener_port,
                parent.port,
                self.ca_certificate,
                listeners=listeners,
            ) as running:
                rendered = running.config_path.read_text(encoding="utf-8")
                block = rendered[rendered.index("# runtime.https-to-https"):]
                self.assertIn(
                    "ssl_serv\nssl_cli\nauth strong\nallow " + DUMMY_LOCAL_USER,
                    block,
                )
                self.assertIn(
                    f"proxy -i127.0.0.1 -p{listener_port}\n"
                    "ssl_noserv\nssl_nocli\nflush",
                    block,
                )
                self.assertIsNone(self._plaintext_proxy_status(listener_port, sentinel.port))
                self.assertEqual(parent.connection_count, 0)
                result = self._https_proxy_connect(
                    listener_port,
                    sentinel.port,
                    (DUMMY_LOCAL_USER, DUMMY_LOCAL_PASSWORD),
                    payload,
                )
                self.assertTrue(parent.wait_for_attempt(), running.diagnostics())
                self.assertEqual(result.status, 200, running.diagnostics())
                self.assertEqual(result.tunneled, SENTINEL_PREFIX + payload)

            self._assert_tls_only(parent)
            self.assertEqual(parent.tls_sessions, 1)
            self.assertEqual(parent.connect_targets, [("127.0.0.1", sentinel.port)])
            self.assertEqual(sentinel.payloads, [payload])

    def test_tls_state_is_reset_before_plain_http_and_socks_listeners(self) -> None:
        https_port, http_port, socks_port = sorted(
            (_unused_loopback_port(), _unused_loopback_port(), _unused_loopback_port())
        )
        listeners: list[dict[str, object]] = [
            {
                "id": "runtime.https-first",
                "protocol": "https",
                "listen_ip": "127.0.0.1",
                "port": https_port,
                "parent": "https_primary",
                "capabilities": ["tcp"],
            },
            {
                "id": "runtime.http-after-tls",
                "protocol": "http",
                "listen_ip": "127.0.0.1",
                "port": http_port,
                "parent": "direct",
                "capabilities": ["tcp"],
            },
            {
                "id": "runtime.socks-after-tls",
                "protocol": "socks5",
                "listen_ip": "127.0.0.1",
                "port": socks_port,
                "parent": "direct",
                "capabilities": ["tcp"],
            },
        ]
        with _SentinelTarget() as sentinel, _TlsConnectParent(
            self.server_certificate,
            self.server_key,
            ("127.0.0.1", sentinel.port),
        ) as parent:
            with self._running_proxy(
                "tls-state-reset",
                https_port,
                parent.port,
                self.ca_certificate,
                listeners=listeners,
            ) as running:
                rendered = running.config_path.read_text(encoding="utf-8")
                secure_block = rendered[
                    rendered.index("# runtime.https-first"):rendered.index("# runtime.http-after-tls")
                ]
                plaintext_blocks = rendered[rendered.index("# runtime.http-after-tls"):]
                self.assertIn("ssl_noserv\nssl_nocli\nflush", secure_block)
                self.assertNotIn("ssl_serv", plaintext_blocks)
                self.assertNotIn("ssl_cli", plaintext_blocks)

                https_payload = b"secure-route"
                https_result = self._https_proxy_connect(
                    https_port,
                    sentinel.port,
                    (DUMMY_LOCAL_USER, DUMMY_LOCAL_PASSWORD),
                    https_payload,
                )
                self.assertEqual(https_result.status, 200, running.diagnostics())
                self.assertEqual(https_result.tunneled, SENTINEL_PREFIX + https_payload)

                http_payload = b"plaintext-http-route"
                http_result = self._proxy_connect(
                    http_port,
                    sentinel.port,
                    (DUMMY_LOCAL_USER, DUMMY_LOCAL_PASSWORD),
                    http_payload,
                )
                self.assertEqual(http_result.status, 200, running.diagnostics())
                self.assertEqual(http_result.tunneled, SENTINEL_PREFIX + http_payload)

                socks_payload = b"plaintext-socks-route"
                socks_result = self._socks_connect(socks_port, sentinel.port, socks_payload)
                self.assertEqual(socks_result, SENTINEL_PREFIX + socks_payload, running.diagnostics())

            self._assert_tls_only(parent)
            self.assertEqual(parent.tls_sessions, 1)
            self.assertEqual(parent.connect_targets, [("127.0.0.1", sentinel.port)])
            self.assertEqual(
                sentinel.payloads,
                [b"secure-route", b"plaintext-http-route", b"plaintext-socks-route"],
            )

    def test_tcp_only_socks_listener_rejects_udp_associate_before_https_parent(self) -> None:
        listener_port = _unused_loopback_port()
        payload = b"socks-tcp-only"
        listeners: list[dict[str, object]] = [
            {
                "id": "runtime.socks-tcp-only",
                "protocol": "socks5",
                "listen_ip": "127.0.0.1",
                "port": listener_port,
                "parent": "https_primary",
                "capabilities": ["tcp"],
            }
        ]
        with _SentinelTarget() as sentinel, _TlsConnectParent(
            self.server_certificate,
            self.server_key,
            ("127.0.0.1", sentinel.port),
        ) as parent:
            with self._running_proxy(
                "socks-tcp-only",
                listener_port,
                parent.port,
                self.ca_certificate,
                listeners=listeners,
            ) as running:
                rendered = running.config_path.read_text(encoding="utf-8")
                block = rendered[rendered.index("# runtime.socks-tcp-only"):]
                self.assertLess(
                    block.index("deny * * * * UDPASSOC"),
                    block.index("allow " + DUMMY_LOCAL_USER),
                )

                status = self._socks_udp_associate_status(listener_port)
                self.assertNotEqual(status, 0, running.diagnostics())
                self.assertEqual(parent.connection_count, 0, "UDP ASSOCIATE reached the parent")

                response = self._socks_connect(listener_port, sentinel.port, payload)
                self.assertEqual(response, SENTINEL_PREFIX + payload, running.diagnostics())
                self.assertTrue(parent.wait_for_attempt(), running.diagnostics())

            self._assert_tls_only(parent)
            self.assertEqual(parent.tls_sessions, 1)
            self.assertEqual(parent.connect_targets, [("127.0.0.1", sentinel.port)])
            self.assertEqual(sentinel.payloads, [payload])

    def test_authenticated_connect_roundtrip_is_tls_from_first_byte(self) -> None:
        listener_port = _unused_loopback_port()
        payload = b"positive-authenticated-connect"
        with _SentinelTarget() as sentinel, _TlsConnectParent(
            self.server_certificate,
            self.server_key,
            ("127.0.0.1", sentinel.port),
        ) as parent:
            with self._running_proxy(
                "positive", listener_port, parent.port, self.ca_certificate
            ) as running:
                unauthenticated = self._proxy_connect(listener_port, sentinel.port, None, payload)
                self.assertEqual(
                    unauthenticated.status,
                    407,
                    f"strong local auth was not enforced: {unauthenticated.header!r}\n{running.diagnostics()}",
                )
                self.assertEqual(parent.connection_count, 0, "unauthenticated traffic reached the parent")

                result = self._proxy_connect(
                    listener_port,
                    sentinel.port,
                    (DUMMY_LOCAL_USER, DUMMY_LOCAL_PASSWORD),
                    payload,
                )
                self.assertTrue(parent.wait_for_attempt(), "TLS parent did not finish the CONNECT attempt")
                self.assertEqual(result.status, 200, f"CONNECT failed: {result.header!r}\n{running.diagnostics()}")
                self.assertEqual(result.tunneled, SENTINEL_PREFIX + payload)

            self._assert_tls_only(parent)
            self.assertEqual(parent.tls_sessions, 1)
            self.assertIn(GOOD_PARENT_NAME, parent.sni_names)
            self.assertIn(
                _basic_value(DUMMY_UPSTREAM_USER, DUMMY_UPSTREAM_PASSWORD),
                parent.authorization_values,
            )
            self.assertEqual(parent.connect_targets, [("127.0.0.1", sentinel.port)])
            self.assertEqual(sentinel.hit_count, 1)
            self.assertEqual(sentinel.payloads, [payload])
            self.assertFalse(parent.tls_errors, parent.tls_errors)
            self.assertFalse(parent.errors, parent.errors)

    def test_multiple_generic_socks_listeners_share_verified_https_parent(self) -> None:
        first_port = _unused_loopback_port()
        second_port = _unused_loopback_port()
        while second_port == first_port:
            second_port = _unused_loopback_port()
        listeners: list[dict[str, object]] = [
            {
                "id": "secure-socks.public",
                "protocol": "socks5",
                "listen_ip": "127.0.0.1",
                "port": first_port,
                "parent": "https_primary",
                "capabilities": ["tcp"],
            },
            {
                "id": "secure-socks.local",
                "protocol": "socks5",
                "listen_ip": "127.0.0.1",
                "port": second_port,
                "parent": "https_primary",
                "capabilities": ["tcp"],
            },
        ]
        first_payload = b"generic-first-socks-listener"
        second_payload = b"generic-second-socks-listener"
        with _SentinelTarget() as sentinel, _TlsConnectParent(
            self.server_certificate,
            self.server_key,
            ("127.0.0.1", sentinel.port),
        ) as parent:
            with self._running_proxy(
                "multiple-generic-socks",
                first_port,
                parent.port,
                self.ca_certificate,
                listeners=listeners,
            ) as running:
                rendered_lines = running.config_path.read_text(encoding="utf-8").splitlines()
                self.assertIn("# secure-socks.public", rendered_lines)
                self.assertIn("# secure-socks.local", rendered_lines)
                self.assertEqual(rendered_lines.count("ssl_cli"), 2)
                self.assertEqual(rendered_lines.count("ssl_nocli"), 2)
                self.assertEqual(
                    rendered_lines.count(
                        f"parent 1000 connect+s 127.0.0.1 {parent.port} "
                        f"{DUMMY_UPSTREAM_USER} {DUMMY_UPSTREAM_PASSWORD}"
                    ),
                    2,
                )
                first_response = self._socks_connect(first_port, sentinel.port, first_payload)
                second_response = self._socks_connect(second_port, sentinel.port, second_payload)
                self.assertEqual(first_response, SENTINEL_PREFIX + first_payload)
                self.assertEqual(second_response, SENTINEL_PREFIX + second_payload)

            self._assert_tls_only(parent)
            self.assertEqual(parent.tls_sessions, 2)
            self.assertEqual(parent.sni_names.count(GOOD_PARENT_NAME), 2)
            expected_authorization = _basic_value(
                DUMMY_UPSTREAM_USER,
                DUMMY_UPSTREAM_PASSWORD,
            )
            self.assertEqual(parent.authorization_values.count(expected_authorization), 2)
            self.assertEqual(
                parent.connect_targets,
                [("127.0.0.1", sentinel.port), ("127.0.0.1", sentinel.port)],
            )
            self.assertEqual(sentinel.hit_count, 2)
            self.assertEqual(sentinel.payloads, [first_payload, second_payload])
            self.assertFalse(parent.tls_errors, parent.tls_errors)
            self.assertFalse(parent.errors, parent.errors)

    def test_mixed_strong_and_loopback_iponly_socks4_share_verified_https_parent(self) -> None:
        strong_port = _unused_loopback_port()
        bridge_port = _unused_loopback_port()
        while bridge_port == strong_port:
            bridge_port = _unused_loopback_port()
        strong_port, bridge_port = sorted((strong_port, bridge_port))
        listeners: list[dict[str, object]] = [
            {
                "id": "secure-socks.strong",
                "protocol": "socks5",
                "listen_ip": "127.0.0.1",
                "port": strong_port,
                "parent": "https_primary",
                "capabilities": ["tcp"],
            },
            {
                "id": "whatsapp-media.socks4",
                "protocol": "socks5",
                "listen_ip": "127.0.0.1",
                "port": bridge_port,
                "parent": "https_primary",
                "capabilities": ["tcp"],
                "access": {
                    "mode": "iponly",
                    "allowed_client_cidrs": ["127.0.0.1/32"],
                },
            },
        ]
        strong_payload = b"mixed-strong-socks5"
        bridge_payload = b"mixed-iponly-socks4"
        with _SentinelTarget() as sentinel, _TlsConnectParent(
            self.server_certificate,
            self.server_key,
            ("127.0.0.1", sentinel.port),
        ) as parent:
            with self._running_proxy(
                "mixed-strong-iponly-socks4",
                strong_port,
                parent.port,
                self.ca_certificate,
                listeners=listeners,
            ) as running:
                rendered = running.config_path.read_text(encoding="utf-8")
                strong_block = rendered[
                    rendered.index("# secure-socks.strong"):
                    rendered.index("# whatsapp-media.socks4")
                ]
                bridge_block = rendered[rendered.index("# whatsapp-media.socks4"):]
                self.assertEqual(
                    rendered.count(
                        f"users {DUMMY_LOCAL_USER}:CL:{DUMMY_LOCAL_PASSWORD}"
                    ),
                    1,
                )
                self.assertIn("auth strong", strong_block)
                self.assertIn(f"allow {DUMMY_LOCAL_USER}", strong_block)
                self.assertIn(
                    "auth iponly\n"
                    "deny * * * * UDPASSOC\n"
                    "allow * 127.0.0.1/32\n",
                    bridge_block,
                )
                self.assertIn("\ndeny *\nsocks -i127.0.0.1", bridge_block)
                self.assertNotIn(f"allow {DUMMY_LOCAL_USER}", bridge_block)

                strong_response = self._socks_connect(
                    strong_port,
                    sentinel.port,
                    strong_payload,
                )
                bridge_response = self._socks4_noauth_connect(
                    bridge_port,
                    sentinel.port,
                    bridge_payload,
                )
                self.assertEqual(strong_response, SENTINEL_PREFIX + strong_payload)
                self.assertEqual(bridge_response, SENTINEL_PREFIX + bridge_payload)

            self._assert_tls_only(parent)
            self.assertEqual(parent.tls_sessions, 2)
            self.assertEqual(parent.sni_names.count(GOOD_PARENT_NAME), 2)
            expected_authorization = _basic_value(
                DUMMY_UPSTREAM_USER,
                DUMMY_UPSTREAM_PASSWORD,
            )
            self.assertEqual(parent.authorization_values.count(expected_authorization), 2)
            self.assertEqual(
                parent.connect_targets,
                [("127.0.0.1", sentinel.port), ("127.0.0.1", sentinel.port)],
            )
            self.assertEqual(sentinel.payloads, [strong_payload, bridge_payload])
            self.assertFalse(parent.tls_errors, parent.tls_errors)
            self.assertFalse(parent.errors, parent.errors)

    def test_whitelist_https_parent_roundtrip_has_no_upstream_authorization(self) -> None:
        listener_port = _unused_loopback_port()
        payload = b"positive-whitelist-parent-connect"
        with _SentinelTarget() as sentinel, _TlsConnectParent(
            self.server_certificate,
            self.server_key,
            ("127.0.0.1", sentinel.port),
            expected_username=None,
            expected_password=None,
        ) as parent:
            with self._running_proxy(
                "whitelist-parent",
                listener_port,
                parent.port,
                self.ca_certificate,
                upstream_auth=False,
            ) as running:
                parent_lines = [
                    line
                    for line in running.config_path.read_text(encoding="utf-8").splitlines()
                    if line.startswith("parent ")
                ]
                self.assertEqual(
                    parent_lines,
                    [f"parent 1000 connect+s 127.0.0.1 {parent.port}"],
                )
                result = self._proxy_connect(
                    listener_port,
                    sentinel.port,
                    (DUMMY_LOCAL_USER, DUMMY_LOCAL_PASSWORD),
                    payload,
                )
                self.assertTrue(parent.wait_for_attempt(), "whitelist parent did not finish CONNECT")
                self.assertEqual(
                    result.status,
                    200,
                    f"whitelist-style CONNECT failed: {result.header!r}\n{running.diagnostics()}",
                )
                self.assertEqual(result.tunneled, SENTINEL_PREFIX + payload)

            self._assert_tls_only(parent)
            self.assertEqual(parent.tls_sessions, 1)
            self.assertIn(GOOD_PARENT_NAME, parent.sni_names)
            self.assertEqual(parent.authorization_values, [])
            self.assertTrue(parent.requests)
            self.assertNotIn(b"proxy-authorization:", parent.requests[0].lower())
            self.assertEqual(parent.connect_targets, [("127.0.0.1", sentinel.port)])
            self.assertEqual(sentinel.hit_count, 1)
            self.assertEqual(sentinel.payloads, [payload])
            self.assertFalse(parent.tls_errors, parent.tls_errors)
            self.assertFalse(parent.errors, parent.errors)

    def test_expired_https_parent_rejects_without_direct_fallback(self) -> None:
        ca, certificate, key = self._generate_certificate_chain("expired-parent", GOOD_PARENT_NAME)
        directory = certificate.parent
        self._run_openssl("x509", "-req", "-in", str(directory/"leaf.csr"),
                          "-CA", str(ca), "-CAkey", str(directory/"ca.key"),
                          "-set_serial", "991", "-days", "-1", "-sha256",
                          "-extfile", str(directory/"leaf.cnf"), "-extensions", "server_ext",
                          "-out", str(certificate))
        port = _unused_loopback_port()
        with _SentinelTarget() as sentinel, _TlsConnectParent(
                certificate, key, ("127.0.0.1", sentinel.port)) as parent:
            with self._running_proxy("expired-parent-proxy", port, parent.port, ca) as running:
                result = self._proxy_connect(port, sentinel.port,
                    (DUMMY_LOCAL_USER, DUMMY_LOCAL_PASSWORD), b"expired-must-not-pass")
                self.assertTrue(parent.wait_for_attempt(), running.diagnostics())
                self.assertFalse(result.status is not None and 200 <= result.status < 300,
                                 running.diagnostics())
            self._assert_tls_only(parent)
            self.assertEqual(parent.tls_sessions, 0)
            self.assertEqual(parent.requests, [])
            self.assertEqual(sentinel.hit_count, 0)
            self.assertFalse(parent.errors, parent.errors)

    def test_wrong_ca_rejects_parent_and_never_reaches_target(self) -> None:
        listener_port = _unused_loopback_port()
        payload = b"must-not-pass-wrong-ca"
        with _SentinelTarget() as sentinel, _TlsConnectParent(
            self.server_certificate,
            self.server_key,
            ("127.0.0.1", sentinel.port),
        ) as parent:
            with self._running_proxy(
                "wrong-ca", listener_port, parent.port, self.untrusted_ca_certificate
            ) as running:
                result = self._proxy_connect(
                    listener_port,
                    sentinel.port,
                    (DUMMY_LOCAL_USER, DUMMY_LOCAL_PASSWORD),
                    payload,
                )
                self.assertTrue(parent.wait_for_attempt(), "wrong-CA TLS attempt was not observed")
                self.assertFalse(
                    result.status is not None and 200 <= result.status < 300,
                    f"wrong CA was accepted: {result.header!r}\n{running.diagnostics()}",
                )

            self._assert_tls_only(parent)
            self.assertEqual(parent.tls_sessions, 0)
            self.assertIn(GOOD_PARENT_NAME, parent.sni_names)
            self.assertEqual(parent.requests, [])
            self.assertEqual(sentinel.hit_count, 0, "wrong-CA failure fell back to a direct target connection")
            self.assertFalse(parent.errors, parent.errors)

    def test_wrong_sni_hostname_rejects_parent_and_never_reaches_target(self) -> None:
        listener_port = _unused_loopback_port()
        payload = b"must-not-pass-wrong-hostname"
        with _SentinelTarget() as sentinel, _TlsConnectParent(
            self.server_certificate,
            self.server_key,
            ("127.0.0.1", sentinel.port),
        ) as parent:
            with self._running_proxy(
                "wrong-sni",
                listener_port,
                parent.port,
                self.ca_certificate,
                server_name=WRONG_PARENT_NAME,
            ) as running:
                result = self._proxy_connect(
                    listener_port,
                    sentinel.port,
                    (DUMMY_LOCAL_USER, DUMMY_LOCAL_PASSWORD),
                    payload,
                )
                self.assertTrue(parent.wait_for_attempt(), "wrong-SNI TLS attempt was not observed")
                self.assertFalse(
                    result.status is not None and 200 <= result.status < 300,
                    f"certificate hostname mismatch was accepted: {result.header!r}\n{running.diagnostics()}",
                )

            self._assert_tls_only(parent)
            self.assertIn(WRONG_PARENT_NAME, parent.sni_names)
            self.assertEqual(parent.tls_sessions, 0)
            self.assertEqual(parent.requests, [])
            self.assertEqual(sentinel.hit_count, 0, "hostname failure fell back to a direct target connection")
            self.assertFalse(parent.errors, parent.errors)

    def test_wrong_upstream_password_has_no_direct_fallback(self) -> None:
        listener_port = _unused_loopback_port()
        payload = b"must-not-pass-upstream-auth"
        wrong_dummy_password = "WrongRuntimeParentDummy_41"
        # Pinned 1.0.0 can report a misleading frontend 200 when the target ends in 2.
        # Exercise that known response-parser quirk deterministically, and prove that
        # parent authorization and application transport remain closed independently.
        with _SentinelTarget(port_last_digit=2) as sentinel, _TlsConnectParent(
            self.server_certificate,
            self.server_key,
            ("127.0.0.1", sentinel.port),
        ) as parent:
            with self._running_proxy(
                "wrong-parent-password",
                listener_port,
                parent.port,
                self.ca_certificate,
                upstream_password=wrong_dummy_password,
            ) as running:
                result = self._proxy_connect(
                    listener_port,
                    sentinel.port,
                    (DUMMY_LOCAL_USER, DUMMY_LOCAL_PASSWORD),
                    payload,
                )
                self.assertTrue(parent.wait_for_attempt(), "upstream-auth CONNECT attempt was not observed")
                self.assertGreaterEqual(parent.auth_rejections, 1, "parent did not emit the required 407")
                self.assertEqual(
                    result.tunneled, b"",
                    f"wrong upstream credentials transferred application data: {result.header!r}\n{running.diagnostics()}",
                )

            self._assert_tls_only(parent)
            self.assertGreaterEqual(parent.tls_sessions, 1)
            self.assertIn(GOOD_PARENT_NAME, parent.sni_names)
            self.assertIn(
                _basic_value(DUMMY_UPSTREAM_USER, wrong_dummy_password),
                parent.authorization_values,
            )
            self.assertNotIn(
                _basic_value(DUMMY_UPSTREAM_USER, DUMMY_UPSTREAM_PASSWORD),
                parent.authorization_values,
            )
            self.assertEqual(parent.connect_targets, [])
            self.assertEqual(sentinel.hit_count, 0, "parent auth failure fell back to a direct target connection")
            self.assertEqual(sentinel.payloads, [], "wrong-auth traffic reached the application")
            self.assertFalse(parent.errors, parent.errors)


if __name__ == "__main__":
    unittest.main()
