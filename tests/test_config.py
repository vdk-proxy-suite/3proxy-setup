from __future__ import annotations

import copy
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import config as config_tool  # noqa: E402


def make_config(*, mode: str = "strong", include_https: bool = True) -> dict:
    """Return a complete v2 configuration without depending on mutable examples."""
    data = {
        "install": {
            "version": config_tool.INSTALL_VERSION,
            "source_url": config_tool.INSTALL_SOURCE_URL,
            "sha256": config_tool.INSTALL_SHA256,
        },
        "server": {
            "public_ip": "203.0.113.10",
            "listen_ip": "0.0.0.0",
            "udp_client_cidr": "0.0.0.0/0",
            "manage_ufw": False,
        },
        "logging": {
            "format": "monitor_v1",
            "rotation": "daily",
            "keep_files": 14,
            "compress": True,
        },
        "access": {"mode": mode},
        "upstreams": {
            "socks_primary": {
                "type": "socks5",
                "host": "socks.example.test",
                "port": 1080,
                "username": "socks-user",
                "password": "socks-password",
                "expected_egress_ip": "198.51.100.10",
                "capabilities": ["tcp", "udp"],
            },
            "http_primary": {
                "type": "http",
                "host": "http.example.test",
                "port": 8080,
                "username": "http-user",
                "password": "http-password",
                "expected_egress_ip": "198.51.100.11",
                "capabilities": ["tcp"],
            },
        },
        "listeners": [
            {
                "id": "socks_direct",
                "protocol": "socks5",
                "port": 1080,
                "parent": "direct",
                "capabilities": ["tcp", "udp"],
            },
            {
                "id": "socks_via_socks",
                "protocol": "socks5",
                "port": 1081,
                "parent": "socks_primary",
                "capabilities": ["tcp", "udp"],
            },
            {
                "id": "socks_via_http",
                "protocol": "socks5",
                "port": 1082,
                "parent": "http_primary",
                "capabilities": ["tcp"],
            },
            {
                "id": "http_direct",
                "protocol": "http",
                "port": 8080,
                "parent": "direct",
                "capabilities": ["tcp"],
            },
            {
                "id": "http_via_socks",
                "protocol": "http",
                "port": 8081,
                "parent": "socks_primary",
                "capabilities": ["tcp"],
            },
            {
                "id": "http_via_http",
                "protocol": "http",
                "port": 8082,
                "parent": "http_primary",
                "capabilities": ["tcp"],
            },
        ],
        "probes": {
            "timeout_seconds": 8,
            "http_host": "api.ipify.org",
            "http_port": 80,
            "dns_server": "1.1.1.1",
            "dns_port": 53,
            "stun_servers": [{"host": "stun.example.test", "port": 3478}],
        },
    }
    if mode == "strong":
        data["local_auth"] = {"username": "local-user", "password": "local-password"}
    else:
        data["access"]["allowed_client_cidrs"] = ["198.51.100.25/32"]
    if include_https:
        data["upstreams"]["https_primary"] = {
            "type": "https",
            "host": "secure-proxy.example.test",
            "port": 8443,
            "username": "https-user",
            "password": "https-password",
            "tls_server_name": "secure-proxy.example.test",
            "expected_egress_ip": "198.51.100.12",
            "capabilities": ["tcp"],
        }
        data["listeners"].extend(
            [
                {
                    "id": "socks_via_https",
                    "protocol": "socks5",
                    "port": 1083,
                    "parent": "https_primary",
                    "capabilities": ["tcp"],
                },
                {
                    "id": "http_via_https",
                    "protocol": "http",
                    "port": 8083,
                    "parent": "https_primary",
                    "capabilities": ["tcp"],
                },
            ]
        )
    return data


class ConfigCliMixin:
    def invoke(self, *args: str) -> tuple[int, str]:
        output = io.StringIO()
        with mock.patch.object(sys, "argv", ["config.py", *args]), redirect_stdout(output):
            result = config_tool.main()
        return result, output.getvalue()

    def dump_config(self, directory: str, data: dict) -> Path:
        path = Path(directory) / "config.yaml"
        path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        return path


class PrimitiveApiTests(unittest.TestCase):
    def test_load_config_requires_mapping_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            good = Path(directory) / "good.yaml"
            good.write_text("outer:\n  inner: value\nflag: true\n", encoding="utf-8")
            self.assertEqual(config_tool.load_config(good)["outer"]["inner"], "value")

            bad = Path(directory) / "bad.yaml"
            bad.write_text("- item\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "YAML root must be a mapping"):
                config_tool.load_config(bad)

    def test_scalar_reads_nested_values_and_rejects_missing_or_composite_values(self) -> None:
        data = {"outer": {"answer": 42, "items": [1]}, "flag": False}
        self.assertEqual(config_tool.scalar(data, "outer.answer"), 42)
        self.assertIs(config_tool.scalar(data, "flag"), False)
        with self.assertRaisesRegex(ValueError, "missing configuration key: outer.missing"):
            config_tool.scalar(data, "outer.missing")
        with self.assertRaisesRegex(ValueError, "not scalar: outer"):
            config_tool.scalar(data, "outer")
        with self.assertRaisesRegex(ValueError, "not scalar: outer.items"):
            config_tool.scalar(data, "outer.items")

    def test_safe_token_accepts_unicode_by_byte_length_and_can_allow_colons(self) -> None:
        self.assertEqual(config_tool.safe_token("proxy.example:443", "host", colon=False), "proxy.example:443")
        self.assertEqual(config_tool.safe_token("я" * 127, "value"), "я" * 127)
        for value in (None, "", "has space", "line\nbreak", "user:name", "x" * 256, "я" * 128):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    config_tool.safe_token(value, "value")

    def test_dns_hostname_accepts_unambiguous_names_and_rejects_ips_or_bad_labels(self) -> None:
        for hostname in ("proxy.example", "UPPER.example", "single-label", "a" * 63 + ".example"):
            with self.subTest(hostname=hostname):
                self.assertEqual(config_tool.dns_hostname(hostname, "sni"), hostname)
        invalid = (
            "192.0.2.1",
            "2001:db8::1",
            "proxy.example.",
            "bad_label.example",
            "-bad.example",
            "bad-.example",
            "two..dots",
            "a" * 64 + ".example",
            "a" * 250 + ".test",
        )
        for hostname in invalid:
            with self.subTest(hostname=hostname):
                with self.assertRaises(ValueError):
                    config_tool.dns_hostname(hostname, "sni")

    def test_ca_and_listener_helpers_apply_defaults_and_overrides(self) -> None:
        data = make_config()
        listener = data["listeners"][0]
        self.assertEqual(config_tool.client_ca_file(data), config_tool.DEFAULT_CLIENT_CA_FILE)
        self.assertEqual(config_tool.listener_ip(data, listener), "0.0.0.0")
        data["tls"] = {"client_ca_file": "/opt/ca/custom.pem"}
        listener["listen_ip"] = "127.0.0.1"
        self.assertEqual(config_tool.client_ca_file(data), "/opt/ca/custom.pem")
        self.assertEqual(config_tool.listener_ip(data, listener), "127.0.0.1")


class ValidationTests(unittest.TestCase):
    def test_complete_v2_topology_is_valid(self) -> None:
        data = make_config()
        self.assertIsNone(config_tool.validate(data))
        self.assertEqual(len(data["listeners"]), len(config_tool.EXPECTED_LISTENERS))

    def test_legacy_six_listener_strong_topology_remains_supported(self) -> None:
        data = make_config(include_https=False)
        config_tool.validate(data)
        rendered = config_tool.render_3proxy(data)
        self.assertIn("users local-user:CL:local-password", rendered)
        self.assertEqual(rendered.count("auth strong"), 6)
        self.assertEqual(rendered.count("\nflush\n"), 6)
        self.assertNotIn("ssl_cli", rendered)

    def test_legacy_iponly_topology_remains_passwordless_and_closed_by_default(self) -> None:
        data = make_config(mode="iponly", include_https=False)
        config_tool.validate(data)
        rendered = config_tool.render_3proxy(data)
        self.assertNotIn("users ", rendered)
        self.assertNotIn(":CL:", rendered)
        self.assertNotIn("auth strong", rendered)
        self.assertEqual(rendered.count("auth iponly"), 6)
        self.assertEqual(rendered.count("allow * 198.51.100.25/32"), 6)
        self.assertEqual(rendered.count("deny *"), 6)

    def test_install_server_logging_and_probe_constraints(self) -> None:
        cases = [
            ("install mapping", lambda d: d.__setitem__("install", []), "install must be a mapping"),
            ("version pin", lambda d: d["install"].__setitem__("version", "0.9.7"), "pinned to 3proxy 1.0.0"),
            ("pinned sha", lambda d: d["install"].__setitem__("sha256", "A" * 64), "pinned official"),
            ("official source", lambda d: d["install"].__setitem__("source_url", "https://example.test/1.0.0.tgz"), "pinned official"),
            ("server mapping", lambda d: d.__setitem__("server", []), "server must be a mapping"),
            ("public IP", lambda d: d["server"].__setitem__("public_ip", "not-an-ip"), None),
            ("listen IP", lambda d: d["server"].__setitem__("listen_ip", "not-an-ip"), None),
            ("UDP CIDR", lambda d: d["server"].__setitem__("udp_client_cidr", "bad-cidr"), None),
            ("manage UFW bool", lambda d: d["server"].__setitem__("manage_ufw", 1), "must be boolean"),
            ("logging mapping", lambda d: d.__setitem__("logging", []), "logging must be a mapping"),
            ("log format", lambda d: d["logging"].__setitem__("format", "other"), "monitor_v1"),
            ("rotation", lambda d: d["logging"].__setitem__("rotation", "weekly"), "daily"),
            ("keep lower bound", lambda d: d["logging"].__setitem__("keep_files", 0), "between 1 and 365"),
            ("keep upper bound", lambda d: d["logging"].__setitem__("keep_files", 366), "between 1 and 365"),
            ("compress bool", lambda d: d["logging"].__setitem__("compress", 1), "must be boolean"),
            ("probes mapping", lambda d: d.__setitem__("probes", []), "probes must be a mapping"),
            ("timeout lower", lambda d: d["probes"].__setitem__("timeout_seconds", 0), "between 1 and 60"),
            ("timeout upper", lambda d: d["probes"].__setitem__("timeout_seconds", 61), "between 1 and 60"),
            ("STUN list", lambda d: d["probes"].__setitem__("stun_servers", []), "STUN server"),
        ]
        for name, mutate, message in cases:
            with self.subTest(name=name):
                data = make_config()
                mutate(data)
                context = self.assertRaisesRegex(ValueError, message) if message else self.assertRaises(ValueError)
                with context:
                    config_tool.validate(data)

    def test_integer_fields_reject_booleans(self) -> None:
        cases = [
            lambda d: d["logging"].__setitem__("keep_files", True),
            lambda d: d["probes"].__setitem__("timeout_seconds", True),
            lambda d: d["upstreams"]["http_primary"].__setitem__("port", True),
            lambda d: d["listeners"][0].__setitem__("port", True),
        ]
        for mutate in cases:
            with self.subTest(mutate=mutate):
                data = make_config()
                mutate(data)
                with self.assertRaises(ValueError):
                    config_tool.validate(data)

    def test_tls_settings_require_known_keys_and_normalized_absolute_path(self) -> None:
        valid = make_config()
        valid["tls"] = {"client_ca_file": "/opt/3proxy/ca.pem"}
        config_tool.validate(valid)

        cases = [
            ([], "tls must be a mapping"),
            ({"verify": False}, "unsupported tls settings"),
            ({"client_ca_file": "relative.pem"}, "absolute normalized POSIX path"),
            ({"client_ca_file": "/etc/../secret.pem"}, "absolute normalized POSIX path"),
            ({"client_ca_file": "/etc/ca/.."}, "absolute normalized POSIX path"),
            ({"client_ca_file": "/etc/./ca.pem"}, "absolute normalized POSIX path"),
            ({"client_ca_file": "/etc//ca.pem"}, "absolute normalized POSIX path"),
        ]
        for tls, message in cases:
            with self.subTest(tls=tls):
                data = make_config()
                data["tls"] = tls
                with self.assertRaisesRegex(ValueError, message):
                    config_tool.validate(data)

    def test_access_and_local_auth_constraints(self) -> None:
        cases = [
            (lambda d: d.__setitem__("access", []), "access must be a mapping"),
            (lambda d: d["access"].__setitem__("mode", "open"), "strong or iponly"),
            (lambda d: d["access"].__setitem__("allowed_client_cidrs", "198.51.100.0/24"), "must be a list"),
            (lambda d: d.__setitem__("local_auth", None), "local_auth must be a mapping"),
            (lambda d: d["local_auth"].__setitem__("username", "bad user"), "unsafe"),
        ]
        for mutate, message in cases:
            with self.subTest(message=message):
                data = make_config()
                mutate(data)
                with self.assertRaisesRegex(ValueError, message):
                    config_tool.validate(data)

        for cidrs, message in (([], "at least one"), (["0.0.0.0/0"], "open /0"), (["2001:db8::/64"], "must be IPv4")):
            with self.subTest(cidrs=cidrs):
                data = make_config(mode="iponly")
                data["access"]["allowed_client_cidrs"] = cidrs
                with self.assertRaisesRegex(ValueError, message):
                    config_tool.validate(data)

    def test_upstream_credentials_are_optional_but_must_be_paired_and_safe(self) -> None:
        data = make_config()
        for upstream in data["upstreams"].values():
            upstream.pop("username")
            upstream.pop("password")
        config_tool.validate(data)
        self.assertEqual(config_tool.parent_line(data, "socks_primary"), "parent 1000 socks5 socks.example.test 1080")
        self.assertEqual(config_tool.parent_line(data, "http_primary"), "parent 1000 connect+ http.example.test 8080")
        self.assertEqual(
            config_tool.parent_line(data, "https_primary"),
            "parent 1000 connect+s secure-proxy.example.test 8443",
        )

        for missing in ("username", "password"):
            with self.subTest(missing=missing):
                invalid = make_config()
                invalid["upstreams"]["https_primary"].pop(missing)
                with self.assertRaisesRegex(ValueError, "must be provided together"):
                    config_tool.validate(invalid)

        invalid = make_config()
        invalid["upstreams"]["socks_primary"]["password"] = "bad password"
        with self.assertRaisesRegex(ValueError, "unsafe"):
            config_tool.validate(invalid)

    def test_https_credentials_are_limited_to_128_encoded_bytes(self) -> None:
        data = make_config()
        data["upstreams"]["https_primary"]["username"] = "x" * 128
        data["upstreams"]["https_primary"]["password"] = "y" * 128
        config_tool.validate(data)
        data["upstreams"]["https_primary"]["password"] = "я" * 65
        with self.assertRaisesRegex(ValueError, "at most 128 bytes"):
            config_tool.validate(data)

    def test_https_requires_dns_sni_and_non_https_rejects_sni(self) -> None:
        for server_name in ("192.0.2.5", "2001:db8::5", "proxy.example.", "bad_name.example"):
            with self.subTest(server_name=server_name):
                data = make_config()
                data["upstreams"]["https_primary"]["tls_server_name"] = server_name
                with self.assertRaises(ValueError):
                    config_tool.validate(data)

        missing = make_config()
        missing["upstreams"]["https_primary"].pop("tls_server_name")
        with self.assertRaises(ValueError):
            config_tool.validate(missing)

        wrong_type = make_config()
        wrong_type["upstreams"]["http_primary"]["tls_server_name"] = "http.example.test"
        with self.assertRaisesRegex(ValueError, "unsupported settings.*tls_server_name"):
            config_tool.validate(wrong_type)

    def test_upstream_mapping_type_port_address_and_capabilities_are_validated(self) -> None:
        cases = [
            (lambda d: d.__setitem__("upstreams", []), "upstreams must be a mapping"),
            (lambda d: d["upstreams"].__setitem__("other", {}), "unsupported upstreams"),
            (lambda d: d["upstreams"].__setitem__("http_primary", []), "must be a mapping"),
            (lambda d: d["upstreams"]["http_primary"].__setitem__("type", "socks5"), "type must be http"),
            (lambda d: d["upstreams"]["http_primary"].__setitem__("host", "bad host"), "unsafe"),
            (lambda d: d["upstreams"]["http_primary"].__setitem__("port", 0), "port is invalid"),
            (lambda d: d["upstreams"]["http_primary"].__setitem__("expected_egress_ip", "bad"), None),
            (lambda d: d["upstreams"]["http_primary"].__setitem__("capabilities", ["tcp", "udp"]), "capabilities"),
        ]
        for mutate, message in cases:
            with self.subTest(message=message):
                data = make_config()
                mutate(data)
                context = self.assertRaisesRegex(ValueError, message) if message else self.assertRaises(ValueError)
                with context:
                    config_tool.validate(data)

    def test_listener_topology_and_bind_addresses_are_validated(self) -> None:
        cases = [
            (lambda d: d.__setitem__("listeners", []), "at least one"),
            (lambda d: d["listeners"].append(copy.deepcopy(d["listeners"][0])), "more entries"),
            (lambda d: d["listeners"].__setitem__(0, []), "mapping with id"),
            (lambda d: d["listeners"][1].__setitem__("id", "socks_direct"), "duplicate listener id"),
            (lambda d: d["listeners"][1].__setitem__("port", d["listeners"][0]["port"]), "duplicate listener port"),
            (lambda d: d["listeners"][0].__setitem__("listen_ip", "bad"), None),
            (lambda d: d["listeners"][0].__setitem__("id", "unknown"), "unsupported listener ids"),
            (lambda d: d["listeners"][0].__setitem__("protocol", "http"), "invalid protocol/parent"),
            (lambda d: d["listeners"][0].__setitem__("capabilities", ["tcp"]), "invalid capabilities"),
            (lambda d: d["upstreams"].pop("socks_primary"), "undefined upstream"),
        ]
        for mutate, message in cases:
            with self.subTest(message=message):
                data = make_config()
                mutate(data)
                context = self.assertRaisesRegex(ValueError, message) if message else self.assertRaises(ValueError)
                with context:
                    config_tool.validate(data)


class RenderingTests(unittest.TestCase):
    def test_https_render_uses_verified_tls_and_resets_state_after_each_secure_listener(self) -> None:
        data = make_config()
        config_tool.validate(data)
        rendered = config_tool.render_3proxy(data)
        for directive in (
            "ssl_client_mode 3",
            "ssl_client_verify",
            f"ssl_client_ca_file {config_tool.DEFAULT_CLIENT_CA_FILE}",
            "ssl_client_sni secure-proxy.example.test",
            "ssl_client_min_proto_version TLSv1.2",
        ):
            self.assertEqual(rendered.count(directive), 1)
        self.assertEqual(rendered.count("\nssl_cli\n"), 2)
        self.assertEqual(rendered.count("\nssl_nocli\n"), 2)

        socks_https = rendered[rendered.index("# socks_via_https"):rendered.index("# http_direct")]
        self.assertIn(
            "ssl_cli\nauth strong\nallow local-user\n"
            "parent 1000 connect+s secure-proxy.example.test 8443 https-user https-password\n"
            "socks -i0.0.0.0 -p1083\nssl_nocli\nflush",
            socks_https,
        )
        http_direct = rendered[rendered.index("# http_direct"):rendered.index("# http_via_socks")]
        self.assertNotIn("ssl_cli", http_direct)
        self.assertNotIn("ssl_nocli", http_direct)

        http_https = rendered[rendered.index("# http_via_https"):]
        self.assertIn("ssl_cli", http_https)
        self.assertLess(http_https.index("ssl_cli"), http_https.index("parent 1000 connect+s"))
        self.assertLess(http_https.index("proxy -i0.0.0.0 -p8083"), http_https.index("ssl_nocli"))
        self.assertLess(http_https.index("ssl_nocli"), http_https.index("flush"))

    def test_custom_ca_and_optional_https_credentials_are_rendered(self) -> None:
        data = make_config()
        data["tls"] = {"client_ca_file": "/opt/ca/proxy-chain.pem"}
        upstream = data["upstreams"]["https_primary"]
        upstream.pop("username")
        upstream.pop("password")
        config_tool.validate(data)
        rendered = config_tool.render_3proxy(data)
        self.assertIn("ssl_client_ca_file /opt/ca/proxy-chain.pem", rendered)
        self.assertIn("parent 1000 connect+s secure-proxy.example.test 8443\n", rendered)
        self.assertNotIn("None", rendered)

    def test_per_listener_bind_overrides_server_bind_and_other_listeners_inherit(self) -> None:
        data = make_config(include_https=False)
        data["listeners"][0]["listen_ip"] = "127.0.0.1"
        data["listeners"][3]["listen_ip"] = "192.0.2.20"
        config_tool.validate(data)
        rendered = config_tool.render_3proxy(data)
        self.assertIn("socks -i127.0.0.1 -p1080 -Ni203.0.113.10", rendered)
        self.assertIn("socks -i0.0.0.0 -p1081 -Ni203.0.113.10", rendered)
        self.assertIn("proxy -i192.0.2.20 -p8080", rendered)
        self.assertIn("proxy -i0.0.0.0 -p8081", rendered)

    def test_logging_rotation_compression_and_systemd_contract(self) -> None:
        data = make_config(include_https=False)
        data["logging"]["keep_files"] = 30
        data["logging"]["compress"] = False
        rendered = config_tool.render_3proxy(data)
        self.assertIn("rotate 30", rendered)
        self.assertNotIn("archiver ", rendered)
        systemd = config_tool.render_systemd()
        self.assertIn("ExecStart=/usr/local/bin/3proxy /etc/3proxy/3proxy.cfg", systemd)
        self.assertIn("NoNewPrivileges=true", systemd)
        self.assertTrue(systemd.endswith("\n"))


class CliTests(ConfigCliMixin, unittest.TestCase):
    def test_validate_get_ports_and_render_commands(self) -> None:
        data = make_config(include_https=False)
        with tempfile.TemporaryDirectory() as directory:
            config_path = self.dump_config(directory, data)
            result, output = self.invoke("validate", "--config", str(config_path))
            self.assertEqual((result, output), (0, "configuration valid\n"))

            result, output = self.invoke("get", "--config", str(config_path), "--path", "server.manage_ufw")
            self.assertEqual((result, output), (0, "false\n"))

            result, output = self.invoke("ports", "--config", str(config_path))
            self.assertEqual(result, 0)
            self.assertEqual(output.splitlines(), ["1080", "1081", "1082", "8080", "8081", "8082"])

            proxy_output = Path(directory) / "3proxy.cfg"
            result, output = self.invoke("render-3proxy", "--config", str(config_path), "--output", str(proxy_output))
            self.assertEqual((result, output), (0, ""))
            self.assertEqual(proxy_output.read_text(encoding="utf-8"), config_tool.render_3proxy(data))

            systemd_output = Path(directory) / "3proxy.service"
            result, output = self.invoke("render-systemd", "--output", str(systemd_output))
            self.assertEqual((result, output), (0, ""))
            self.assertEqual(systemd_output.read_text(encoding="utf-8"), config_tool.render_systemd())

    def test_firewall_ports_exclude_loopback_binds_and_are_sorted(self) -> None:
        data = make_config()
        by_id = {item["id"]: item for item in data["listeners"]}
        by_id["socks_direct"]["listen_ip"] = "127.0.0.1"
        by_id["socks_via_http"]["listen_ip"] = "::1"
        with tempfile.TemporaryDirectory() as directory:
            path = self.dump_config(directory, data)
            result, output = self.invoke("firewall-ports", "--config", str(path))
        self.assertEqual(result, 0)
        self.assertEqual(output.splitlines(), ["1081", "1083", "8080", "8081", "8082", "8083"])

    def test_external_udp_reflects_only_non_loopback_udp_listeners(self) -> None:
        data = make_config()
        by_id = {item["id"]: item for item in data["listeners"]}
        by_id["socks_direct"]["listen_ip"] = "127.0.0.1"
        with tempfile.TemporaryDirectory() as directory:
            path = self.dump_config(directory, data)
            result, output = self.invoke("external-udp", "--config", str(path))
            self.assertEqual((result, output), (0, "true\n"))

            by_id["socks_via_socks"]["listen_ip"] = "::1"
            path = self.dump_config(directory, data)
            result, output = self.invoke("external-udp", "--config", str(path))
            self.assertEqual((result, output), (0, "false\n"))

    def test_manifest_round_trip_and_build_profile_mismatch(self) -> None:
        self.assertEqual(config_tool.BUILD_PROFILE, "cmake-openssl")
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "manifest.json"
            common = (
                "--version", "1.0.0",
                "--source-sha", "source-sha",
                "--patch-sha", "patch-sha",
                "--build-profile", config_tool.BUILD_PROFILE,
            )
            result, output = self.invoke(
                "write-manifest", "--output", str(manifest), *common, "--binary-sha", "binary-sha"
            )
            self.assertEqual((result, output), (0, ""))
            self.assertEqual(
                json.loads(manifest.read_text(encoding="utf-8")),
                {
                    "binary_sha256": "binary-sha",
                    "build_profile": "cmake-openssl",
                    "patchset_sha256": "patch-sha",
                    "source_sha256": "source-sha",
                    "version": "1.0.0",
                },
            )
            self.assertTrue(manifest.read_bytes().endswith(b"\n"))

            result, _ = self.invoke("manifest-matches", "--manifest", str(manifest), *common)
            self.assertEqual(result, 0)
            mismatched = list(common)
            mismatched[-1] = "legacy-make"
            result, _ = self.invoke("manifest-matches", "--manifest", str(manifest), *mismatched)
            self.assertEqual(result, 1)

            manifest.write_text("not-json", encoding="utf-8")
            result, _ = self.invoke("manifest-matches", "--manifest", str(manifest), *common)
            self.assertEqual(result, 1)


if __name__ == "__main__":
    unittest.main()
