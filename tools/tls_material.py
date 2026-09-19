#!/usr/bin/env python3
"""Validated, instance-owned server TLS material. No ACME or service mutations."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import tempfile

import config as config_tool
from instance import guard

SYSTEM_CA = "/etc/ssl/certs/ca-certificates.crt"
CERTIFICATE = re.compile(rb"-----BEGIN CERTIFICATE-----\s+.*?-----END CERTIFICATE-----", re.S)


def read_input(path: Path, *, private: bool = False) -> bytes:
    guard(path)
    if not path.is_file() or path.stat().st_nlink != 1:
        raise ValueError(f"TLS input must be an exclusively owned regular file: {path}")
    if path.stat().st_size > 10 * 1024 * 1024:
        raise ValueError("TLS input exceeds 10 MiB")
    if private and os.name == "posix" and path.stat().st_mode & 0o007:
        raise ValueError("TLS private key must not be accessible to other users")
    return path.read_bytes()


def openssl(*args: str) -> str:
    result = subprocess.run(["openssl", *args], capture_output=True, text=True, timeout=30)
    if result.returncode:
        # OpenSSL errors contain paths and certificate metadata, never key contents.
        raise ValueError("TLS validation failed: " + result.stderr.strip() + result.stdout.strip())
    return result.stdout


def validate_bundle(bundle: dict[str, bytes], public_ip: str, *, minimum_seconds: int = 86400) -> None:
    chain = bundle["server.crt"]
    certs = CERTIFICATE.findall(chain)
    if not certs or CERTIFICATE.sub(b"", chain).strip():
        raise ValueError("fullchain must contain PEM certificates only, leaf first")
    with tempfile.TemporaryDirectory(prefix="3proxy-tls-validate-") as name:
        root = Path(name)
        for filename, value in bundle.items():
            file = root / filename
            file.write_bytes(value)
            file.chmod(0o600)
        leaf = root / "leaf.crt"
        leaf.write_bytes(certs[0])
        trust = str(root / "trust.crt") if "trust.crt" in bundle else SYSTEM_CA
        openssl("x509", "-in", str(leaf), "-noout", "-checkend", str(minimum_seconds))
        openssl("verify", "-purpose", "sslserver", "-verify_ip", public_ip,
                "-CAfile", trust, "-untrusted", str(root / "server.crt"), str(leaf))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            context.load_cert_chain(str(root / "server.crt"), str(root / "server.key"), password=lambda: "")
        except (OSError, ssl.SSLError) as exc:
            raise ValueError(f"invalid fullchain/private key pair: {exc}") from exc


def collect(data: dict, pending: Path | None = None) -> dict[str, bytes]:
    server = data["tls"]["server"]
    bundle = {}
    active = Path(config_tool.paths(data.get("instance", {}).get("id"))["CONFIG_DIR"]) / "tls"
    for key, name in (("fullchain_file", "server.crt"), ("private_key_file", "server.key"), ("ca_file", "trust.crt")):
        value = server.get(key, SYSTEM_CA if key == "ca_file" else None)
        if key == "ca_file" and value == SYSTEM_CA:
            continue
        source = Path(value)
        if pending is not None and source == active / name and (pending / name).exists():
            source = pending / name
        bundle[name] = read_input(source, private=key == "private_key_file")
    validate_bundle(bundle, str(data["server"]["public_ip"]))
    return bundle


def replace_directory(destination: Path, bundle: dict[str, bytes]) -> None:
    """Caller has stopped its instance; retain old directory on any install failure."""
    guard(destination)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=".tls.new.", dir=destination.parent))
    old = work.with_name(work.name + ".old")
    try:
        for filename, value in bundle.items():
            target = work / filename
            target.write_bytes(value)
            target.chmod(0o600 if filename.endswith(".key") else 0o644)
        (work / "mode").write_text("external\n")
        if destination.exists():
            os.rename(destination, old)
        try:
            os.rename(work, destination)
        except BaseException:
            if old.exists():
                os.rename(old, destination)
            raise
        if old.exists():
            shutil.rmtree(old)
    finally:
        if work.exists():
            shutil.rmtree(work)


def stage(data: dict, p: dict, bundle: dict[str, bytes]) -> None:
    pending = Path(p["INSTANCE_STATE"]) / "pending-server-tls"
    replace_directory(pending, bundle)
    server = data["tls"]["server"]
    active = Path(p["CONFIG_DIR"]) / "tls"
    server["fullchain_file"] = str(active / "server.crt")
    server["private_key_file"] = str(active / "server.key")
    if "trust.crt" in bundle:
        server["ca_file"] = str(active / "trust.crt")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    data = config_tool.load_config(args.config)
    config_tool.validate(data)
    if config_tool.tls_server_mode(data) != "external":
        raise ValueError("external TLS mode is required")
    p = config_tool.paths(data.get("instance", {}).get("id"))
    pending = Path(p["INSTANCE_STATE"]) / "pending-server-tls"
    bundle = collect(data, pending)
    replace_directory(args.directory, bundle)
    if pending.exists():
        guard(pending)
        shutil.rmtree(pending)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"external TLS error: {exc}")
