#!/usr/bin/env python3
"""Instance identity, ownership and cleanup. Never discovers processes by name."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import uuid
import hashlib
import ipaddress
import socket

import yaml

ID = re.compile(r"[a-z][a-z0-9-]{0,19}")


def paths(instance: str | None) -> dict[str, str]:
    if instance is None:
        return dict(INSTANCE_ID="", SERVICE="3proxy", SERVICE_USER="root", SERVICE_GROUP="root",
                    CONFIG_DIR="/etc/3proxy", BINARY="/usr/local/bin/3proxy",
                    DATA_DIR="/var/lib/3proxy", LOG_DIR="/var/log/3proxy", RUNTIME_DIR="/run/3proxy",
                    INSTANCE_STATE="/var/lib/3proxy-setup/legacy",
                    INSTALLED_ROOT="/usr/local/lib/3proxy-setup/legacy",
                    BUILD_MANIFEST="/usr/local/share/3proxy-build/manifest.json",
                    BACKUP_ROOT="/var/backups/3proxy", STATE_FILE="/run/3proxy-setup.state",
                    UNIT_FILE="/etc/systemd/system/3proxy.service")
    if not isinstance(instance, str) or not ID.fullmatch(instance):
        raise ValueError("instance.id must match [a-z][a-z0-9-]{0,19}")
    state = f"/var/lib/3proxy-setup/instances/{instance}"
    service = f"3proxy-{instance}"
    return dict(INSTANCE_ID=instance, SERVICE=service, SERVICE_USER=service, SERVICE_GROUP=service,
                CONFIG_DIR=f"/etc/3proxy-setup/instances/{instance}",
                BINARY=f"/opt/3proxy/instances/{instance}/bin/3proxy",
                DATA_DIR=f"/var/lib/3proxy-instances/{instance}",
                LOG_DIR=f"/var/log/3proxy-setup/instances/{instance}", RUNTIME_DIR=f"/run/{service}",
                INSTANCE_STATE=state, INSTALLED_ROOT=f"/usr/local/lib/3proxy-setup/instances/{instance}",
                BUILD_MANIFEST=f"{state}/build-manifest.json", BACKUP_ROOT=f"{state}/backups",
                STATE_FILE=f"{state}/backup.state", UNIT_FILE=f"/etc/systemd/system/{service}.service")


def identity(data: dict, legacy: bool = False) -> str | None:
    block = data.get("instance")
    if block is None:
        if legacy:
            return None
        raise ValueError("instance.id is required; existing legacy installations require explicit --legacy")
    if not isinstance(block, dict) or set(block) != {"id"}:
        raise ValueError("instance must contain only id")
    value = block["id"]
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise ValueError("instance.id must match [a-z][a-z0-9-]{0,19}")
    paths(value)
    if legacy:
        raise ValueError("--legacy cannot select an instance.id configuration")
    return value


def guard(path: Path, *, root_owned: bool = True) -> None:
    """Reject symlink traversal, writable ancestors and non-root managed files."""
    for item in [*reversed(path.parents), path]:
        if item.is_symlink():
            raise ValueError(f"refusing symlink path: {item}")
        if item.exists() and os.name == "posix":
            stat = item.stat()
            if root_owned and stat.st_uid != 0:
                raise ValueError(f"path is not root-owned: {item}")
            # Root /tmp is acceptable for test fixtures; managed paths never use it.
            trusted_log_parent = item == Path("/var/log") and stat.st_uid == 0 and not stat.st_mode & 0o002
            if stat.st_mode & 0o022 and not stat.st_mode & 0o1000 and not trusted_log_parent:
                raise ValueError(f"path is writable by other users: {item}")


def atomic_json(path: Path, data: dict) -> None:
    guard(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temp = path.with_suffix(".new")
    guard(temp)
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(data, stream, indent=2)
        stream.write("\n")
    os.replace(temp, path)


def read_manifest(p: dict) -> dict | None:
    file = Path(p["INSTANCE_STATE"]) / "manifest.json"
    guard(file)
    if not file.exists():
        return None
    data = json.loads(file.read_text())
    if data.get("schema") != 1 or data.get("paths") != p:
        raise ValueError("ownership manifest identity/paths do not match the selected instance")
    return data


def account_exists(name: str, database: str) -> bool:
    return subprocess.run(["getent", database, name], stdout=subprocess.DEVNULL).returncode == 0


def checked_accounts(p: dict, manifest: dict) -> None:
    if not p["INSTANCE_ID"]:
        return
    for database, key in (("group", "gid"), ("passwd", "uid")):
        current = subprocess.run(["getent", database, p["SERVICE"]], capture_output=True, text=True)
        if current.returncode == 0:
            number = int(current.stdout.split(":")[2])
            if manifest.get(key) is None and manifest.get("status") == "preparing":
                fields = current.stdout.strip().split(":")
                expected = (database == "group" and manifest.get("group_created")
                            and len(fields) == 4 and not fields[3] and 0 < number < 1000)
                if database == "passwd" and manifest.get("user_created"):
                    expected = (len(fields) == 7 and fields[5] == p["DATA_DIR"]
                                and fields[6] == "/usr/sbin/nologin"
                                and int(fields[3]) == manifest.get("gid") and 0 < number < 1000)
                if expected:
                    manifest[key] = number
            if manifest.get(key) != number:
                raise ValueError(f"account identity changed: {p['SERVICE']} {key}")


def check_ports(p: dict, config: Path) -> None:
    data = yaml.safe_load(config.read_text())
    requested = {(str(item.get("listen_ip", data["server"]["listen_ip"])), item["port"])
                 for item in data["listeners"]}
    state_parent = Path(p["INSTANCE_STATE"]).parent
    for other in state_parent.glob("*/manifest.json"):
        guard(other)
        saved = json.loads(other.read_text())
        if saved.get("paths", {}).get("INSTANCE_ID") == p["INSTANCE_ID"] or saved.get("status") == "removed":
            continue
        other_config = other.parent / "requested.yaml"
        if not other_config.exists():
            raise ValueError(f"cannot verify ports of incomplete neighboring instance: {other.parent.name}")
        other_data = yaml.safe_load(other_config.read_text())
        for listener in other_data["listeners"]:
            address = str(listener.get("listen_ip", other_data["server"]["listen_ip"]))
            for host, port in requested:
                if port == listener["port"] and (host == address or host in ("0.0.0.0", "::") or address in ("0.0.0.0", "::")):
                    raise ValueError(f"listener conflicts with instance {other.parent.name}: port {port}")
    active = subprocess.run(["systemctl", "is-active", "--quiet", p["SERVICE"]],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    for host, port in requested:
        with socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind((host, port))
            except OSError as exc:
                if not active:
                    raise ValueError(f"listener address/port unavailable: {host}:{port}: {exc}") from exc
                pid = subprocess.check_output(["systemctl", "show", "--value", "-p", "MainPID", p["SERVICE"]], text=True).strip()
                owners = subprocess.check_output(["ss", "-H", "-lntp", f"sport = :{port}"], text=True)
                rows = [line for line in owners.splitlines() if line.strip()]
                if not pid.isdigit() or pid == "0" or not rows or any(
                        f"pid={pid}," not in line for line in rows):
                    raise ValueError(f"listener is occupied by another service: {host}:{port}") from exc


def verify_unit(p: dict, manifest: dict) -> None:
    unit = Path(p["UNIT_FILE"])
    guard(unit)
    if Path(p["UNIT_FILE"] + ".d").exists():
        raise ValueError("unmanaged systemd drop-ins require review")
    if unit.exists():
        digest = hashlib.sha256(unit.read_bytes()).hexdigest()
        if digest not in manifest.get("unit_hashes", []):
            raise ValueError("unit identity changed; refusing operation")
    else:
        for directory in ("/usr/lib/systemd/system", "/lib/systemd/system", "/run/systemd/system"):
            foreign = Path(directory) / (p["SERVICE"] + ".service")
            if foreign.exists() or foreign.is_symlink():
                raise ValueError(f"unowned systemd unit conflicts: {foreign}")


def prepare(p: dict, config: Path, source: Path, update: bool, *, check_listeners: bool = False) -> None:
    for key in ("CONFIG_DIR", "BINARY", "INSTANCE_STATE", "INSTALLED_ROOT", "UNIT_FILE", "LOG_DIR", "BACKUP_ROOT", "BUILD_MANIFEST"):
        guard(Path(p[key]), root_owned=key != "LOG_DIR")
    pending_binary = Path(p["BINARY"] + ".new")
    guard(pending_binary)
    if pending_binary.exists() and (not pending_binary.is_file() or pending_binary.stat().st_nlink != 1):
        raise ValueError("pending binary is not an exclusively owned regular file")
    manifest = read_manifest(p)
    origin = str(source.resolve())
    if manifest:
        checked_accounts(p, manifest)
        verify_unit(p, manifest)
        for key in ("CONFIG_DIR", "INSTANCE_STATE", "INSTALLED_ROOT", "LOG_DIR", "DATA_DIR"):
            directory = Path(p[key])
            if directory.is_symlink():
                raise ValueError(f"managed directory became a symlink: {directory}")
            if directory.exists():
                if os.name == "posix" and directory.stat().st_uid not in (0, manifest.get("uid")):
                    raise ValueError(f"managed directory owner changed: {directory}")
                if any(child.is_symlink() or (child.is_file() and child.stat().st_nlink != 1) for child in directory.rglob("*")):
                    raise ValueError(f"symlink or hardlink inside managed directory: {directory}")
        if manifest["origin"] != origin and origin != p["INSTALLED_ROOT"] and not update:
            raise ValueError("instance already belongs to another setup directory; use --update-existing explicitly")
    else:
        if p["INSTANCE_ID"]:
            binary_root = Path(p["BINARY"]).parent.parent
            if binary_root.exists():
                raise ValueError(f"unowned binary root exists: {binary_root}")
            for key in ("CONFIG_DIR", "BINARY", "INSTALLED_ROOT", "UNIT_FILE", "LOG_DIR", "DATA_DIR", "RUNTIME_DIR"):
                if Path(p[key]).exists():
                    raise ValueError(f"unowned resource exists: {p[key]}")
            for database in ("passwd", "group"):
                if account_exists(p["SERVICE"], database):
                    raise ValueError(f"unowned {database} account exists: {p['SERVICE']}")
        manifest = dict(schema=1, paths=p, origin=origin, token=uuid.uuid4().hex,
                        status="preparing", user_created=False, group_created=False, uid=None, gid=None, unit_hashes=[])
    if check_listeners:
        check_ports(p, config)
    unit = Path(p["UNIT_FILE"])
    if not p["INSTANCE_ID"] and unit.exists() and not manifest.get("unit_hashes"):
        # Adopt only the exact previous release unit; arbitrary ExecStop/User directives are rejected.
        legacy_unit = """[Unit]
Description=3proxy - modular installation
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/3proxy /etc/3proxy/3proxy.cfg
Restart=always
RestartSec=3
LimitNOFILE=65536
NoNewPrivileges=true
UMask=0027

[Install]
WantedBy=multi-user.target
"""
        if unit.read_text() != legacy_unit:
            raise ValueError("legacy unit differs from the supported previous release; review required")
        manifest["unit_hashes"] = [hashlib.sha256(unit.read_bytes()).hexdigest()]
    verify_unit(p, manifest)
    marker = source / ".3proxy-instance.json"
    if source.resolve() != Path(p["INSTALLED_ROOT"]):
        if marker.is_symlink():
            raise ValueError("setup ownership marker is a symlink")
        if marker.exists():
            old = json.loads(marker.read_text())
            if old.get("instance") != p["INSTANCE_ID"] or old.get("token") != manifest["token"]:
                raise ValueError("setup directory belongs to a different instance")
    from config import load_config, validate
    normalized_config = load_config(config)
    validate(normalized_config)
    supplied_ca = normalized_config.get("tls", {}).get("client_ca_file")
    managed_ca = Path(p["CONFIG_DIR"]) / "client-ca.crt"
    ca_bytes = None
    pending_ca = Path(p["INSTANCE_STATE"]) / "pending-client-ca.crt"
    if supplied_ca and supplied_ca != "/etc/ssl/certs/ca-certificates.crt":
        ca_source = Path(supplied_ca)
        if ca_source == managed_ca and pending_ca.is_file():
            guard(pending_ca)
            ca_source = pending_ca
        if not ca_source.is_file():
            raise ValueError(f"client CA file not found: {ca_source}")
        if ca_source.stat().st_size > 10 * 1024 * 1024:
            raise ValueError("client CA input exceeds 10 MiB")
        ca_bytes = ca_source.read_bytes()
        normalized_config["tls"]["client_ca_file"] = str(managed_ca)
    # Write intent before any resources, including partial installations, are created.
    if origin != p["INSTALLED_ROOT"]:
        manifest["origin"] = origin
    manifest["status"] = "preparing"
    atomic_json(Path(p["INSTANCE_STATE"]) / "manifest.json", manifest)
    for key in ("CONFIG_DIR", "INSTALLED_ROOT", "BACKUP_ROOT"):
        Path(p[key]).mkdir(mode=0o700, parents=True, exist_ok=True)
    snapshot = Path(p["INSTANCE_STATE"]) / "requested.yaml"
    guard(snapshot)
    if ca_bytes is not None:
        guard(pending_ca)
        pending_ca.write_bytes(ca_bytes)
        pending_ca.chmod(0o600)
    snapshot.write_text(yaml.safe_dump(normalized_config, sort_keys=False), encoding="utf-8")
    snapshot.chmod(0o600)
    marker = source / ".3proxy-instance.json"
    if source.resolve() != Path(p["INSTALLED_ROOT"]):
        if marker.is_symlink():
            raise ValueError("setup ownership marker is a symlink")
        if marker.exists():
            old = json.loads(marker.read_text())
            if old.get("instance") != p["INSTANCE_ID"] or old.get("token") != manifest["token"]:
                raise ValueError("setup directory belongs to a different instance")
        marker.write_text(json.dumps(dict(instance=p["INSTANCE_ID"], token=manifest["token"])))
        marker.chmod(0o600)
    # Copy only release code, never arbitrary files or private configs from an unpacking.
    target = Path(p["INSTALLED_ROOT"])
    if source.resolve() != target:
        names = ["setup3proxy.sh", "clean3proxy.sh", "VERSION"]
        names += [str(f.relative_to(source)) for d in ("lib", "steps", "tools", "patches")
                  for f in (source / d).glob("*") if f.is_file() and f.suffix in (".sh", ".py", ".patch", ".md")]
        for name in names:
            src, dst = source / name, target / name
            if src.is_symlink():
                raise ValueError(f"setup code is a symlink: {src}")
            guard(dst)
            dst.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            shutil.copyfile(src, dst)
            dst.chmod(0o755 if dst.suffix in (".sh", ".py") else 0o644)
    if p["INSTANCE_ID"]:
        if not account_exists(p["SERVICE_GROUP"], "group"):
            manifest["group_created"] = True
            atomic_json(Path(p["INSTANCE_STATE"]) / "manifest.json", manifest)
            subprocess.run(["groupadd", "--system", p["SERVICE_GROUP"]], check=True)
            manifest["gid"] = int(subprocess.check_output(["getent", "group", p["SERVICE_GROUP"]], text=True).split(":")[2])
            atomic_json(Path(p["INSTANCE_STATE"]) / "manifest.json", manifest)
        if not account_exists(p["SERVICE_USER"], "passwd"):
            manifest["user_created"] = True
            atomic_json(Path(p["INSTANCE_STATE"]) / "manifest.json", manifest)
            subprocess.run(["useradd", "--system", "--gid", p["SERVICE_GROUP"], "--home-dir", p["DATA_DIR"],
                            "--no-create-home", "--shell", "/usr/sbin/nologin", p["SERVICE_USER"]], check=True)
            manifest["uid"] = int(subprocess.check_output(["getent", "passwd", p["SERVICE_USER"]], text=True).split(":")[2])
            atomic_json(Path(p["INSTANCE_STATE"]) / "manifest.json", manifest)
    manifest["status"] = "installed"
    atomic_json(Path(p["INSTANCE_STATE"]) / "manifest.json", manifest)


def selected(args: argparse.Namespace) -> tuple[dict, Path | None]:
    config = args.config
    if args.action == "cleanup" and args.instance and config is None:
        return paths(args.instance), None
    if config is None and args.instance:
        p = paths(args.instance)
        saved = Path(p["CONFIG_DIR"]) / "setup.yaml"
        config = saved if saved.exists() else Path(p["INSTANCE_STATE"]) / "requested.yaml"
    if config is None and not args.instance:
        config = args.source / "config.yaml"
        if args.legacy and not config.exists():
            config = Path("/etc/3proxy/setup.yaml")
    if config.exists():
        data = yaml.safe_load(config.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("configuration must be a mapping")
        instance = identity(data, args.legacy)
        if args.instance and instance != args.instance:
            raise ValueError("--instance does not match config instance.id")
    elif args.instance:
        instance = args.instance
        config = None
    elif args.legacy:
        instance = None
        config = None
    else:
        raise ValueError(f"configuration not found: {config}; select --instance ID for installed operations")
    return paths(instance), config


def prepare_log(p: dict) -> None:
    manifest = read_manifest(p)
    if not manifest:
        raise ValueError("ownership manifest is required")
    checked_accounts(p, manifest)
    file = Path(p["LOG_DIR"]) / "3proxy.log"
    guard(file, root_owned=False)
    fd = os.open(file, os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o640)
    try:
        if os.fstat(fd).st_nlink != 1:
            raise ValueError("refusing hardlinked log")
        uid = manifest.get("uid") if p["INSTANCE_ID"] else 0
        gid = int(subprocess.check_output(["getent", "group", "proxy-observability"], text=True).split(":")[2])
        os.fchown(fd, uid, gid)
        os.fchmod(fd, 0o640)
    finally:
        os.close(fd)


def cleanup(p: dict, args: argparse.Namespace) -> None:
    manifest = read_manifest(p)
    if manifest is None:
        raise ValueError("no ownership manifest; refusing cleanup of unowned installation")
    checked_accounts(p, manifest)
    verify_unit(p, manifest)
    # A process or external unit using this dedicated account must never be orphaned.
    foreign_units = []
    if p["INSTANCE_ID"]:
        for directory in (Path("/etc/systemd/system"), Path("/usr/lib/systemd/system")):
            for candidate in directory.glob("*.service"):
                if candidate.name == p["SERVICE"] + ".service" or candidate.is_symlink():
                    continue
                text = candidate.read_text(errors="replace")
                if any(line.strip() in (f"User={p['SERVICE_USER']}", f"Group={p['SERVICE_GROUP']}")
                       for line in text.splitlines()):
                    foreign_units.append(str(candidate))
        if foreign_units:
            raise ValueError("account is referenced by other units; refusing cleanup")
    # Retain installed management code so repeat cleanup works after removing the unpacking.
    removable = [p[k] for k in ("CONFIG_DIR", "DATA_DIR", "RUNTIME_DIR", "UNIT_FILE")]
    if not p["INSTANCE_ID"]:
        removable = [str(Path(p["CONFIG_DIR"]) / name) for name in ("3proxy.cfg", "setup.yaml", "tls")]
        removable += [p["BINARY"], p["UNIT_FILE"], p["BUILD_MANIFEST"], p["STATE_FILE"]]
    if p["INSTANCE_ID"]:
        removable.append(str(Path(p["BINARY"]).parent.parent))
    dropins = Path(p["UNIT_FILE"] + ".d")
    if dropins.exists():
        raise ValueError("unmanaged drop-ins exist; review before cleanup")
    if args.purge_setup:
        origin = Path(manifest["origin"])
        marker = origin / ".3proxy-instance.json"
        if origin == Path(p["INSTALLED_ROOT"]) or len(origin.parts) < 3 or origin.is_symlink():
            raise ValueError("unsafe unpacked setup path")
        if origin.exists():
            if marker.is_symlink() or not marker.is_file():
                raise ValueError("setup ownership marker missing")
            owner = json.loads(marker.read_text())
            if owner != dict(instance=p["INSTANCE_ID"], token=manifest["token"]):
                raise ValueError("setup ownership mismatch")
            captured_logs = [file for file in origin.rglob("*") if file.is_file() and
                             (file.suffix.lower() in (".log", ".gz") or "healthchecks" in file.parts)]
            if captured_logs and not args.purge_logs:
                print("Preserving unpacked directory containing logs; add --purge-logs to remove it")
            else:
                removable.append(str(origin))
    build_dirs = list(Path(p["INSTANCE_STATE"]).glob("build.*"))
    removable.extend(str(directory) for directory in build_dirs)
    retained_build_logs = []
    if not args.purge_logs:
        for directory in build_dirs:
            guard(directory)
            for log in directory.rglob("*.log"):
                if log.is_symlink() or not log.is_file():
                    raise ValueError("unsafe build log")
                retained_build_logs.append((log, Path(p["LOG_DIR"]) / "setup-build" / directory.name / log.relative_to(directory)))
    if not args.keep_backups:
        removable.append(p["BACKUP_ROOT"])
    if args.purge_logs:
        if p["INSTANCE_ID"]:
            removable.append(p["LOG_DIR"])
        else:
            # Never delete /var/log/3proxy/instances or unrelated files.
            removable.extend(str(f) for f in Path(p["LOG_DIR"]).glob("3proxy.log*") if f.is_file())
            removable.append(str(Path(p["LOG_DIR"]) / "healthchecks"))
    for file in ("requested.yaml", "build-manifest.json", "backup.state", "monitor-v1-migrated", "manifest.new", "pending-client-ca.crt"):
        removable.append(str(Path(p["INSTANCE_STATE"]) / file))
    # Validate every path before stopping the service or deleting anything.
    for item in removable:
        path = Path(item)
        guard(path, root_owned=item not in (p["DATA_DIR"], p["RUNTIME_DIR"], p["LOG_DIR"], manifest["origin"]))
        if item in (p["DATA_DIR"], p["RUNTIME_DIR"], p["LOG_DIR"]) and path.exists() and os.name == "posix":
            if path.stat().st_uid not in (0, manifest.get("uid")):
                raise ValueError(f"managed directory owner changed: {path}")
    retained_log_dir = Path(p["LOG_DIR"])
    if retained_log_dir.exists():
        guard(retained_log_dir, root_owned=False)
        if os.name == "posix" and retained_log_dir.stat().st_uid not in (0, manifest.get("uid")):
            raise ValueError("log directory owner changed")
        if any(file.is_symlink() or (file.is_file() and file.stat().st_nlink != 1)
               for file in retained_log_dir.rglob("*")):
            raise ValueError("unsafe link in instance logs")
    print(f"{'Cleanup' if args.yes and not args.dry_run else 'Dry-run'}: {p['SERVICE']}")
    for item in removable:
        print(f"  remove {item}")
    print("  preserve ownership manifest; shared journal and OS packages are never removed")
    if args.purge_shared_components:
        print("  shared components retained: ownership and external consumers cannot be proven")
    if args.purge_ufw or args.purge_shared_components:
        from firewall import purge
        # Validate every rule (including later records) before stopping the unit.
        purge(p, manifest, execute=False)
    if not args.yes or args.dry_run:
        return
    if os.geteuid() != 0:
        raise ValueError("real cleanup requires root")
    subprocess.run(["systemctl", "disable", "--now", p["SERVICE"]], check=False)
    active = subprocess.run(["systemctl", "is-active", "--quiet", p["SERVICE"]]).returncode
    if active == 0:
        raise ValueError("selected service is still active; cleanup stopped")
    if args.purge_ufw or args.purge_shared_components:
        from firewall import purge
        purge(p, manifest, execute=True)
    for source, destination in retained_build_logs:
        guard(destination, root_owned=False)
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        destination.chmod(0o600)
    for item in removable:
        path = Path(item)
        if path.is_dir():
            shutil.rmtree(path)
        elif path.exists():
            path.unlink()
    if not args.purge_logs and p["INSTANCE_ID"] and os.name == "posix":
        retained = Path(p["LOG_DIR"])
        if retained.exists():
            # Avoid leaking retained logs to a future account reusing the deleted UID.
            for file in [retained, *retained.rglob("*")]:
                if file.is_symlink() or (file.is_file() and file.stat().st_nlink != 1):
                    raise ValueError("unsafe link in retained logs; user removal stopped")
            for file in [retained, *retained.rglob("*")]:
                os.chown(file, 0, -1, follow_symlinks=False)
    if manifest["user_created"] and account_exists(p["SERVICE_USER"], "passwd"):
        subprocess.run(["userdel", p["SERVICE_USER"]], check=True)
    if manifest["group_created"] and account_exists(p["SERVICE_GROUP"], "group"):
        subprocess.run(["groupdel", p["SERVICE_GROUP"]], check=True)
    manifest["status"] = "removed"
    atomic_json(Path(p["INSTANCE_STATE"]) / "manifest.json", manifest)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "reset-failed", p["SERVICE"]], check=False)


def install_dependencies() -> None:
    packages = ["build-essential", "cmake", "curl", "ca-certificates", "libssl-dev",
                "openssl", "patch", "python3-yaml", "iproute2"]
    missing = []
    for package in packages:
        result = subprocess.run(["dpkg-query", "-W", "-f=${Status}", package],
                                capture_output=True, text=True)
        if result.returncode:
            missing.append(package)
        elif result.stdout.strip() != "install ok installed":
            raise ValueError(f"shared dependency {package} is partially installed; repair it separately")
    if not missing:
        print("Shared dependencies already installed; apt unchanged")
        return
    environment = dict(os.environ, DEBIAN_FRONTEND="noninteractive", NEEDRESTART_MODE="l", LC_ALL="C")
    subprocess.run(["apt-get", "update"], env=environment, check=True)
    simulation = subprocess.run(["apt-get", "-s", "install", "--no-upgrade", "--no-remove",
                                 "--no-install-recommends", *missing],
                                env=environment, capture_output=True, text=True, check=True)
    if re.search(r"(?m)^(?:Remv\s|Inst\s+\S+\s+\[)", simulation.stdout):
        raise ValueError("shared dependency solver requires upgrading/removing existing packages; review separately")
    subprocess.run(["apt-get", "install", "-y", "--no-upgrade", "--no-remove",
                    "--no-install-recommends", *missing], env=environment, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["env", "prepare", "cleanup", "verify", "prepare-log", "unit-intent", "dependencies", "configure-firewall"])
    parser.add_argument("--config", type=Path)
    parser.add_argument("--instance")
    parser.add_argument("--unit-file", type=Path)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--legacy", action="store_true")
    parser.add_argument("--update-existing", action="store_true")
    for flag in ("yes", "dry-run", "keep-backups", "purge-logs", "purge-shared-components", "purge-ufw", "purge-setup", "check-listeners", "existing"):
        parser.add_argument("--" + flag, action="store_true")
    args = parser.parse_args()
    p, config = selected(args)
    if args.action == "env":
        if config is None:
            raise ValueError("saved YAML is unavailable; only cleanup can proceed without YAML")
        for key, value in dict(p, CONFIG=str(config.resolve())).items():
            print(f"{key}={shlex.quote(value)}")
    elif args.action == "configure-firewall":
        from config import load_config
        from firewall import configure
        configure(p, load_config(config))
    elif args.action == "dependencies":
        install_dependencies()
    elif args.action == "unit-intent":
        manifest = read_manifest(p)
        if not manifest or args.unit_file is None:
            raise ValueError("manifest and --unit-file are required")
        guard(args.unit_file)
        digest = hashlib.sha256(args.unit_file.read_bytes()).hexdigest()
        manifest.setdefault("unit_hashes", [])
        if digest not in manifest["unit_hashes"]:
            manifest["unit_hashes"].append(digest)
        atomic_json(Path(p["INSTANCE_STATE"]) / "manifest.json", manifest)
    elif args.action == "prepare-log":
        prepare_log(p)
    elif args.action == "verify":
        manifest = read_manifest(p)
        if not manifest or manifest.get("status") == "removed":
            raise ValueError("selected installation has no active ownership manifest")
        checked_accounts(p, manifest)
        verify_unit(p, manifest)
    elif args.action == "prepare":
        if config is None:
            raise ValueError("configuration is required")
        prepare(p, config, args.source, args.update_existing, check_listeners=args.check_listeners)
    else:
        cleanup(p, args)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit(f"instance error: {exc}")
