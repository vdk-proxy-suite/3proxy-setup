#!/usr/bin/env python3
"""Instance-owned ACME issuance and scheduled deployment; never an unverified fallback."""
from __future__ import annotations
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from zoneinfo import ZoneInfo

import acme_config as policy
import config as config_tool
import instance
import operation_lock
import tls_material as tls

HERE = Path(__file__).resolve().parent


def run(args, *, check=True, **kwargs):
    return subprocess.run([str(x) for x in args], check=check, text=True, capture_output=True, timeout=600, **kwargs)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save_manifest(p, manifest):
    instance.atomic_json(Path(p["INSTANCE_STATE"]) / "manifest.json", manifest)


def verify_tree(root: Path) -> None:
    instance.guard(root)
    if not root.exists():
        return
    for file in root.rglob("*"):
        if file.is_symlink():
            relative = file.relative_to(root).as_posix()
            target = file.resolve(strict=True)
            expected = False
            if relative == "client/lib64":
                expected = target == root / "client/lib"
            match = re.fullmatch(r"(production|staging)/config/live/(ip-[a-f0-9]{16})/(cert|chain|fullchain|privkey)\.pem", relative)
            if match:
                env, lineage, kind = match.groups()
                parent = root / env / "config/archive" / lineage
                expected = target.parent == parent and re.fullmatch(kind + r"[0-9]+\.pem", target.name) is not None
            if not expected:
                raise ValueError(f"unowned ACME symlink: {file}")
            instance.guard(target)
        else:
            instance.guard(file)
            if not file.is_file() and not file.is_dir():
                raise ValueError(f"special file in ACME resources: {file}")
            if file.is_file() and file.stat().st_nlink != 1:
                raise ValueError(f"hardlink in ACME resources: {file}")


def verify_owned(p: dict, manifest: dict) -> None:
    if not p["INSTANCE_ID"]:
        return
    r = policy.resources(p)
    record = manifest.get("acme")
    if record is None:
        if r["root"].exists() or r["root"].is_symlink():
            raise ValueError("unowned ACME directory exists")
        for name in policy.unit_names(p):
            for directory in (r["unit_dir"], Path("/run/systemd/system"), Path("/usr/lib/systemd/system"), Path("/lib/systemd/system")):
                if (directory/name).exists() or (directory/name).is_symlink():
                    raise ValueError("unowned ACME unit exists")
        return
    if not isinstance(record, dict) or set(record) - {"root", "token", "units", "retain_state"}:
        raise ValueError("invalid ACME ownership record")
    units = record.get("units")
    if not isinstance(units, dict) or set(units) - set(policy.unit_names(p)):
        raise ValueError("invalid ACME unit ownership records")
    for hashes in units.values():
        if not isinstance(hashes, list) or any(not isinstance(sha, str) or not re.fullmatch(r"[a-f0-9]{64}", sha) for sha in hashes):
            raise ValueError("invalid ACME unit hashes")
    if not isinstance(record.get("retain_state", False), bool):
        raise ValueError("invalid ACME retention ownership")
    if record.get("root") != str(r["root"]) or record.get("token") != manifest["token"]:
        raise ValueError("ACME ownership identity mismatch")
    verify_tree(r["root"])
    if r["root"].exists():
        if not r["registry"].is_file():
            if any(r["root"].iterdir()):
                raise ValueError("ACME ownership marker missing from nonempty directory")
        elif json.loads(r["registry"].read_text()) != {"instance": p["INSTANCE_ID"], "token": manifest["token"]}:
            raise ValueError("ACME ownership marker mismatch")
    for name in policy.unit_names(p):
        file = r["unit_dir"]/name
        instance.guard(file)
        if Path(str(file)+".d").exists():
            raise ValueError("unowned ACME drop-ins")
        if file.exists() and digest(file) not in record.get("units", {}).get(name, []):
            raise ValueError("ACME unit identity changed")
        for directory in ("/run/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"):
            foreign = Path(directory)/name
            if foreign.exists() or foreign.is_symlink():
                raise ValueError("foreign ACME system unit")


def register(p: dict, data: dict) -> dict:
    manifest = instance.read_manifest(p)
    if manifest is None:
        raise ValueError("instance manifest required before ACME")
    verify_owned(p, manifest)
    r = policy.resources(p)
    if "acme" not in manifest:
        manifest["acme"] = dict(root=str(r["root"]), token=manifest["token"], units={})
        save_manifest(p, manifest)
    if not r["root"].exists():
        r["root"].mkdir(mode=0o700, parents=True)
    if not r["registry"].exists():
        instance.atomic_json(r["registry"], {"instance": p["INSTANCE_ID"], "token": manifest["token"]})
    r["root"].chmod(0o700)
    manifest["acme"]["retain_state"] = policy.settings(data)["retain_state"]
    save_manifest(p, manifest)
    return manifest


def event(p: dict, **values) -> None:
    file = policy.resources(p)["status"]
    old = json.loads(file.read_text()) if file.exists() else {}
    old.update(values)
    instance.atomic_json(file, old)


def bootstrap(p: dict) -> None:
    r = policy.resources(p)
    client = r["client"]
    lock = HERE/"certbot-requirements.txt"
    expected = digest(lock)
    marker = client/"requirements.sha256"
    if marker.is_file() and marker.read_text().strip() == expected:
        if run([client/"bin/certbot", "--version"]).stdout.strip() == "certbot " + policy.CERTBOT_VERSION:
            return
        raise ValueError("installed ACME client does not match its manifest")
    instance.install_dependencies(["python3-venv", "ca-certificates", "openssl"])
    # --copies avoids executable links; lib64 is the sole permitted venv link.
    run([sys.executable, "-m", "venv", "--copies", client])
    run([client/"bin/python", "-m", "pip", "install", "--disable-pip-version-check",
         "--only-binary=:all:", "--require-hashes", "-r", lock])
    if run([client/"bin/certbot", "--version"]).stdout.strip() != "certbot " + policy.CERTBOT_VERSION:
        raise ValueError("unexpected Certbot version")
    marker.write_text(expected+"\n")
    marker.chmod(0o600)


def trust_file(data: dict) -> Path:
    if policy.settings(data)["environment"] == "staging":
        return HERE/"acme-staging-roots.txt"
    return Path(tls.SYSTEM_CA)


def fingerprint(certificate: Path) -> str:
    leaf = tls.CERTIFICATE.findall(certificate.read_bytes())[0].decode()
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(leaf)).hexdigest()


def leaf_info(certificate: Path) -> dict:
    decoded = ssl._ssl._test_decode_cert(str(certificate))
    return dict(fingerprint=fingerprint(certificate),
                not_after=ssl.cert_time_to_seconds(decoded["notAfter"]),
                not_before=ssl.cert_time_to_seconds(decoded["notBefore"]),
                ips=sorted(value for kind, value in decoded.get("subjectAltName", ()) if kind == "IP Address"))


def read_bundle(directory: Path) -> dict:
    return {name: tls.read_input(directory/name, private=name.endswith(".key"))
            for name in ("server.crt", "server.key", "trust.crt") if (directory/name).exists()}


def validate(data: dict, bundle: dict, minimum=86400) -> None:
    supplied = dict(bundle)
    # Always select trust from YAML environment, never trust candidate-provided roots.
    supplied.pop("trust.crt", None)
    if policy.settings(data)["environment"] == "staging":
        supplied["trust.crt"] = trust_file(data).read_bytes()
    tls.validate_bundle(supplied, str(data["server"]["public_ip"]), minimum_seconds=minimum)
    with tempfile.TemporaryDirectory(prefix="3proxy-acme-leaf-") as temporary:
        leaf = Path(temporary)/"leaf.crt"
        leaf.write_bytes(bundle["server.crt"])
        info = leaf_info(leaf)
        if info["not_after"] - info["not_before"] > 7*86400:
            raise ValueError("ACME returned a non-shortlived certificate")


def certbot_args(p: dict, data: dict, *, first: bool) -> list[str]:
    settings = policy.settings(data)
    r = policy.resources(p)
    directory = r["root"]/settings["environment"]
    lineage = "ip-" + hashlib.sha256(str(data["server"]["public_ip"]).encode()).hexdigest()[:16]
    args = [str(r["client"]/"bin/certbot"), "certonly" if first else "renew",
            "--non-interactive", "--agree-tos", "--config", str(r["root"]/"cli.ini"),
            "--config-dir", str(directory/"config"), "--work-dir", str(directory/"work"),
            "--logs-dir", str(directory/"logs"), "--server", policy.DIRECTORIES[settings["environment"]],
            "--cert-name", lineage, "--standalone", "--preferred-challenges", "http-01",
            "--required-profile", "shortlived", "--no-reuse-key", "--no-directory-hooks"]
    if first:
        args += ["--ip-address", str(data["server"]["public_ip"]), "--keep-until-expiring"]
        args += ["--email", settings["email"]] if settings["email"] else ["--register-unsafely-without-email"]
    else:
        args += ["--no-random-sleep-on-renew"]
    return args


def issuance(p: dict, data: dict) -> None:
    r = policy.resources(p)
    settings = policy.settings(data)
    directory = r["root"]/settings["environment"]
    lineage = "ip-" + hashlib.sha256(str(data["server"]["public_ip"]).encode()).hexdigest()[:16]
    live = directory/"config/live"/lineage
    first = not (directory/"config/renewal"/(lineage+".conf")).exists()
    (r["root"]/"cli.ini").write_text("# Instance-owned Certbot configuration; policy supplied by controller.\n")
    with operation_lock.acquire(p["INSTANCE_ID"], http=True):
        # Certbot sees system trust for its HTTPS API; staging leaf trust remains separate.
        environment = dict(os.environ, REQUESTS_CA_BUNDLE=tls.SYSTEM_CA)
        result = run(certbot_args(p, data, first=first), check=False, env=environment)
    if result.returncode:
        raise ValueError("Certbot issuance/renewal failed: " + result.stderr[-1800:] + result.stdout[-1800:])
    verify_tree(r["root"])
    bundle = {}
    for filename, source in (("server.crt", "fullchain.pem"), ("server.key", "privkey.pem")):
        target = (live/source).resolve(strict=True)
        # verify_tree already validated the exact lineage symlink, bounds and ownership.
        bundle[filename] = tls.read_input(target, private=filename.endswith(".key"))
    if settings["environment"] == "staging":
        bundle["trust.crt"] = trust_file(data).read_bytes()
    validate(data, bundle)
    candidate = r["candidate"]
    before = fingerprint(candidate/"server.crt") if (candidate/"server.crt").exists() else None
    tls.replace_directory(candidate, bundle)
    info = leaf_info(candidate/"server.crt")
    instance.atomic_json(candidate/"identity.json", dict(environment=settings["environment"], ip=str(data["server"]["public_ip"]), fingerprint=info["fingerprint"]))
    event(p, last_check=time.time(), last_error=None, candidate=info,
          **({"last_issued": time.time()} if before != info["fingerprint"] else {}))


def check_identity(p: dict, data: dict) -> None:
    r = policy.resources(p)
    meta = json.loads((r["candidate"]/"identity.json").read_text())
    if meta != dict(environment=policy.settings(data)["environment"], ip=str(data["server"]["public_ip"]),
                    fingerprint=fingerprint(r["candidate"]/"server.crt")):
        raise ValueError("candidate identity mismatch")


def active_matches(p: dict, data: dict) -> bool:
    directory = Path(p["CONFIG_DIR"])/"tls"
    try:
        marker = (directory/"mode").read_text().strip()
        return marker == "acme:"+policy.settings(data)["environment"] and leaf_info(directory/"server.crt")["ips"] == [str(data["server"]["public_ip"])]
    except (OSError, ValueError, ssl.SSLError):
        return False


def preflight(p: dict, data: dict) -> None:
    if not policy.enabled(data):
        return
    active = Path(p["CONFIG_DIR"])/"tls"
    if policy.settings(data)["environment"] == "staging" and (active/"server.crt").exists() and not active_matches(p, data):
        raise ValueError("staging cannot replace an existing non-staging listener; use a separate instance")
    register(p, data)
    bootstrap(p)
    if active_matches(p, data):
        validate(data, read_bundle(active), minimum=0)
        return
    issuance(p, data)


def install_candidate(p: dict, data: dict) -> None:
    """Only called after setup has stopped its instance or inside scheduled deploy."""
    r = policy.resources(p)
    check_identity(p, data)
    bundle = read_bundle(r["candidate"])
    validate(data, bundle)
    destination = Path(p["CONFIG_DIR"])/"tls"
    tls.replace_directory(destination, bundle)
    (destination/"mode").write_text("acme:"+policy.settings(data)["environment"]+"\n")
    active_permissions(p)


def active_permissions(p: dict) -> None:
    import grp
    destination = Path(p["CONFIG_DIR"])/"tls"
    gid = grp.getgrnam(p["SERVICE_GROUP"]).gr_gid
    os.chown(destination, 0, gid); destination.chmod(0o750)
    os.chown(destination/"server.key", 0, gid); (destination/"server.key").chmod(0o640)
    if (destination/"ca.key").exists():
        os.chown(destination/"ca.key", 0, 0); (destination/"ca.key").chmod(0o600)


def setup_install(p: dict, data: dict) -> None:
    if active_matches(p, data):
        # A manual reconfigure must not apply a queued renewal outside the daily window.
        validate(data, read_bundle(Path(p["CONFIG_DIR"])/"tls"), minimum=0)
        return
    install_candidate(p, data)


def rendered_units(p: dict, data: dict) -> dict[str, str]:
    r = policy.resources(p)
    controller = (Path(p["INSTALLED_ROOT"])/"tools/acme.py").as_posix()
    common = "[Unit]\nDescription=3proxy instance ACME {action}\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=oneshot\nUser=root\nUMask=0077\nExecStart=/usr/bin/python3 {controller} {action} --instance {identity}\nTimeoutStartSec=900\n"
    output = {}
    for action in ("renew", "deploy"):
        output[r["prefix"]+"-"+action+".service"] = common.format(action=action, controller=controller, identity=p["INSTANCE_ID"])
        schedule = ("OnBootSec=5min\nOnUnitActiveSec="+str(policy.settings(data)["interval_minutes"])+"min\nRandomizedDelaySec=60\n") if action == "renew" else "OnCalendar=*-*-* 05:00:00 Europe/Moscow\nAccuracySec=1s\nRandomizedDelaySec=0\n"
        output[r["prefix"]+"-"+action+".timer"] = "[Unit]\nDescription=3proxy ACME "+action+" schedule\n\n[Timer]\n"+schedule+"Persistent=false\nUnit="+r["prefix"]+"-"+action+".service\n\n[Install]\nWantedBy=timers.target\n"
    return output


def configure(p: dict, data: dict) -> None:
    manifest = instance.read_manifest(p)
    if not p["INSTANCE_ID"] or not manifest or not manifest.get("acme"):
        return
    verify_owned(p, manifest)
    r = policy.resources(p)
    if not policy.enabled(data):
        for name in policy.unit_names(p):
            if name.endswith(".timer"):
                run(["systemctl", "disable", "--now", name], check=False)
        return
    units = rendered_units(p, data)
    for name, content in units.items():
        sha = hashlib.sha256(content.encode()).hexdigest()
        hashes = manifest["acme"]["units"].setdefault(name, [])
        if sha not in hashes: hashes.append(sha)
    manifest["acme"]["retain_state"] = policy.settings(data)["retain_state"]
    save_manifest(p, manifest)
    for name, content in units.items():
        file = r["unit_dir"]/name
        fd, name_tmp = tempfile.mkstemp(prefix="."+name+".", dir=r["unit_dir"])
        temporary = Path(name_tmp)
        try:
            with os.fdopen(fd, "w") as stream: stream.write(content)
            temporary.chmod(0o644); os.replace(temporary, file)
        finally:
            if temporary.exists(): temporary.unlink()
    run(["systemctl", "daemon-reload"])
    for action in ("renew", "deploy"):
        name = r["prefix"]+"-"+action+".timer"
        if policy.settings(data)["renewal_enabled"]:
            run(["systemctl", "enable", name]); run(["systemctl", "restart", name])
        else:
            run(["systemctl", "disable", "--now", name])
    actual = served(p, data, fingerprint(Path(p["CONFIG_DIR"])/"tls/server.crt"))
    old = json.loads(r["status"].read_text()) if r["status"].exists() else {}
    if old.get("served", [{}])[0].get("fingerprint") != actual[0]["fingerprint"]:
        event(p, last_deployed=time.time(), served=actual, last_deploy_error=None)


def served(p: dict, data: dict, expected: str | None = None) -> list[dict]:
    results = []
    context = ssl.create_default_context(cafile=str(trust_file(data)))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    for listener in data["listeners"]:
        if listener["protocol"] != "https": continue
        host = config_tool.listener_ip(data, listener)
        if host in ("0.0.0.0", "::"): host = "127.0.0.1" if host == "0.0.0.0" else "::1"
        with socket.create_connection((host, listener["port"]), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=str(data["server"]["public_ip"])) as connection:
                sha = hashlib.sha256(connection.getpeercert(binary_form=True)).hexdigest()
                expiry = ssl.cert_time_to_seconds(connection.getpeercert()["notAfter"])
                if expected is not None and sha != expected: raise ValueError("listener still serves a different certificate")
                results.append(dict(listener=listener["id"], fingerprint=sha, not_after=expiry))
    if not results: raise ValueError("ACME has no HTTPS listeners")
    return results


def wait_served(p: dict, data: dict, expected: str) -> list[dict]:
    for attempt in range(10):
        try:
            return served(p, data, expected)
        except (OSError, ValueError, ssl.SSLError):
            if attempt == 9:
                raise
            time.sleep(.5)
    raise ValueError("listener did not become ready")


def in_window(now: datetime | None = None) -> bool:
    local = (now or datetime.now(ZoneInfo("Europe/Moscow"))).astimezone(ZoneInfo("Europe/Moscow"))
    return local.hour == 5 and local.minute == 0


def deploy(p: dict, data: dict, *, now: datetime | None = None) -> str:
    if not policy.settings(data)["renewal_enabled"]: return "automation disabled"
    if not in_window(now): return "outside 05:00 Europe/Moscow window"
    if run(["systemctl", "is-active", "--quiet", p["SERVICE"]], check=False).returncode:
        return "instance is stopped; not starting it"
    r = policy.resources(p)
    if not (r["candidate"]/"identity.json").exists(): return "no candidate"
    check_identity(p, data)
    validate(data, read_bundle(r["candidate"]))
    expected = fingerprint(r["candidate"]/"server.crt")
    try:
        current = served(p, data)
    except ssl.SSLCertVerificationError:
        current = [leaf_info(Path(p["CONFIG_DIR"])/"tls/server.crt")]
    if all(item["fingerprint"] == expected for item in current):
        event(p, last_deploy_error=None, served=current)
        return "already deployed"
    destination = Path(p["CONFIG_DIR"])/"tls"
    rollback = r["root"]/"deploy-rollback"
    if rollback.exists(): shutil.rmtree(rollback)
    shutil.copytree(destination, rollback)
    try:
        install_candidate(p, data)
        run(["systemctl", "restart", p["SERVICE"]])
        actual = wait_served(p, data, expected)
    except Exception:
        shutil.rmtree(destination)
        shutil.copytree(rollback, destination)
        active_permissions(p)
        run(["systemctl", "restart", p["SERVICE"]])
        wait_served(p, data, current[0]["fingerprint"])
        event(p, last_deploy_error="new certificate deployment failed; previous certificate restored")
        raise
    event(p, last_deployed=time.time(), last_deploy_error=None, served=actual)
    return "new certificate deployed and verified"


def status(p: dict, data: dict) -> dict:
    r = policy.resources(p)
    result = json.loads(r["status"].read_text()) if r["status"].exists() else {}
    result["renewal_enabled"] = policy.settings(data)["renewal_enabled"]
    result["environment"] = policy.settings(data)["environment"]
    result["served"] = served(p, data)
    remaining = min(item["not_after"] for item in result["served"]) - time.time()
    result["remaining_hours"] = round(remaining/3600, 2)
    result["state"] = "critical" if remaining < 86400 else "warning" if remaining < 172800 else "ok"
    if result.get("last_error") or result.get("last_deploy_error") or not result["renewal_enabled"]:
        if result["state"] == "ok": result["state"] = "warning"
    result["timers"] = {}
    for action in ("renew", "deploy"):
        unit = r["prefix"]+"-"+action+".timer"
        result["timers"][action] = dict(
            active=run(["systemctl", "is-active", "--quiet", unit], check=False).returncode == 0,
            enabled=run(["systemctl", "is-enabled", "--quiet", unit], check=False).returncode == 0)
    if result["renewal_enabled"] and any(not all(value.values()) for value in result["timers"].values()):
        if result["state"] == "ok": result["state"] = "warning"
    if result.get("last_check", 0) < time.time() - (policy.settings(data)["interval_minutes"]*120+300):
        if result["state"] == "ok": result["state"] = "warning"
    active_sha = fingerprint(Path(p["CONFIG_DIR"])/"tls/server.crt")
    if any(item["fingerprint"] != active_sha for item in result["served"]): result["state"] = "critical"
    return result


def cleanup(p: dict, manifest: dict, *, execute: bool, purge_logs=False) -> None:
    if not manifest.get("acme"): return
    verify_owned(p, manifest)
    r = policy.resources(p)
    print("  ACME: remove owned timers/client; "+("retain certificate/account/renewal state" if manifest["acme"].get("retain_state") else "remove certificate/account/renewal state"))
    if not execute: return
    # Caller holds the instance lock. Queued jobs cannot mutate state while cleanup runs.
    for name in policy.unit_names(p):
        run(["systemctl", "disable" if name.endswith(".timer") else "stop", "--now" if name.endswith(".timer") else name, *([name] if name.endswith(".timer") else [])], check=False)
    for name in policy.unit_names(p):
        file = r["unit_dir"]/name
        if file.exists(): file.unlink()
    if r["root"].exists():
        if not purge_logs:
            logs = Path(p["LOG_DIR"])/"acme"
            for environment in ("production", "staging"):
                source = r["root"]/environment/"logs"
                if source.exists():
                    logs.mkdir(mode=0o700, parents=True, exist_ok=True)
                    shutil.copytree(source, logs/environment, dirs_exist_ok=True)
        if manifest["acme"].get("retain_state"):
            for name in ("client", "candidate", "deploy-rollback"):
                target = r["root"]/name
                if target.exists(): shutil.rmtree(target)
        else:
            shutil.rmtree(r["root"])
    run(["systemctl", "daemon-reload"])


def backup(p: dict, directory: Path) -> None:
    manifest = instance.read_manifest(p)
    if not p["INSTANCE_ID"] or not manifest or not manifest.get("acme"): return
    verify_owned(p, manifest)
    r = policy.resources(p)
    destination = directory/"acme"
    destination.mkdir(mode=0o700)
    state = {}
    for name in policy.unit_names(p):
        source = r["unit_dir"]/name
        if source.exists():
            shutil.copyfile(source, destination/name)
            state[name] = dict(enabled=run(["systemctl","is-enabled","--quiet",name],check=False).returncode == 0,
                               active=run(["systemctl","is-active","--quiet",name],check=False).returncode == 0)
    for name in ("status.json", "candidate"):
        source = r["root"]/name
        if source.is_dir(): shutil.copytree(source, destination/name)
        elif source.exists(): shutil.copyfile(source, destination/name)
    instance.atomic_json(destination/"units.json", state)


def rollback(p: dict, directory: Path) -> None:
    manifest = instance.read_manifest(p)
    if not p["INSTANCE_ID"] or not manifest or not manifest.get("acme"): return
    verify_owned(p, manifest)
    r = policy.resources(p)
    saved = directory/"acme"
    for name in policy.unit_names(p):
        if name.endswith(".timer"): run(["systemctl","disable","--now",name],check=False)
        target = r["unit_dir"]/name
        source = saved/name
        if source.exists():
            # Only restore files whose contents belong to this instance's known unit history.
            if digest(source) not in manifest["acme"]["units"].get(name, []):
                raise ValueError("backup ACME unit ownership mismatch")
            shutil.copyfile(source,target);target.chmod(0o644)
        elif target.exists(): target.unlink()
    for name in ("status.json", "candidate"):
        target=r["root"]/name
        if target.is_dir(): shutil.rmtree(target)
        elif target.exists(): target.unlink()
        source=saved/name
        if source.is_dir(): shutil.copytree(source,target)
        elif source.exists(): shutil.copyfile(source,target)
    run(["systemctl","daemon-reload"])
    states=json.loads((saved/"units.json").read_text()) if (saved/"units.json").exists() else {}
    for name, state in states.items():
        if not name.endswith(".timer"): continue
        if state["enabled"]: run(["systemctl","enable",name])
        if state["active"]: run(["systemctl","start",name])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("preflight", "install", "configure", "renew", "deploy", "status", "backup", "rollback"))
    parser.add_argument("--config", type=Path)
    parser.add_argument("--instance")
    parser.add_argument("--directory", type=Path)
    args = parser.parse_args()
    if args.instance:
        p = instance.paths(args.instance)
        path = Path(p["CONFIG_DIR"])/"setup.yaml"
    elif args.config:
        data = config_tool.load_config(args.config);config_tool.validate(data)
        p = instance.paths(data.get("instance", {}).get("id"));path=args.config
    else: parser.error("--config or --instance required")
    data = config_tool.load_config(path);config_tool.validate(data)
    if not policy.enabled(data) and args.action not in ("configure", "backup", "rollback"): return 0
    if os.geteuid() != 0: raise ValueError("ACME controller requires root")
    with operation_lock.acquire(p["INSTANCE_ID"]):
        manifest = instance.read_manifest(p)
        if not manifest or manifest.get("status") == "removed": raise ValueError("no active instance ownership")
        instance.checked_accounts(p, manifest);instance.verify_unit(p, manifest)
        try:
            if args.action in ("backup", "rollback"):
                if args.directory is None or args.directory.resolve().parent != Path(p["BACKUP_ROOT"]).resolve():
                    raise ValueError("invalid instance backup directory")
                instance.guard(args.directory)
                (backup if args.action == "backup" else rollback)(p, args.directory)
            elif args.action == "preflight": preflight(p, data)
            elif args.action == "install": setup_install(p, data)
            elif args.action == "configure": configure(p, data)
            elif args.action == "renew":
                if policy.settings(data)["renewal_enabled"]:
                    issuance(p, data)
                    if run(["systemctl", "is-active", "--quiet", p["SERVICE"]], check=False).returncode == 0:
                        report = status(p, data);event(p, observed=report)
                        print(json.dumps(report))
                    else:
                        print("renewal checked; instance remains stopped")
            elif args.action == "deploy": print(deploy(p, data))
            else:
                report=status(p, data);print(json.dumps(report))
                return 0 if report["state"] == "ok" else 1
        except Exception as exc:
            if policy.resources(p)["root"].exists(): event(p, last_error=str(exc), last_failure=time.time())
            raise
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"ACME error: {exc}")
