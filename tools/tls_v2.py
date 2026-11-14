"""Named certificate lifecycle for schema 2, with one transactional instance deploy."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import ssl
import tempfile
import time

import acme
import acme_config as policy
import addressing
import instance
import schema_v2 as schema
import tls_material as material


def contexts(p: dict, data: dict, *, only_acme: bool = False):
    for name, certificate in schema.certificates(data).items():
        if only_acme and certificate["mode"] != "acme":
            continue
        wanted = schema.certificate_identities(data, name)
        scoped = dict(p, CERTIFICATE_ID=name)
        view = {"instance": data["instance"], "tls": {"server": copy.deepcopy(certificate)},
                "server": {"public_ip": wanted[0].value, "listen_ip": "127.0.0.1"}, "listeners": []}
        for listener in schema.expanded_listeners(data):
            if listener.get("tls_certificate") != name:
                continue
            bind = listener["listen_ip"]
            hosts = ["127.0.0.1", "::1"] if bind == "::" else ["127.0.0.1" if bind == "0.0.0.0" else bind]
            for host in hosts:
                view["listeners"].append(dict(listener, listen_ip=host))
        yield name, scoped, view


def active_permissions(p: dict, data: dict) -> None:
    import grp
    root = Path(p["CONFIG_DIR"]) / "tls"
    if not root.exists():
        return
    gid = grp.getgrnam(p["SERVICE_GROUP"]).gr_gid
    os.chown(root, 0, gid); root.chmod(0o750)
    for _, scoped, _ in contexts(p, data):
        if acme.active_directory(scoped).exists():
            acme.active_permissions(scoped)


def pending_directory(p: dict, name: str) -> Path:
    if not schema.CERT_ID.fullmatch(name):
        raise ValueError("invalid certificate id")
    return Path(p["INSTANCE_STATE"]) / "pending-certificates" / name


def validate_material(data: dict, name: str, bundle: dict, *, minimum: int = 86400) -> None:
    material.validate_bundle(bundle, [i.value for i in schema.certificate_identities(data, name)],
                             minimum_seconds=minimum, exact_sans=True)


def collect_external(p: dict, data: dict) -> dict[str, dict]:
    """Read/verify all inputs before ownership writes or service stops."""
    result = {}
    for name, certificate in schema.certificates(data).items():
        if certificate["mode"] != "external":
            continue
        active = schema.certificate_directory(data, p["CONFIG_DIR"], name)
        pending = pending_directory(p, name)
        bundle = {}
        for setting, filename in [("fullchain_file", "server.crt"), ("private_key_file", "server.key"), ("ca_file", "trust.crt")]:
            source = certificate.get(setting, material.SYSTEM_CA if setting == "ca_file" else None)
            if source == material.SYSTEM_CA:
                continue
            path = Path(source)
            if path == active / filename and (pending / filename).exists():
                path = pending / filename
            bundle[filename] = material.read_input(path, private=filename.endswith(".key"))
        validate_material(data, name, bundle)
        result[name] = bundle
    return result


def stage_external(p: dict, data: dict, bundles: dict[str, dict]) -> None:
    for name, bundle in bundles.items():
        material.replace_directory(pending_directory(p, name), bundle)
        active = schema.certificate_directory(data, p["CONFIG_DIR"], name)
        cert = data["tls"]["certificates"][name]
        cert["fullchain_file"] = str(active / "server.crt")
        cert["private_key_file"] = str(active / "server.key")
        if "trust.crt" in bundle:
            cert["ca_file"] = str(active / "trust.crt")


def managed_candidate(p: dict, data: dict, name: str) -> dict:
    certificate = schema.certificates(data)[name]
    active = schema.certificate_directory(data, p["CONFIG_DIR"], name)
    minimum_ca = certificate["validity_days"] * 86400
    regenerate = certificate["regenerate_on_setup"]
    with tempfile.TemporaryDirectory(prefix="3proxy-managed-") as temporary:
        work = Path(temporary)
        reused_ca = False
        if not regenerate and (active / "ca.crt").exists() and (active / "ca.key").exists():
            try:
                ca = material.read_input(active / "ca.crt")
                key = material.read_input(active / "ca.key", private=True)
                (work / "ca.crt").write_bytes(ca); (work / "ca.key").write_bytes(key)
                (work / "ca.key").chmod(0o600)
                material.openssl("x509", "-in", str(work / "ca.crt"), "-noout", "-checkend", str(minimum_ca))
                material.openssl("verify", "-CAfile", str(work / "ca.crt"), str(work / "ca.crt"))
                if "CA:TRUE" not in material.openssl("x509", "-in", str(work / "ca.crt"), "-noout", "-text"):
                    raise ValueError("managed CA missing CA constraint")
                ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(str(work / "ca.crt"), str(work / "ca.key"), password=lambda: "")
                reused_ca = True
            except (OSError, ValueError, ssl.SSLError):
                reused_ca = False
        if not reused_ca:
            material.openssl("req", "-x509", "-newkey", "rsa:4096", "-nodes", "-sha256", "-keyout", str(work / "ca.key"),
                             "-out", str(work / "ca.crt"), "-days", str(certificate["ca_validity_days"]),
                             "-subj", "/CN=3proxy-managed-" + name, "-addext", "basicConstraints=critical,CA:TRUE",
                             "-addext", "keyUsage=critical,keyCertSign,cRLSign")
            (work / "ca.key").chmod(0o600)
        if reused_ca and (active / "server.crt").exists() and (active / "server.key").exists():
            try:
                bundle = {file: material.read_input(active / file, private=file.endswith(".key"))
                          for file in ("server.crt", "server.key", "ca.crt", "ca.key")}
                validate_material(data, name, dict(bundle, **{"trust.crt": bundle["ca.crt"]}))
                return bundle
            except (ValueError, OSError):
                pass
        sans = ",".join(("DNS:" if i.kind == "dns" else "IP:") + i.value for i in schema.certificate_identities(data, name))
        ext = work / "leaf.ext"
        ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                       "extendedKeyUsage=serverAuth\nsubjectAltName=" + sans + "\n")
        material.openssl("req", "-new", "-newkey", "rsa:4096", "-nodes", "-sha256", "-keyout", str(work / "server.key"),
                         "-out", str(work / "leaf.csr"), "-subj", "/CN=3proxy-managed-leaf")
        (work / "server.key").chmod(0o600)
        material.openssl("x509", "-req", "-in", str(work / "leaf.csr"), "-CA", str(work / "ca.crt"),
                         "-CAkey", str(work / "ca.key"), "-CAcreateserial", "-days", str(certificate["validity_days"]),
                         "-sha256", "-extfile", str(ext), "-out", str(work / "server.crt"))
        bundle = {file: (work / file).read_bytes() for file in ("server.crt", "server.key", "ca.crt", "ca.key")}
        validate_material(data, name, dict(bundle, **{"trust.crt": bundle["ca.crt"]}))
        return bundle


def preflight(p: dict, data: dict) -> None:
    import firewall
    firewall.configure(p, data, rules=firewall.acme_rules(data))
    for name, scoped, view in contexts(p, data):
        mode = view["tls"]["server"]["mode"]
        if mode == "acme":
            acme.preflight(scoped, view)
        elif mode == "managed":
            material.replace_directory(pending_directory(p, name), managed_candidate(p, data, name))
        else:
            # Input was staged by instance.prepare before the source path is replaced.
            pending = pending_directory(p, name)
            bundle = acme.read_bundle(pending) if pending.exists() else collect_external(p, data)[name]
            validate_material(data, name, bundle)
            material.replace_directory(pending, bundle)


def install(p: dict, data: dict) -> None:
    if acme.run(["systemctl", "is-active", "--quiet", p["SERVICE"]], check=False).returncode == 0:
        raise ValueError("certificate install requires the selected instance to be stopped")
    for name, scoped, view in contexts(p, data):
        mode = view["tls"]["server"]["mode"]
        if mode == "acme":
            acme.setup_install(scoped, view)
        else:
            pending = pending_directory(p, name)
            bundle = acme.read_bundle(pending)
            if mode == "managed":
                bundle.update({f: material.read_input(pending / f, private=f.endswith(".key")) for f in ("ca.crt", "ca.key")})
            validate_material(data, name, dict(bundle, **({"trust.crt": bundle["ca.crt"]} if mode == "managed" else {})))
            target = acme.active_directory(scoped)
            material.replace_directory(target, bundle)
            (target / "mode").write_text(mode + "\n")
    active_permissions(p, data)


def renew(p: dict, data: dict) -> None:
    failures = []
    for name, scoped, view in contexts(p, data, only_acme=True):
        if not policy.settings(view)["renewal_enabled"]:
            continue
        try:
            acme.issuance(scoped, view)
        except Exception as exc:
            acme.event(scoped, last_error=str(exc), last_failure=time.time())
            failures.append(name)
    if failures:
        raise ValueError("ACME renewal failed for certificates: " + ", ".join(failures))


def configure(p: dict, data: dict) -> None:
    entries = list(contexts(p, data, only_acme=True))
    if not entries:
        acme.configure(p, {}, verify_served=False)
        return
    aggregate = copy.deepcopy(entries[0][2])
    settings = [policy.settings(view) for _, _, view in entries]
    block = aggregate["tls"]["server"]["acme"]
    block["renewal"] = dict(enabled=any(s["renewal_enabled"] for s in settings),
                            interval_minutes=min(s["interval_minutes"] for s in settings))
    block["cleanup"] = dict(retain_state=any(s["retain_state"] for s in settings))
    acme.configure(p, aggregate, verify_served=False)
    for _, scoped, view in entries:
        actual = acme.served(scoped, view, acme.fingerprint(acme.active_directory(scoped) / "server.crt"))
        acme.event(scoped, served=actual)


def status(p: dict, data: dict) -> dict:
    reports = {}
    for name, scoped, view in contexts(p, data, only_acme=True):
        try:
            reports[name] = acme.status(scoped, view)
        except Exception as exc:
            reports[name] = dict(state="critical", error=str(exc))
    states = {report["state"] for report in reports.values()}
    return dict(schema_version=2, certificates=reports,
                state="critical" if "critical" in states else "warning" if "warning" in states else "ok")


def deploy(p: dict, data: dict, *, now=None) -> str:
    if not acme.in_window(now):
        return "outside 05:00 Europe/Moscow window"
    if acme.run(["systemctl", "is-active", "--quiet", p["SERVICE"]], check=False).returncode:
        return "instance is stopped; not starting it"
    updates = []
    for name, scoped, view in contexts(p, data, only_acme=True):
        if not policy.settings(view)["renewal_enabled"]:
            continue
        candidate = policy.resources(scoped)["candidate"]
        if not (candidate / "identity.json").exists():
            continue
        acme.check_identity(scoped, view)
        acme.validate(view, acme.read_bundle(candidate))
        fingerprint = acme.fingerprint(candidate / "server.crt")
        if fingerprint != acme.fingerprint(acme.active_directory(scoped) / "server.crt"):
            updates.append((name, scoped, view, fingerprint))
    if not updates:
        return "no changed certificate candidates"
    destination = Path(p["CONFIG_DIR"]) / "tls"
    instance.guard(destination)
    rollback = policy.resources(p)["root"] / "deploy-rollback-v2"
    instance.guard(rollback)
    if rollback.exists():
        shutil.rmtree(rollback)
    shutil.copytree(destination, rollback)
    previous = {name: acme.fingerprint(acme.active_directory(scoped) / "server.crt") for name, scoped, _, _ in updates}
    try:
        for _, scoped, view, _ in updates:
            acme.install_candidate(scoped, view)
        active_permissions(p, data)
        acme.run(["systemctl", "restart", p["SERVICE"]])
        for _, scoped, view, fingerprint in updates:
            acme.wait_served(scoped, view, fingerprint)
    except Exception:
        shutil.rmtree(destination)
        shutil.copytree(rollback, destination)
        active_permissions(p, data)
        acme.run(["systemctl", "restart", p["SERVICE"]])
        for name, scoped, view, _ in updates:
            acme.wait_served(scoped, view, previous[name])
            acme.event(scoped, last_deploy_error="certificate batch failed; previous set restored")
        raise
    for _, scoped, view, _ in updates:
        acme.event(scoped, last_deployed=time.time(), last_deploy_error=None, served=acme.served(scoped, view))
    return "certificate batch deployed with one instance restart"
