#!/usr/bin/env python3
"""Conservative UFW ownership: never adopt a preexisting matching rule."""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess

import yaml

from instance import atomic_json, guard, read_manifest


def required_rules(data: dict) -> list[list[str]]:
    rules = []
    external_udp = False
    for listener in data["listeners"]:
        address = listener.get("listen_ip", data["server"]["listen_ip"])
        if ipaddress.ip_address(address).is_loopback:
            continue
        rule = ["allow", f"{listener['port']}/tcp"]
        if rule not in rules:
            rules.append(rule)
        external_udp |= "udp" in listener.get("capabilities", [])
    if external_udp:
        rules.append(["allow", "from", data["server"]["udp_client_cidr"], "to", "any",
                      "port", "1024:65535", "proto", "udp"])
    return rules


def signature(args: list[str]) -> tuple | None:
    if not args or args[0] != "allow":
        return None
    if len(args) == 2 and "/" in args[1]:
        port, protocol = args[1].split("/", 1)
        return protocol, port, "any", "any"
    # Recognize only our destination-port rules, allowing UFW's canonical
    # proto/from/to ordering. Unknown qualifiers/source ports are not equivalent.
    values = {}
    last_address = None
    index = 1
    while index < len(args):
        key = args[index]
        if key not in ("proto", "from", "to", "port") or key in values or index + 1 >= len(args):
            return None
        if key == "port" and last_address != "to":
            return None
        values[key] = args[index + 1]
        if key in ("from", "to"):
            last_address = key
        index += 2
    if "proto" not in values or "port" not in values:
        return None
    def address(value):
        if value == "any":
            return value
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return None
        return "any" if network.prefixlen == 0 else network.with_prefixlen
    source = address(values.get("from", "any"))
    destination = address(values.get("to", "any"))
    if source is None or destination is None:
        return None
    return values["proto"], values["port"], source, destination


def added_rules() -> list[tuple[list[str], str | None]]:
    result = subprocess.run(["ufw", "show", "added"], capture_output=True, text=True, check=True,
                            env=dict(os.environ, LC_ALL="C"))
    rules = []
    for line in result.stdout.splitlines():
        if not line.startswith("ufw "):
            continue
        args = shlex.split(line)[1:]
        comment = None
        if "comment" in args:
            index = args.index("comment")
            comment = args[index + 1] if len(args) > index + 1 else None
            args = args[:index]
        rules.append((args, comment))
    return rules


def configure(p: dict, data: dict) -> None:
    if not data["server"]["manage_ufw"]:
        return
    if shutil.which("ufw") is None:
        print("UFW unavailable; no firewall changes")
        return
    status = subprocess.run(["ufw", "status"], capture_output=True, text=True, check=True,
                            env=dict(os.environ, LC_ALL="C"))
    if "Status: active" not in status.stdout:
        print("UFW inactive; no firewall changes")
        return
    manifest = read_manifest(p)
    if manifest is None:
        raise ValueError("firewall mutation requires an ownership manifest")
    marker = f"3proxy-setup:{p['INSTANCE_ID'] or 'legacy'}:{manifest['token']}"
    existing = added_rules()
    for args in required_rules(data):
        matches = [(rule, comment) for rule, comment in existing if signature(rule) == signature(args)]
        if matches:
            print(f"Preserving existing UFW rule for {signature(args)}; no ownership adopted")
            continue
        record = dict(args=args, comment=marker)
        if record not in manifest.setdefault("ufw_rules", []):
            manifest["ufw_rules"].append(record)
        # Persist intent first; cleanup requires the exact observed comment as well.
        atomic_json(Path(p["INSTANCE_STATE"]) / "manifest.json", manifest)
        subprocess.run(["ufw", *args, "comment", marker], check=True)
        existing.append((args, marker))


def neighbor_uses(p: dict, target: list[str]) -> bool:
    state = Path(p["INSTANCE_STATE"])
    registry = state.parent.parent if p["INSTANCE_ID"] else state.parent
    manifests = [*registry.glob("instances/*/manifest.json"), registry / "legacy/manifest.json"]
    for file in manifests:
        if not file.exists() or file.parent == state:
            continue
        guard(file)
        try:
            other = json.loads(file.read_text())
        except (ValueError, OSError):
            return True
        if other.get("status") == "removed":
            continue
        config = file.parent / "requested.yaml"
        if not config.exists():
            return True
        try:
            rules = required_rules(yaml.safe_load(config.read_text()))
        except (ValueError, KeyError, TypeError, yaml.YAMLError):
            return True
        for rule in rules:
            if signature(rule) == signature(target):
                return True
            if signature(rule)[0] == signature(target)[0] == "udp":
                # Dynamic relay ranges can overlap even with different client CIDRs.
                return True
    return False


def validate_ownership(p: dict, manifest: dict) -> tuple[list, str]:
    records = manifest.get("ufw_rules", [])
    if not isinstance(records, list):
        raise ValueError("firewall ownership records must be a list")
    token = manifest.get("token")
    if not isinstance(token, str) or not token:
        raise ValueError("firewall ownership token is invalid")
    expected = f"3proxy-setup:{p['INSTANCE_ID'] or 'legacy'}:{token}"
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("args"), list) or any(
                not isinstance(arg, str) for arg in record["args"]):
            raise ValueError("firewall ownership record is invalid")
        args = record.get("args", [])
        target = signature(args)
        valid_tcp = (target is not None and target[0] == "tcp" and target[1].isdigit()
                     and 1 <= int(target[1]) <= 65535 and args == ["allow", target[1] + "/tcp"])
        valid_udp = False
        if target and target[0] == "udp" and target[1] == "1024:65535":
            try:
                network = ipaddress.ip_network(args[2], strict=False)
                valid_udp = (network.version in (4, 6) and args == ["allow", "from", args[2], "to", "any",
                            "port", "1024:65535", "proto", "udp"])
            except (ValueError, IndexError):
                pass
        if not (valid_tcp or valid_udp) or record.get("comment") != expected:
            raise ValueError("firewall ownership record is invalid")
    return records, expected


def purge(p: dict, manifest: dict, *, execute: bool) -> None:
    records, expected = validate_ownership(p, manifest)
    if not records:
        print("No exclusively owned UFW rules recorded; existing rules retained")
        return
    if shutil.which("ufw") is None:
        print("UFW unavailable; owned rules retained")
        return
    existing = added_rules()
    for record in records[:]:
        args = record["args"]
        target = signature(args)
        matches = [(rule, comment) for rule, comment in existing if signature(rule) == target]
        if len(matches) != 1 or matches[0][1] != expected:
            print(f"UFW rule {target} retained: ownership comment changed or ambiguous")
            continue
        if neighbor_uses(p, args):
            print(f"UFW rule {target} retained: another instance may require it")
            continue
        if target[0] == "tcp":
            listeners = subprocess.run(["ss", "-H", "-lnt", f"sport = :{target[1]}"],
                                       capture_output=True, text=True, check=True)
            if listeners.stdout.strip():
                print(f"UFW rule {target} retained: port is still in use")
                continue
        print(f"Remove exclusively owned UFW rule: {args}")
        if execute:
            subprocess.run(["ufw", "--force", "delete", *args], check=True)
            manifest["ufw_rules"].remove(record)
            atomic_json(Path(p["INSTANCE_STATE"]) / "manifest.json", manifest)
