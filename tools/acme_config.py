"""Strict YAML contract and deterministic ACME resource names."""
from __future__ import annotations
from pathlib import Path
import re

CERTBOT_VERSION = "5.8.0"
DIRECTORIES = {
    "production": "https://acme-v02.api.letsencrypt.org/directory",
    "staging": "https://acme-staging-v02.api.letsencrypt.org/directory",
}


def enabled(data: dict) -> bool:
    return data.get("tls", {}).get("server", {}).get("mode") == "acme_ip"


def settings(data: dict) -> dict:
    value = data["tls"]["server"]["acme"]
    return dict(environment=value.get("environment", "production"), email=value.get("email"),
                renewal_enabled=value.get("renewal", {}).get("enabled", True),
                interval_minutes=value.get("renewal", {}).get("interval_minutes", 60),
                retain_state=value.get("cleanup", {}).get("retain_state", False))


def validate(server: dict) -> None:
    if set(server) != {"mode", "acme"}:
        raise ValueError("acme_ip tls.server must contain only mode and acme")
    value = server["acme"]
    if not isinstance(value, dict) or set(value) - {"environment", "email", "agree_tos", "profile", "challenge", "renewal", "deploy", "cleanup"}:
        raise ValueError("unsupported tls.server.acme settings")
    if value.get("environment", "production") not in ("production", "staging"):
        raise ValueError("ACME environment must be production or staging")
    if value.get("agree_tos") is not True:
        raise ValueError("ACME requires explicit agree_tos: true")
    if value.get("profile", "shortlived") != "shortlived" or value.get("challenge", "http-01") != "http-01":
        raise ValueError("ACME IP requires shortlived and http-01")
    email = value.get("email")
    if email is not None and (not isinstance(email, str) or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or len(email) > 254):
        raise ValueError("invalid ACME contact email")
    for name, keys in (("renewal", {"enabled", "interval_minutes"}), ("deploy", {"time", "timezone"}), ("cleanup", {"retain_state"})):
        block = value.get(name, {})
        if not isinstance(block, dict) or set(block) - keys:
            raise ValueError(f"unsupported ACME {name} settings")
    renewal = value.get("renewal", {})
    if not isinstance(renewal.get("enabled", True), bool):
        raise ValueError("ACME renewal.enabled must be boolean")
    interval = renewal.get("interval_minutes", 60)
    if isinstance(interval, bool) or not isinstance(interval, int) or not 5 <= interval <= 720:
        raise ValueError("ACME renewal.interval_minutes must be 5..720")
    deploy = value.get("deploy", {})
    if deploy.get("time", "05:00") != "05:00" or deploy.get("timezone", "Europe/Moscow") != "Europe/Moscow":
        raise ValueError("ACME deploy is fixed at 05:00 Europe/Moscow")
    if not isinstance(value.get("cleanup", {}).get("retain_state", False), bool):
        raise ValueError("ACME cleanup.retain_state must be boolean")


def resources(p: dict) -> dict:
    identity = p["INSTANCE_ID"]
    if not identity:
        raise ValueError("ACME requires a named instance.id")
    root = Path("/var/lib/3proxy-acme/instances") / identity
    return dict(root=root, client=root / "client", candidate=root / "candidate",
                status=root / "status.json", registry=root / "owner.json",
                unit_dir=Path(p["UNIT_FILE"]).parent,
                prefix=p["SERVICE"] + "-acme")


def unit_names(p: dict) -> list[str]:
    prefix = resources(p)["prefix"]
    return [prefix + "-" + action + suffix for action in ("renew", "deploy") for suffix in (".service", ".timer")]
