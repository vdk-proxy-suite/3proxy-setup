#!/usr/bin/env python3
"""Set local strong-auth credentials interactively, without shell history/argv secrets."""
from __future__ import annotations

import argparse
from getpass import getpass
import os
from pathlib import Path
import tempfile

import yaml
import config


def update(path: Path, username: str, password: str) -> None:
    if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
        raise ValueError("configuration must be a regular, non-linked file")
    if len(password) < 16:
        raise ValueError("use a password of at least 16 characters")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("configuration must be a mapping")
    data["local_auth"] = dict(username=username, password=password)
    # Preserve relative TLS paths in the original YAML while validating them
    # against the actual source location in a protected temporary sibling.
    fd, name = tempfile.mkstemp(prefix=".credentials-", suffix=".yaml", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            yaml.safe_dump(data, stream, sort_keys=False)
        temporary.chmod(0o600)
        config.validate(config.load_config(temporary))
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    username = input("Proxy username: ").strip()
    password = getpass("Proxy password (at least 16 characters): ")
    if password != getpass("Repeat password: "):
        raise ValueError("passwords do not match; configuration unchanged")
    update(args.config, username, password)
    print("Local credentials saved; configuration valid. No credentials were printed.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as exc:
        raise SystemExit(str(exc))
