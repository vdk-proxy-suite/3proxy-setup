#!/usr/bin/env python3
"""Build a deterministic standalone ZIP with explicit Unix modes."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import zipfile


EXECUTABLE_NAMES = {"setup3proxy.sh", "clean3proxy.sh"}
RELEASE_DIRECTORIES = {"lib", "steps", "tools", "patches", "tests", "docs", "examples"}
RELEASE_ROOT_FILES = {".gitattributes", ".gitignore", ".env.example", "README.md", "VERSION", *EXECUTABLE_NAMES}
EXCLUDED_NAMES = {
    ".3proxy-instance.json", "AGENTS.md", "__pycache__", ".git", ".agents", ".idea", ".vscode",
    ".DS_Store", "Thumbs.db", "healthchecks", "venv", ".venv", ".test-work", "tmp",
}


def excluded(path: Path) -> bool:
    if len(path.parts) == 1:
        if path.name not in RELEASE_ROOT_FILES and not (path.name.startswith("config.") and path.name.endswith(".example.yaml")):
            # The historical primary example has no second component before .example.
            if path.name != "config.example.yaml":
                return True
    elif path.parts[0] not in RELEASE_DIRECTORIES:
        return True
    if path.name.startswith(".credentials-"):
        return True
    if path.name != ".env.example" and (path.name == ".env" or path.name.startswith(".env.")):
        return True
    if any(part in EXCLUDED_NAMES for part in path.parts) or path.suffix.lower() in {
        ".pyc", ".pyo", ".pyd", ".log", ".pcap", ".pcapng", ".zip", ".sha256",
        ".crt", ".key", ".pem", ".csr", ".srl", ".cnf", ".der", ".p12", ".pfx",
    }:
        return True
    return path.name.startswith("config") and path.suffix == ".yaml" and not path.name.endswith(".example.yaml")


def executable(path: Path) -> bool:
    return (
        path.name in EXECUTABLE_NAMES
        or "steps" in path.parts
        or ("tools" in path.parts and path.suffix == ".py")
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve()
    files = sorted(path for path in source.rglob("*") if path.is_file() and not excluded(path.relative_to(source)))
    if any(path.is_symlink() for path in files):
        raise ValueError("release inputs must not be symlinks")
    with zipfile.ZipFile(args.output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files:
            relative = path.relative_to(source)
            info = zipfile.ZipInfo((Path(source.name) / relative).as_posix(), date_time=(2026, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = ((0o755 if executable(relative) else 0o644) & 0xFFFF) << 16
            archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    print(f"{args.output} sha256={hashlib.sha256(args.output.read_bytes()).hexdigest()} files={len(files)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
