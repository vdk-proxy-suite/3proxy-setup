#!/usr/bin/env python3
"""Build a deterministic standalone ZIP with explicit Unix modes."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import zipfile


EXECUTABLE_NAMES = {"setup3proxy.sh", "clean3proxy.sh"}
EXCLUDED_NAMES = {"AGENTS.md", "__pycache__", ".git", ".agents", "venv", ".venv"}


def excluded(path: Path) -> bool:
    if any(part in EXCLUDED_NAMES for part in path.parts) or path.suffix in {".pyc", ".pcap", ".pcapng"}:
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
