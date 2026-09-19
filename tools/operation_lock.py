#!/usr/bin/env python3
"""Serialize an instance's lifecycle and its ACME jobs; inherited locks are reentrant."""
from __future__ import annotations
import argparse
from contextlib import contextmanager
import os
from pathlib import Path
import re
import subprocess

ENV = "THREEPROXY_OPERATION_FD"


def filename(identity: str) -> Path:
    if identity and not re.fullmatch(r"[a-z][a-z0-9-]{0,19}", identity):
        raise ValueError("invalid lock instance")
    return Path("/run/lock") / ("3proxy-instance-" + (identity or "legacy") + ".lock")


def inherited(identity: str) -> int | None:
    try:
        fd = int(os.environ.get(ENV, "-1"))
        stat = os.fstat(fd)
        if stat.st_uid == 0 and stat.st_nlink == 1 and not stat.st_mode & 0o077 and os.readlink(f"/proc/self/fd/{fd}") == str(filename(identity)):
            return fd
    except (OSError, ValueError):
        pass
    return None


@contextmanager
def acquire(identity: str, *, http: bool = False):
    import fcntl
    existing = None if http else inherited(identity)
    if existing is not None:
        yield existing
        return
    path = Path("/run/lock/3proxy-acme-http01.lock") if http else filename(identity)
    from instance import guard
    guard(path)
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        stat = os.fstat(fd)
        if stat.st_uid != 0 or stat.st_nlink != 1 or stat.st_mode & 0o077:
            raise ValueError("unsafe operation lock")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield fd
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("check", "run"))
    parser.add_argument("identity")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.action == "check":
        return 0 if inherited(args.identity) is not None else 1
    with acquire(args.identity) as fd:
        return subprocess.run(args.command, env=dict(os.environ, **{ENV: str(fd)}), pass_fds=(fd,)).returncode


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as exc:
        raise SystemExit(f"operation lock: {exc}")
