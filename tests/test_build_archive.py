from __future__ import annotations

import io
import sys
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path, PurePosixPath
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import build_archive  # noqa: E402


class BuildArchiveTests(unittest.TestCase):
    INTENDED_FILES = {
        ".gitattributes": "* text=auto\n",
        ".gitignore": "*.zip\n*.sha256\n",
        "README.md": "# Fixture package\n",
        "VERSION": "2.0.1\n",
        "clean3proxy.sh": "#!/bin/sh\n",
        "config.example.yaml": "access:\n  mode: strong\n",
        "config.iponly.example.yaml": "access:\n  mode: iponly\n",
        "config.https.example.yaml": "tls:\n  client_ca_file: /fixture/ca.crt\n",
        "docs/operations.md": "# Operations\n",
        "examples/install.sh": "#!/bin/sh\n",
        "lib/common.sh": "#!/bin/sh\n",
        "patches/0001-fix.patch": "fixture patch\n",
        "patches/README.md": "# Patches\n",
        "setup3proxy.sh": "#!/bin/sh\n",
        "steps/00-stop-backup.sh": "#!/bin/sh\n",
        "steps/01-install.sh": "#!/bin/sh\n",
        "tests/fixture.sh": "#!/bin/sh\n",
        "tests/test_config.py": "def test_fixture():\n    pass\n",
        "tools/build_archive.py": "#!/usr/bin/env python3\n",
        "tools/config.py": "#!/usr/bin/env python3\n",
    }

    EXCLUDED_FILES = {
        ".agents/session.json": "{}\n",
        ".git/config": "[core]\n",
        ".venv/pyvenv.cfg": "home = fixture\n",
        "AGENTS.md": "local-only instructions\n",
        "captures/session.pcap": "pcap payload\n",
        "captures/session.pcapng": "pcapng payload\n",
        "config.prod.yaml": "credentials: secret\n",
        "config.yaml": "credentials: secret\n",
        "tests/__pycache__/test_config.cpython-312.pyc": "bytecode\n",
        "venv/pyvenv.cfg": "home = fixture\n",
    }

    EXECUTABLE_FILES = {
        "clean3proxy.sh",
        "setup3proxy.sh",
        "steps/00-stop-backup.sh",
        "steps/01-install.sh",
        "tools/build_archive.py",
        "tools/config.py",
    }

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.source = Path(self.temporary_directory.name) / "3proxy-setup"
        self.source.mkdir()

        for relative, contents in self.INTENDED_FILES.items():
            self.write_fixture(relative, contents)
        for relative, contents in self.EXCLUDED_FILES.items():
            self.write_fixture(relative, contents)

        self.output = self.source / "3proxy-setup-2.0.1.zip"
        self.output.write_bytes(b"pre-existing release archive")
        self.checksum = self.source / "3proxy-setup-2.0.1.zip.sha256"
        self.checksum.write_text("pre-existing checksum\n", encoding="utf-8")
        self.write_fixture("previous-release.zip", "pre-existing zip\n")
        self.write_fixture("previous-release.sha256", "pre-existing checksum\n")

    def write_fixture(self, relative: str, contents: str) -> None:
        path = self.source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8", newline="\n")

    def build(self) -> bytes:
        argv = [
            "build_archive.py",
            "--source",
            str(self.source),
            "--output",
            str(self.output),
        ]
        with mock.patch.object(sys, "argv", argv), redirect_stdout(io.StringIO()):
            self.assertEqual(build_archive.main(), 0)
        return self.output.read_bytes()

    def test_two_builds_with_existing_outputs_are_byte_identical(self) -> None:
        checksum_before = self.checksum.read_bytes()

        first_build = self.build()
        second_build = self.build()

        self.assertEqual(first_build, second_build)
        self.assertEqual(self.checksum.read_bytes(), checksum_before)

    def test_archive_contains_exactly_the_intended_files_under_one_root(self) -> None:
        archive_bytes = self.build()

        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            names = archive.namelist()

        prefix = "3proxy-setup/"
        expected_names = {
            prefix + PurePosixPath(relative).as_posix()
            for relative in self.INTENDED_FILES
        }
        self.assertEqual(set(names), expected_names)
        self.assertEqual(len(names), len(expected_names))
        self.assertEqual(
            {PurePosixPath(name).parts[0] for name in names},
            {"3proxy-setup"},
        )
        self.assertTrue(all(name.startswith(prefix) for name in names))
        self.assertIn(prefix + "config.https.example.yaml", names)

        excluded = set(self.EXCLUDED_FILES) | {
            self.output.name,
            self.checksum.name,
            "previous-release.zip",
            "previous-release.sha256",
        }
        for relative in excluded:
            with self.subTest(excluded=relative):
                self.assertNotIn(prefix + PurePosixPath(relative).as_posix(), names)

    def test_archive_assigns_only_the_expected_unix_modes(self) -> None:
        archive_bytes = self.build()

        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            infos = archive.infolist()

        for info in infos:
            relative = PurePosixPath(info.filename).relative_to("3proxy-setup").as_posix()
            expected_mode = 0o755 if relative in self.EXECUTABLE_FILES else 0o644
            with self.subTest(path=relative):
                self.assertEqual(info.create_system, 3)
                self.assertEqual((info.external_attr >> 16) & 0o777, expected_mode)

        non_executable_directories = {"tests", "examples", "docs", "patches"}
        checked_directories = {
            PurePosixPath(info.filename).parts[1]
            for info in infos
            if len(PurePosixPath(info.filename).parts) > 2
            and (info.external_attr >> 16) & 0o777 == 0o644
        }
        self.assertTrue(non_executable_directories <= checked_directories)


if __name__ == "__main__":
    unittest.main()
