"""Package solver plans must never change existing shared dependencies."""
import subprocess
import sys
from pathlib import Path
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import instance


class DependencyIsolationTests(unittest.TestCase):
    def execute(self, plan='', missing=True, partial=False):
        self.calls = []
        def run(argv, **kwargs):
            self.calls.append(argv)
            if argv[0] == 'dpkg-query':
                if argv[-1] == 'build-essential' and missing:
                    return subprocess.CompletedProcess(argv, 1, '')
                return subprocess.CompletedProcess(argv, 0, 'install ok unpacked' if partial else 'install ok installed')
            return subprocess.CompletedProcess(argv, 0, plan if '-s' in argv else '')
        with mock.patch.object(instance.subprocess, 'run', side_effect=run):
            instance.install_dependencies()

    def test_existing_dependencies_do_not_run_apt(self):
        self.execute(missing=False)
        self.assertFalse(any(call[0] == 'apt-get' for call in self.calls))

    def test_transitive_upgrade_is_rejected_before_install(self):
        with self.assertRaisesRegex(ValueError, 'upgrading/removing'):
            self.execute('Inst libssl3:amd64 [3.0.1] (3.0.2 Ubuntu)\n')
        self.assertFalse(any(call[:2] == ['apt-get', 'install'] for call in self.calls))

    def test_solver_removal_is_rejected_before_install(self):
        with self.assertRaisesRegex(ValueError, 'upgrading/removing'):
            self.execute('Remv foreign-service [1.0]\n')
        self.assertFalse(any(call[:2] == ['apt-get', 'install'] for call in self.calls))

    def test_only_absent_packages_are_requested(self):
        self.execute('Inst build-essential (12.0 Ubuntu)\n')
        install = next(call for call in self.calls if call[:2] == ['apt-get', 'install'])
        self.assertIn('--no-remove', install)
        self.assertIn('--no-upgrade', install)
        self.assertEqual(install[-1], 'build-essential')
        self.assertNotIn('openssl', install)

    def test_partial_existing_package_requires_separate_repair(self):
        with self.assertRaisesRegex(ValueError, 'partially installed'):
            self.execute(missing=False, partial=True)
        self.assertFalse(any(call[0] == 'apt-get' for call in self.calls))
