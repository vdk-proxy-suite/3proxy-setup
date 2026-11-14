import os
from pathlib import Path
import tempfile
import unittest
import yaml

from test_schema_v2 import profile
import set_credentials


class CredentialUpdateTests(unittest.TestCase):
    def test_invalid_credentials_leave_original_unchanged_and_no_temporary_secret(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); path = root / "config.private.yaml"
            original = yaml.safe_dump(profile()); path.write_text(original)
            with self.assertRaises(ValueError):
                set_credentials.update(path, "invalid:user", "test-password-long-enough")
            self.assertEqual(path.read_text(), original)
            self.assertEqual(list(root.iterdir()), [path])

    def test_success_keeps_password_out_of_arguments_and_writes_private_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.private.yaml"
            path.write_text(yaml.safe_dump(profile()))
            set_credentials.update(path, "fixture-user", "fixture-password-long-enough")
            self.assertEqual(yaml.safe_load(path.read_text())["local_auth"]["username"], "fixture-user")
            if os.name == "posix":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
