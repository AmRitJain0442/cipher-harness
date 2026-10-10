import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'control'))
from settings import secret


class ConfigTests(unittest.TestCase):
    def test_environment_secret(self):
        with patch.dict(os.environ, {'TEST_HARNESS_SECRET': '  private-test  '}):
            self.assertEqual(secret('TEST_HARNESS_SECRET'), 'private-test')

    def test_file_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'key'
            path.write_text('file-test\n')
            with patch.dict(os.environ, {'TEST_HARNESS_SECRET_FILE': str(path)}):
                self.assertEqual(secret('TEST_HARNESS_SECRET'), 'file-test')

    def test_missing_secret_has_configuration_error(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, 'Set TEST_HARNESS_SECRET'):
                secret('TEST_HARNESS_SECRET')
