import os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from evidence import Evidence
class ConfiguredOwnerRedaction(unittest.TestCase):
    def test_configured_owner_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'owner-key').write_text('probe-private-owner-value')
            with patch.dict(os.environ,{'HARNESS_DATA_DIR':directory,'HARNESS_OWNER_KEY':'','HARNESS_OWNER_KEY_FILE':''}):
                store=Evidence(root/'evidence.sqlite3')
                self.assertNotIn('probe-private-owner-value',store.redact('token=probe-private-owner-value'))
