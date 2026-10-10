"""Known behavioral probes: select verified failures instead of speculative bugs."""
PROBES=[{
    'id':'failed-tool-status','path':'control/evidence.py',
    'task':'''Evidence.finish currently defaults every result to completed. Fix ONLY
recording status for structured failed tool results: a dictionary with success=False
or a nonempty error must be failed when the requested status is completed. Also
recognize a JSON-string tool result containing that dictionary. Plain text and
successful results stay completed. Explicit interrupted/failed status stays intact.
Do not change command replay behavior or the stored output shape. Add a regression
that calls finish without status and checks get(...)["status"].''',
    'test':'''import json,tempfile,unittest
from pathlib import Path
from evidence import Evidence
class FailureStatus(unittest.TestCase):
    def test_failure_status(self):
        with tempfile.TemporaryDirectory() as directory:
            store=Evidence(Path(directory)/'evidence.sqlite3')
            for index,output in enumerate(({'success':False},{'error':'spawn tool ENOENT'},json.dumps({'success':False}),json.dumps({'error':'missing tool'}))):
                _,record=store.reserve('job','echo '+str(index))
                store.finish(record['id'],output)
                self.assertEqual(store.get('job',record['id'])['status'],'failed')
'''}, {
    'id':'configured-owner-redaction','path':'control/evidence.py',
    'task':'''Evidence.redact reads the default ROOT/data/owner-key, even when
HARNESS_DATA_DIR points somewhere else. The console reads the fallback owner-key
from the configured data directory. Fix redaction to read that same file, keeping
other secret sources and environment key handling. Test a temporary configured
data directory containing owner-key; the secret must be removed from output.''',
    'test':'''import os,tempfile,unittest
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
'''}]
