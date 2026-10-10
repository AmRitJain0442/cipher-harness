import json,tempfile,unittest
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
