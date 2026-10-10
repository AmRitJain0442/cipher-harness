import sys,os,tempfile,json,unittest
from pathlib import Path
sys.path.insert(0,'/work/control')
from evidence import Evidence
class T(unittest.TestCase):
    def runTest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'runs/job-a/cai-test'
            root.mkdir(parents=True)
            conv=[{'type':'function_call','call_id':'call-a','arguments':json.dumps({'command':'echo hello','working_directory':None})},
                  {'type':'function_call_output','call_id':'call-a','output':'hello'}]
            (root/'result.json').write_text(json.dumps({'conversation':conv}))
            ev=Evidence(tmp+'/evidence.sqlite3')
            ev.backfill(tmp)
            rows=ev.search('job-a')
            self.assertEqual(len(rows),1)
            self.assertEqual(rows[0]['cwd'],str(root.resolve()))