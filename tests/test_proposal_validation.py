from pathlib import Path
import sys
import tempfile
import types
import unittest

root=Path(__file__).resolve().parents[1]
if not (root/'improvement/runner.py').exists(): root=Path('/work')
sys.path.insert(0,str(root/'improvement'))
try:
    import fcntl
except ModuleNotFoundError:
    # Validation is portable; the cloud runner's process lock requires Linux.
    sys.modules['fcntl']=types.ModuleType('fcntl')
from runner import validate


class ProposalTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.path=self.root/'control/evidence.py'
        self.path.parent.mkdir()
        self.source='def example():\n    return 1\n'
        self.path.write_text(self.source)

    def proposal(self,old,new,test=None):
        return {'edits':[{'path':'control/evidence.py','old':old,'new':new}],
                'regression_test':test or 'import unittest\nclass Test(unittest.TestCase):\n    def test_value(self):\n        self.assertTrue(True)\n'}

    def test_unsupplied_file_is_rejected(self):
        with self.assertRaisesRegex(ValueError,'did not supply'):
            validate(self.proposal('return 1','return 2'),self.root,{'control/app.py'})
        self.assertEqual(self.path.read_text(),self.source)

    def test_invented_function_is_rejected_with_actual_source(self):
        with self.assertRaisesRegex(ValueError,'Closest actual lines'):
            validate(self.proposal('def imagined():','def other():'),self.root,{'control/evidence.py'})
        self.assertEqual(self.path.read_text(),self.source)

    def test_candidate_syntax_error_is_distinguished(self):
        with self.assertRaisesRegex(ValueError,'Proposed edit introduced a syntax error'):
            validate(self.proposal('return 1','return {)'),self.root)
        self.assertEqual(self.path.read_text(),self.source)

    def test_test_syntax_error_is_distinguished(self):
        broken='import unittest\nclass Test(unittest.TestCase):\n    def test_x(self):\n        value = {)\n'
        with self.assertRaisesRegex(ValueError,'Generated regression test has a syntax error'):
            validate(self.proposal('return 1','return 2',broken),self.root)
