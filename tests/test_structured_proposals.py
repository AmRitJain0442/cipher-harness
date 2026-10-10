from pathlib import Path
import json
import sys
import types
import unittest
from unittest.mock import patch

root=Path(__file__).resolve().parents[1]
if not (root/'improvement/proposals.py').exists(): root=Path('/work')
sys.path.insert(0,str(root/'improvement'))
try: import fcntl
except ModuleNotFoundError: sys.modules['fcntl']=types.ModuleType('fcntl')
from proposals import proposal_schema, normalize_proposal
from runner import ask


class StructuredProposalTests(unittest.TestCase):
    def setUp(self):
        self.sources={'control/evidence.py':'def example():\n    return 1\n\ndef other():\n    return 2\n'}
        self.raw={'title':'change','reason':'behavior fix','vm_packages':[],
            'edits':[{'path':'control/evidence.py','start_line':2,'end_line':2,
                      'replacement_lines':['    return "quote: \\\" and slash \\\\"']}],
            'regression_test_lines':['import unittest','class T(unittest.TestCase):',
                                    '    def runTest(self):','        self.assertTrue(True)']}

    def test_line_edits_use_real_snapshot_and_keep_indentation(self):
        proposal=normalize_proposal(self.raw,self.sources)
        self.assertEqual(proposal['edits'][0]['old'],self.sources['control/evidence.py'])
        self.assertIn('def other():\n    return 2',proposal['edits'][0]['new'])
        self.assertEqual(proposal['edits'][0]['new'].splitlines()[1],self.raw['edits'][0]['replacement_lines'][0])

    def test_schema_allows_only_supplied_paths(self):
        schema=proposal_schema(self.sources)
        self.assertEqual(schema['properties']['edits']['items']['properties']['path']['enum'],['control/evidence.py'])

    def test_invalid_range_and_boolean_are_rejected(self):
        for first,last in ((0,2),(2,20),(True,2),(3,2)):
            self.raw['edits'][0].update(start_line=first,end_line=last)
            with self.assertRaisesRegex(ValueError,'Invalid source line range'):
                normalize_proposal(self.raw,self.sources)

    def test_overlapping_ranges_are_rejected(self):
        self.raw['edits'].append(dict(self.raw['edits'][0]))
        with self.assertRaisesRegex(ValueError,'Overlapping'):
            normalize_proposal(self.raw,self.sources)

    def test_multi_line_replacement_item_is_rejected(self):
        self.raw['edits'][0]['replacement_lines']=['one\ntwo']
        with self.assertRaisesRegex(ValueError,'one source line'):
            normalize_proposal(self.raw,self.sources)

    def test_request_enforces_schema_and_preserves_escaped_code(self):
        body=json.dumps({'choices':[{'finish_reason':'stop','message':{'content':json.dumps(self.raw)}}]}).encode()
        from io import BytesIO
        args=types.SimpleNamespace(objective='Improve reliability',model='local',endpoint='http://example.invalid/v1')
        with patch('runner.urllib.request.urlopen',return_value=BytesIO(body)) as open_request:
            result=ask(args,self.sources,[],'dummy')
        request_body=json.loads(open_request.call_args.args[0].data)
        self.assertEqual(request_body['response_format']['type'],'json_object')
        self.assertIn('schema',request_body['response_format'])
        self.assertEqual(result['edits'][0]['new'].splitlines()[1],self.raw['edits'][0]['replacement_lines'][0])

    def test_truncated_response_is_rejected(self):
        from io import BytesIO
        body=json.dumps({'choices':[{'finish_reason':'length','message':{'content':'{}'}}]}).encode()
        args=types.SimpleNamespace(objective='Improve reliability',model='local',endpoint='http://example.invalid/v1')
        with patch('runner.urllib.request.urlopen',return_value=BytesIO(body)):
            with self.assertRaisesRegex(ValueError,'token limit'): ask(args,self.sources,[],'dummy')
