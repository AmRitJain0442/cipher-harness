import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

root = Path(__file__).resolve().parents[1]
if not (root/'improvement/prompt_loop.py').exists():
    root = Path('/work')
sys.path.insert(0, str(root/'improvement'))
from prompt_loop import revise


class PromptLoopTests(unittest.TestCase):
    def test_next_execution_uses_saved_prompt_and_failed_call_preserves_it(self):
        requests = []
        def response(request, timeout):
            requests.append(json.loads(request.data))
            prompt = 'Updated system prompt ' + str(len(requests))
            return io.StringIO(json.dumps({'choices': [{
                'finish_reason': 'stop', 'message': {
                    'content': json.dumps({'system_prompt': prompt})}}]}))
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)/'prompt-state.json'
            with patch('prompt_loop.urllib.request.urlopen', side_effect=response):
                revise(state, 'http://localhost/v1', 'model', 'private-key', 'objective')
                revise(state, 'http://localhost/v1', 'model', 'private-key', 'objective')
            self.assertEqual(requests[1]['messages'][0]['content'], 'Updated system prompt 1')
            self.assertEqual(json.loads(state.read_text())['revision'], 2)
            saved = state.read_text()
            with patch('prompt_loop.urllib.request.urlopen', side_effect=TimeoutError):
                with self.assertRaises(TimeoutError):
                    revise(state, 'http://localhost/v1', 'model', 'private-key', 'objective')
            self.assertEqual(state.read_text(), saved)
