import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import AsyncMock, patch

root = Path(__file__).resolve().parents[1]
if not (root/'control/gemini_advisor.py').exists():
    root = Path('/work')
sys.path.insert(0, str(root/'control'))
from gemini_advisor import failed_command, enrich_command_failure
from runtime_tools import install


def exchange(output):
    return [
        {'role': 'user', 'content': 'Only inspect localhost tool versions.'},
        {'role': 'assistant', 'tool_calls': [{'id': 'call-one', 'function': {
            'name': 'generic_linux_command', 'arguments': json.dumps({'command': 'nmap --versoin'})}}]},
        {'role': 'tool', 'tool_call_id': 'call-one', 'content': output}]


class AdvisorTests(unittest.IsolatedAsyncioTestCase):
    async def test_correction_preserves_tool_evidence_and_never_executes(self):
        data = {'messages': exchange(json.dumps({'exit_code': 2, 'stderr': 'unknown option'}))}
        original = data['messages'][-1].copy()
        advisor = AsyncMock(return_value={'command': 'nmap --version', 'retry_safe': True,
            'explanation': 'Correct the spelling.', 'model': 'test-model', 'executed': False})
        with patch.dict(os.environ, {'HARNESS_GEMINI_PROJECT': 'test-project'}), \
                patch('gemini_advisor.advise', advisor):
            await enrich_command_failure(None, data)
        advisor.assert_awaited_once()
        self.assertEqual(data['messages'][-2], original)
        self.assertIn('nmap --version', data['messages'][-1]['content'])

    async def test_success_and_stale_failure_do_not_call_gemini(self):
        self.assertIsNone(failed_command(exchange(json.dumps({'exit_code': 0, 'stdout': 'ok'}))))
        messages = exchange('unknown option')
        messages.append({'role': 'assistant', 'content': 'Finished.'})
        self.assertIsNone(failed_command(messages))

    async def test_advisor_failure_preserves_native_execution_flow(self):
        data = {'messages': exchange('command not found')}
        before = json.dumps(data)
        with patch.dict(os.environ, {'HARNESS_GEMINI_PROJECT': 'test-project'}), \
                patch('gemini_advisor.advise', AsyncMock(side_effect=TimeoutError('timeout'))):
            await enrich_command_failure(None, data)
        self.assertEqual(json.dumps(data), before)

    async def test_package_install_rejects_shell_and_option_injection(self):
        for name in ('--allow-unauthenticated', 'curl;whoami', '$(id)', '../package'):
            with self.assertRaises(ValueError):
                await install([name])

    async def test_container_install_updates_only_owned_tool_workers(self):
        docker=AsyncMock(side_effect=['abc123 pentagi-terminal-18\ndef456 unrelated-service\n',
                                      'cipher-tools:local','image built','updated','installed'])
        with patch('runtime_tools.docker_command',docker):
            result=await install(['jq'],environment='pentagi')
        self.assertEqual(result['updated_workers'],['abc123'])
        invocations=docker.await_args_list
        self.assertEqual(invocations[3].args,('exec','abc123','apt-get','update'))
        self.assertNotIn('def456',str(invocations))
