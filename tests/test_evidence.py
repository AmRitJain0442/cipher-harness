import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'control'))
from evidence import Evidence, fingerprint


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Evidence(Path(self.tmp.name) / 'evidence.sqlite3')

    def test_completed_is_reused(self):
        execute, row = self.store.reserve('job', 'nikto -Version')
        self.assertTrue(execute)
        self.store.finish(row['id'], {'output': 'Nikto 2.6.1'})
        execute, again = self.store.reserve('job', 'nikto -Version')
        self.assertFalse(execute)
        self.assertEqual(again['id'], row['id'])
        self.assertEqual(again['output']['output'], 'Nikto 2.6.1')

    def test_pending_is_not_restarted(self):
        self.store.reserve('job', 'sqlmap --version')
        execute, row = self.store.reserve('job', 'sqlmap --version')
        self.assertFalse(execute)
        self.assertEqual(row['status'], 'pending')

    def test_uncertain_failure_is_not_restarted(self):
        _, row = self.store.reserve('job', 'nmap -F example.test')
        self.store.finish(row['id'], {'error': 'Timed out'}, 'failed')
        self.assertFalse(self.store.reserve('job', 'nmap -F example.test')[0])

    def test_jobs_are_isolated(self):
        self.store.reserve('job-a', 'sqlmap --version')
        self.assertTrue(self.store.reserve('job-b', 'sqlmap --version')[0])
        self.assertEqual(self.store.search('job-b')[0]['job'], 'job-b')

    def test_literal_search(self):
        _, row = self.store.reserve('job', 'echo percent%')
        self.store.finish(row['id'], {'output': 'a_b'})
        self.assertEqual(len(self.store.search('job', '%')), 1)
        self.assertEqual(len(self.store.search('job', 'a_b')), 1)
        self.assertEqual(len(self.store.search('job', 'not_present')), 0)

    def test_secret_redaction(self):
        with patch.dict(os.environ, {'HARNESS_API_KEY': 'test-private-value'}):
            self.assertNotIn('test-private-value', self.store.redact('Bearer test-private-value'))

    def test_reuse_does_not_claim_execution(self):
        _, row = self.store.reserve('job', 'echo hello')
        self.store.finish(row['id'], {'output': 'hello'})
        result = self.store.reuse(self.store.get('job', row['id']))
        self.assertTrue(result['cached'])
        self.assertFalse(result['executed_again'])

    def test_nmap_flag_order(self):
        self.assertEqual(fingerprint('nmap -Pn -sV example.test'),
                         fingerprint('nmap -sV -Pn example.test'))

    def test_loopback_keeps_environment(self):
        self.assertNotEqual(fingerprint('nmap -F 127.0.0.1', 'vm'),
                            fingerprint('nmap -F 127.0.0.1', 'container'))

    def test_shell_quoting_is_preserved(self):
        self.assertNotEqual(fingerprint("echo '$HOME'"), fingerprint('echo "$HOME"'))

    def test_output_files_keep_environment(self):
        self.assertNotEqual(fingerprint('nmap -oN result.txt example.test', 'vm'),
                            fingerprint('nmap -oN result.txt example.test', 'container'))


if __name__ == '__main__':
    unittest.main()
