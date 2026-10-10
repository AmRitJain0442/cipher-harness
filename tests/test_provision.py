from pathlib import Path
import sys
import unittest
from unittest.mock import patch

root=Path(__file__).resolve().parents[1]
if not (root/'improvement/provision.py').exists(): root=Path('/work')
sys.path.insert(0,str(root/'improvement'))
from provision import install_packages


class ProvisionTests(unittest.TestCase):
    def test_no_packages_does_not_execute_commands(self):
        with patch('provision.subprocess.run') as run:
            self.assertEqual(install_packages([])['installed'],[])
            run.assert_not_called()

    def test_rejects_shell_commands_and_options(self):
        for value in [['nikto; rm -rf /'],['--allow-unauthenticated'],['$(whoami)'],['../package']]:
            with self.assertRaises(ValueError): install_packages(value)

    def test_limits_package_count(self):
        with self.assertRaises(ValueError): install_packages(['a']*9)
