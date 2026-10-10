import io
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import types
import unittest

root = Path(__file__).resolve().parents[1]
if not (root / 'improvement/runner.py').exists():
    root = Path('/work')
sys.path.insert(0, str(root / 'improvement'))
try:
    import fcntl
except ModuleNotFoundError:
    sys.modules['fcntl'] = types.ModuleType('fcntl')
from runner import extract_snapshot


class SnapshotPermissionsTests(unittest.TestCase):
    @unittest.skipIf(os.name == 'nt', 'Unix evaluator permission bits')
    def test_nested_snapshot_readable_under_private_service_umask(self):
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode='w') as tar:
            directory = tarfile.TarInfo('control')
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o700
            tar.addfile(directory)
            source = b'print("loaded")\n'
            member = tarfile.TarInfo('control/app.py')
            member.size = len(source)
            member.mode = 0o600
            tar.addfile(member, io.BytesIO(source))
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / 'snapshot'
            previous = os.umask(0o077)
            try:
                extract_snapshot(archive.getvalue(), destination)
            finally:
                os.umask(previous)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o755)
            self.assertEqual((destination / 'control').stat().st_mode & 0o777, 0o755)
            self.assertEqual((destination / 'control/app.py').stat().st_mode & 0o777, 0o644)
            self.assertEqual((destination / 'control/app.py').read_bytes(), source)
