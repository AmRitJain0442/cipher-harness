"""Run the real console handlers with disposable runtime state and no frameworks."""
import importlib.util
import gc
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

ROOT = Path(__file__).resolve().parents[1]
# Frozen cloud gates live outside the repository; /work holds the revision under test.
if not (ROOT/'control/app.py').exists():
    ROOT = Path('/work')
sys.path.insert(0,str(ROOT/'control'))


class ConsoleTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ,{'HARNESS_API_KEY':'local-test-key',
            'HARNESS_OWNER_KEY':'local-owner-key','HARNESS_PENTAGI_PASSWORD':'local-password',
            'HARNESS_DATA_DIR':self.temp.name})
        self.env.start()
        # Reload configuration for this isolated server.
        for name in ('settings','adapters'):
            sys.modules.pop(name,None)
        spec = importlib.util.spec_from_file_location('harness_console_under_test',ROOT/'control/app.py')
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        app = web.Application(middlewares=[self.module.private])
        app.router.add_get('/',self.module.static)
        app.router.add_get('/join/{key}',self.module.static)
        app.router.add_get('/api/jobs',self.module.jobs)
        self.client = TestClient(TestServer(app))
        await self.client.start_server()

    async def asyncTearDown(self):
        await self.client.close()
        self.module.con.close()
        self.module = None
        gc.collect()
        self.env.stop()
        self.temp.cleanup()

    async def test_api_requires_owner(self):
        response = await self.client.get('/api/jobs')
        self.assertEqual(response.status,401)

    async def test_owner_can_read_jobs(self):
        response = await self.client.get('/api/jobs',cookies={'cipher_owner':'local-owner-key'})
        self.assertEqual(response.status,200)
        await response.json()

    async def test_invalid_join_is_rejected(self):
        response = await self.client.get('/join/wrong-key')
        self.assertIn(response.status,(401,403,404))


if __name__=='__main__':
    unittest.main()
