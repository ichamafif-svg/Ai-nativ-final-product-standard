"""Adversarial checks of the real policy addon, using mitmproxy's HTTP message types.

Run with its hash-locked Python environment: tests do not require an OCI runtime or Unix sockets.
"""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor

ROOT = Path(__file__).resolve().parents[1]
ADDON = ROOT / 'fabric/network/egress_addon.py'
try:
    from mitmproxy import http
except ImportError:
    http = None


@unittest.skipUnless(http, 'requires the separately hash-locked mitmproxy environment')
class Adversarial(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.config = {'records': str(self.root / 'records'), 'destinations': ['example.test'],
                       'secrets': {'api': ['example.test']}, 'bao': {}, 'keys': {},
                       'files': {'root': str(self.root / 'files'), 'types': ['text/plain'],
                                 'max_bytes': 10, 'quota_bytes': 20}}
        self.path = self.root / 'config.json'
        self.path.write_text(json.dumps(self.config))
        self.environment = patch.dict(os.environ, {'STANDARD_EGRESS': str(self.path)})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        spec = importlib.util.spec_from_file_location('standard_egress_test', ADDON)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.proxy = self.module.Egress()

    def flow(self, url='https://example.test/', *, headers=None, body=b'', method='GET'):
        return SimpleNamespace(request=http.Request.make(method, url, body, headers or {}),
                               response=None, metadata={}, server_conn=SimpleNamespace(sni=None))

    def injected(self):
        self.proxy.secret = lambda name: 'credential-value'
        self.proxy.resolve = lambda host, port: host
        flow = self.flow(headers={'authorization': 'Bearer secret:api'})
        self.proxy.request(flow)
        self.assertEqual(flow.request.headers['authorization'], 'Bearer credential-value')
        return flow

    def test_reflected_credentials_in_bodies_and_headers_are_blocked_before_delivery(self):
        for body, headers in ((b'credential-value', {}), (b'ok', {'x-echo': 'credential-value'})):
            with self.subTest(headers=headers):
                flow = self.injected()
                flow.response = http.Response.make(200, body, headers)
                self.proxy.responseheaders(flow)
                self.assertFalse(flow.response.stream)
                self.proxy.response(flow)
                self.assertEqual(flow.response.status_code, 502)
                self.assertNotIn(b'credential-value', flow.response.content)
                self.assertNotIn('standard_injected', flow.metadata)
        self.assertNotIn('credential-value', (self.root / 'records').read_text())

    def test_compressed_reflections_are_inspected_after_decoding(self):
        import gzip
        flow = self.injected()
        flow.response = http.Response.make(200)
        flow.response.headers['content-encoding'] = 'gzip'
        flow.response.raw_content = gzip.compress(b'credential-value')
        self.proxy.response(flow)
        self.assertEqual(flow.response.status_code, 502)

    def test_an_ordinary_credential_bearing_answer_still_works(self):
        flow = self.injected()
        flow.response = http.Response.make(200, b'{"ok":true}')
        self.proxy.response(flow)
        self.assertEqual(flow.response.status_code, 200)
        self.assertEqual(flow.response.content, b'{"ok":true}')

    def test_deny_by_default_includes_other_product_keys_and_other_operations(self):
        self.proxy.config['keys'] = {'product-a': ['encrypt']}
        for key, operation in [('product-b', 'encrypt'), ('product-a', 'decrypt'), ('identity', 'encrypt')]:
            flow = self.flow(f'http://keys.standard/{operation}/{key}', body=b'{}', method='POST')
            self.proxy.keys(flow)
            self.assertEqual(flow.response.status_code, 403)

    def test_unknown_destinations_and_mixed_private_dns_answers_are_refused(self):
        flow = self.flow('https://other.test/')
        self.proxy.request(flow)
        self.assertEqual(flow.response.status_code, 403)
        with patch.object(self.module.socket, 'getaddrinfo', return_value=[
                (None, None, None, None, ('8.8.8.8', 443)),
                (None, None, None, None, ('127.0.0.1', 443))]):
            self.assertIsNone(self.proxy.resolve('example.test', 443))

    def test_repeated_bytes_do_not_consume_the_shared_budget_twice(self):
        self.proxy.config['files']['quota_bytes'] = 5
        for body, expected in [(b'hello', 201), (b'hello', 201), (b'world', 507)]:
            flow = self.flow('http://files.standard/', body=body, method='PUT', headers={'content-type': 'text/plain'})
            self.proxy.files(flow)
            self.assertEqual(flow.response.status_code, expected)

    def test_independent_processes_cannot_race_the_quota(self):
        self.path.write_text(json.dumps(self.config))
        code = ('import runpy,sys; from types import SimpleNamespace; from mitmproxy import http; '
                'p=runpy.run_path(sys.argv[1])["addons"][0]; '
                'f=SimpleNamespace(request=http.Request.make("PUT","http://files.standard/",'
                'sys.argv[2].encode(),{"content-type":"text/plain"}),response=None); '
                'p.files(f); print(f.response.status_code)')
        def put(i):
            done = subprocess.run([sys.executable, '-c', code, str(ADDON), f'{i:05d}'],
                                  capture_output=True, text=True, timeout=30)
            self.assertEqual(done.returncode, 0, done.stderr)
            return int(done.stdout)
        with ThreadPoolExecutor(max_workers=8) as workers:
            results = list(workers.map(put, range(12)))
        self.assertEqual(results.count(201), 4, results)
        self.assertEqual(results.count(507), 8, results)
        blobs = [p for p in (self.root / 'files').iterdir() if len(p.name) == 64]
        self.assertEqual(sum(p.stat().st_size for p in blobs), 20)
