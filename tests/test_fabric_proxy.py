"""Real HTTP proxy and native secret broker. This transport test asserts no sandbox isolation.

The Unix relay is replaced because this test addresses the host TCP listener directly.
Confinement and Unix permissions remain the separate tests/test_platform.py contract.
"""
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx

from engine.catalog import effective, load
from fabric.identity.keys import dev
from fabric.network.egress import Egress, mitmdump
from fabric.supply_chain.components import where


@unittest.skipUnless(where('openbao') and mitmdump(), 'needs pinned OpenBao and the hash-locked proxy environment')
class Proxy(unittest.TestCase):
    def test_real_proxy_injects_without_returning_reflected_credentials(self):
        class Destination(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                self.server.seen_auth = self.headers.get('authorization')
                data = self.server.seen_auth.encode() if self.path == '/reflect' else b'{"ok":true}'
                self.send_response(200)
                self.send_header('content-length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        with tempfile.TemporaryDirectory() as state:
            server = ThreadingHTTPServer(('127.0.0.2', 0), Destination)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            bao, process = dev(state, where('openbao'))
            proxy = None
            try:
                bao.put_secret('api', 'credential-held-by-broker')
                host = f'127.0.0.2:{server.server_port}'
                values = effective(load(), {'destinations': [host]})
                with patch('fabric.network.egress.Relay'):
                    proxy = Egress(state, values, secrets={'api': ['127.0.0.2']}, bao=bao).start()
                # Proxy config receives a scoped token, never the bootstrap token.
                configured = json.loads((Path(state) / 'egress/config.json').read_text())
                self.assertNotEqual(configured['bao']['token'], bao.token)
                with httpx.Client(proxy=f'http://127.0.0.1:{proxy.port}', trust_env=False, timeout=15) as client:
                    headers = {'authorization': 'Bearer secret:api'}
                    answer = client.get(f'http://{host}/safe', headers=headers)
                    self.assertEqual(answer.status_code, 200, answer.text)
                    self.assertEqual(server.seen_auth, 'Bearer credential-held-by-broker')
                    self.assertNotIn('credential-held-by-broker', answer.text)
                    reflected = client.get(f'http://{host}/reflect', headers=headers)
                    self.assertEqual(reflected.status_code, 502, reflected.text)
                    self.assertNotIn('credential-held-by-broker', reflected.text)
                self.assertNotIn('credential-held-by-broker', (Path(state) / 'egress/records.jsonl').read_text())
            finally:
                if proxy:
                    proxy.stop()
                process.kill()
                process.wait(timeout=10)
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
